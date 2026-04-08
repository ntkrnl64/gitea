// Client-side E2E encryption module for Gitea.
// All encryption and decryption happens in the browser.
// Uses HYBRID post-quantum cryptography: X25519 + ML-KEM-768.
// The server NEVER sees plaintext content or private keys.

import init, {
  mlkem768_keygen, mlkem768_dk_size, mlkem768_ek_size,
  mlkem768_encapsulate, mlkem768_decapsulate,
  derive_hybrid_key, aes256gcm_encrypt, aes256gcm_decrypt,
} from '../../../public/assets/wasm/gitea_crypto.js';

const E2E_PREFIX = 'e2e:v1:';
const KDF_ITERATIONS_DEFAULT = 600000;
const REPO_KEY_LENGTH = 32; // 256-bit AES key

let wasmInitialized = false;
let wasmInitPromise: Promise<void> | null = null;

// Initialize the WASM module lazily. Only loads the 64KB WASM binary
// when crypto operations are actually needed (not on every page load).
export async function initCrypto(): Promise<void> {
  if (wasmInitialized) return;
  if (!wasmInitPromise) {
    wasmInitPromise = init().then(() => { wasmInitialized = true; });
  }
  await wasmInitPromise;
}

// Zero out a Uint8Array to prevent sensitive data from lingering in memory.
// Called after private keys, repo keys, and shared secrets are no longer needed.
export function zeroMemory(data: Uint8Array): void {
  crypto.getRandomValues(data); // overwrite with random first
  data.fill(0);                 // then zero
}

// Check if content is E2E encrypted
export function isE2EEncrypted(content: string): boolean {
  return content.startsWith(E2E_PREFIX);
}

// --- Key Derivation (passphrase → AES key for private key encryption) ---

export async function deriveKeyFromPassphrase(
  passphrase: string,
  salt: Uint8Array,
  iterations: number = KDF_ITERATIONS_DEFAULT,
): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    {name: 'PBKDF2', salt, iterations, hash: 'SHA-256'},
    keyMaterial,
    {name: 'AES-GCM', length: 256},
    true, // extractable to get raw bytes
    ['encrypt', 'decrypt'],
  );
}

// --- Passphrase-based AES-GCM (for encrypting the private key bundle) ---

async function passphraseEncrypt(key: CryptoKey, plaintext: Uint8Array): Promise<Uint8Array> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    {name: 'AES-GCM', iv: nonce}, key, plaintext,
  ));
  const result = new Uint8Array(nonce.length + ct.length);
  result.set(nonce);
  result.set(ct, nonce.length);
  return result;
}

async function passphraseDecrypt(key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  const nonce = data.slice(0, 12);
  const ct = data.slice(12);
  return new Uint8Array(await crypto.subtle.decrypt(
    {name: 'AES-GCM', iv: nonce}, key, ct,
  ));
}

// --- Hybrid Key Pair: X25519 + ML-KEM-768 ---

export interface HybridKeyPair {
  x25519PublicKey: Uint8Array;   // 32 bytes
  x25519PrivateKey: Uint8Array;  // PKCS8 encoded
  mlkemPublicKey: Uint8Array;    // 1184 bytes (encapsulation key)
  mlkemPrivateKey: Uint8Array;   // 2400 bytes (decapsulation key)
}

export async function generateHybridKeyPair(): Promise<HybridKeyPair> {
  await initCrypto();

  // Generate X25519 key pair (Web Crypto)
  const x25519Pair = await crypto.subtle.generateKey(
    {name: 'X25519'} as any, true, ['deriveKey', 'deriveBits'],
  );
  const x25519Pub = new Uint8Array(await crypto.subtle.exportKey('raw', x25519Pair.publicKey));
  const x25519Priv = new Uint8Array(await crypto.subtle.exportKey('pkcs8', x25519Pair.privateKey));

  // Generate ML-KEM-768 key pair (Rust WASM)
  const mlkemKeys = mlkem768_keygen();
  const dkSize = mlkem768_dk_size();
  const mlkemPriv = mlkemKeys.slice(0, dkSize);
  const mlkemPub = mlkemKeys.slice(dkSize);

  return {
    x25519PublicKey: x25519Pub,
    x25519PrivateKey: x25519Priv,
    mlkemPublicKey: mlkemPub,
    mlkemPrivateKey: mlkemPriv,
  };
}

// Bundle private keys for storage (encrypted with passphrase)
function bundlePrivateKeys(kp: HybridKeyPair): Uint8Array {
  // Format: [4-byte x25519 len][x25519 priv][mlkem priv]
  const x25519Len = kp.x25519PrivateKey.length;
  const bundle = new Uint8Array(4 + x25519Len + kp.mlkemPrivateKey.length);
  new DataView(bundle.buffer).setUint32(0, x25519Len);
  bundle.set(kp.x25519PrivateKey, 4);
  bundle.set(kp.mlkemPrivateKey, 4 + x25519Len);
  return bundle;
}

function unbundlePrivateKeys(bundle: Uint8Array): {x25519: Uint8Array; mlkem: Uint8Array} {
  const x25519Len = new DataView(bundle.buffer, bundle.byteOffset).getUint32(0);
  return {
    x25519: bundle.slice(4, 4 + x25519Len),
    mlkem: bundle.slice(4 + x25519Len),
  };
}

// Bundle public keys for storage
export function bundlePublicKeys(x25519Pub: Uint8Array, mlkemPub: Uint8Array): Uint8Array {
  // Format: [32-byte x25519][1184-byte mlkem]
  const bundle = new Uint8Array(x25519Pub.length + mlkemPub.length);
  bundle.set(x25519Pub);
  bundle.set(mlkemPub, x25519Pub.length);
  return bundle;
}

export function unbundlePublicKeys(bundle: Uint8Array): {x25519: Uint8Array; mlkem: Uint8Array} {
  return {
    x25519: bundle.slice(0, 32),
    mlkem: bundle.slice(32),
  };
}

// Encrypt private key bundle with passphrase
export async function encryptPrivateKeys(
  kp: HybridKeyPair,
  passphrase: string,
): Promise<{encrypted: string; salt: string; iterations: number}> {
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const iterations = KDF_ITERATIONS_DEFAULT;
  const aesKey = await deriveKeyFromPassphrase(passphrase, salt, iterations);
  const bundle = bundlePrivateKeys(kp);
  const encrypted = await passphraseEncrypt(aesKey, bundle);
  return {
    encrypted: uint8ToBase64(encrypted),
    salt: uint8ToBase64(salt),
    iterations,
  };
}

// Decrypt private key bundle with passphrase
export async function decryptPrivateKeys(
  encryptedBase64: string,
  saltBase64: string,
  iterations: number,
  passphrase: string,
): Promise<{x25519: Uint8Array; mlkem: Uint8Array}> {
  const salt = base64ToUint8(saltBase64);
  const aesKey = await deriveKeyFromPassphrase(passphrase, salt, iterations);
  const encrypted = base64ToUint8(encryptedBase64);
  const bundle = await passphraseDecrypt(aesKey, encrypted);
  return unbundlePrivateKeys(bundle);
}

// --- Repo key: generate ---

export function generateRepoKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(REPO_KEY_LENGTH));
}

// --- Hybrid repo key encryption (X25519 + ML-KEM-768) ---

// Encrypt a repo key for a recipient using hybrid key exchange.
// Both X25519 ECDH AND ML-KEM-768 KEM contribute to the wrapping key.
// Even if one is broken (e.g. X25519 by quantum computer), the other protects.
export async function encryptRepoKeyHybrid(
  repoKey: Uint8Array,
  recipientPubBundle: Uint8Array, // bundled: [32-byte x25519][1184-byte mlkem]
  senderX25519PrivPkcs8: Uint8Array,
): Promise<string> {
  await initCrypto();

  const {x25519: recipientX25519Pub, mlkem: recipientMlkemPub} = unbundlePublicKeys(recipientPubBundle);

  // 1. X25519 ECDH shared secret
  const recipientKey = await crypto.subtle.importKey(
    'raw', recipientX25519Pub, {name: 'X25519'} as any, false, [],
  );
  const senderPriv = await crypto.subtle.importKey(
    'pkcs8', senderX25519PrivPkcs8, {name: 'X25519'} as any, false, ['deriveBits'],
  );
  const x25519SS = new Uint8Array(await crypto.subtle.deriveBits(
    {name: 'X25519', public: recipientKey} as any, senderPriv, 256,
  ));

  // 2. ML-KEM-768 encapsulation (via Rust WASM)
  const mlkemResult = mlkem768_encapsulate(recipientMlkemPub);
  const mlkemSS = mlkemResult.slice(0, 32);
  const mlkemCT = mlkemResult.slice(32);

  // 3. Derive hybrid wrapping key (via Rust WASM HKDF)
  const wrappingKey = derive_hybrid_key(x25519SS, mlkemSS);

  // 4. Wrap repo key with AES-256-GCM (via Rust WASM)
  const wrappedRepoKey = aes256gcm_encrypt(wrappingKey, repoKey);

  // 5. Get sender's X25519 public key for inclusion
  const senderPubJwk = await crypto.subtle.exportKey('jwk',
    (await crypto.subtle.importKey('pkcs8', senderX25519PrivPkcs8, {name: 'X25519'} as any, true, ['deriveBits'])),
  );
  const senderX25519Pub = base64UrlToUint8(senderPubJwk.x!);

  // Output: [32-byte sender X25519 pub][mlkem ciphertext][wrapped repo key]
  const result = new Uint8Array(32 + mlkemCT.length + wrappedRepoKey.length);
  result.set(senderX25519Pub, 0);
  result.set(mlkemCT, 32);
  result.set(wrappedRepoKey, 32 + mlkemCT.length);
  return uint8ToBase64(result);
}

// Decrypt a repo key using hybrid key exchange.
export async function decryptRepoKeyHybrid(
  encryptedBase64: string,
  recipientX25519PrivPkcs8: Uint8Array,
  recipientMlkemPriv: Uint8Array,
): Promise<Uint8Array> {
  await initCrypto();

  const data = base64ToUint8(encryptedBase64);
  const ctSize = 1088; // ML-KEM-768 ciphertext size

  const senderX25519Pub = data.slice(0, 32);
  const mlkemCT = data.slice(32, 32 + ctSize);
  const wrappedRepoKey = data.slice(32 + ctSize);

  // 1. X25519 ECDH shared secret
  const senderPub = await crypto.subtle.importKey(
    'raw', senderX25519Pub, {name: 'X25519'} as any, false, [],
  );
  const recipientPriv = await crypto.subtle.importKey(
    'pkcs8', recipientX25519PrivPkcs8, {name: 'X25519'} as any, false, ['deriveBits'],
  );
  const x25519SS = new Uint8Array(await crypto.subtle.deriveBits(
    {name: 'X25519', public: senderPub} as any, recipientPriv, 256,
  ));

  // 2. ML-KEM-768 decapsulation (via Rust WASM)
  const mlkemSS = mlkem768_decapsulate(recipientMlkemPriv, mlkemCT);

  // 3. Derive hybrid wrapping key
  const wrappingKey = derive_hybrid_key(x25519SS, new Uint8Array(mlkemSS));

  // 4. Unwrap repo key
  return new Uint8Array(aes256gcm_decrypt(wrappingKey, wrappedRepoKey));
}

// --- Content encryption/decryption (AES-256-GCM via WASM) ---

export async function encryptContent(
  content: string,
  repoKey: Uint8Array,
): Promise<string> {
  if (!content) return content;
  await initCrypto();
  const plaintext = new TextEncoder().encode(content);
  const encrypted = aes256gcm_encrypt(repoKey, plaintext);
  return E2E_PREFIX + uint8ToBase64(new Uint8Array(encrypted));
}

export async function decryptContent(
  content: string,
  repoKey: Uint8Array,
): Promise<string> {
  if (!content || !isE2EEncrypted(content)) return content;
  await initCrypto();
  const payload = content.slice(E2E_PREFIX.length);
  const encrypted = base64ToUint8(payload);
  const decrypted = aes256gcm_decrypt(repoKey, encrypted);
  return new TextDecoder().decode(new Uint8Array(decrypted));
}

// --- Base64 utilities ---

export function uint8ToBase64(data: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < data.length; i++) {
    binary += String.fromCharCode(data[i]);
  }
  return btoa(binary);
}

export function base64ToUint8(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function base64UrlToUint8(b64url: string): Uint8Array {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4;
  return base64ToUint8(pad ? b64 + '='.repeat(4 - pad) : b64);
}
