// Client-side E2E encryption module for Gitea.
// All encryption and decryption happens in the browser using Web Crypto API.
// The server NEVER sees plaintext content or private keys.

const E2E_PREFIX = 'e2e:v1:';
const KDF_ITERATIONS_DEFAULT = 600000;
const REPO_KEY_LENGTH = 32;

export function isE2EEncrypted(content: string): boolean {
  return content.startsWith(E2E_PREFIX);
}

// --- Key Derivation (passphrase -> key) ---

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
    false,
    ['encrypt', 'decrypt'],
  );
}

// --- AES-256-GCM encrypt/decrypt ---

async function aesGcmEncrypt(key: CryptoKey, plaintext: Uint8Array): Promise<Uint8Array> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    {name: 'AES-GCM', iv: nonce}, key, plaintext,
  ));
  const result = new Uint8Array(nonce.length + ciphertext.length);
  result.set(nonce);
  result.set(ciphertext, nonce.length);
  return result;
}

async function aesGcmDecrypt(key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  const nonce = data.slice(0, 12);
  const ciphertext = data.slice(12);
  return new Uint8Array(await crypto.subtle.decrypt(
    {name: 'AES-GCM', iv: nonce}, key, ciphertext,
  ));
}

// --- X25519 ECDH key pair generation ---

export async function generateUserKeyPair(): Promise<{publicKey: Uint8Array, privateKey: Uint8Array}> {
  const keyPair = await crypto.subtle.generateKey(
    {name: 'X25519'} as EcKeyGenParams,
    true,
    ['deriveBits'],
  );
  const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));
  const privateKey = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey));
  return {publicKey, privateKey};
}

export async function encryptPrivateKey(
  privateKey: Uint8Array,
  passphrase: string,
): Promise<{encrypted: string, salt: string, iterations: number}> {
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const iterations = KDF_ITERATIONS_DEFAULT;
  const aesKey = await deriveKeyFromPassphrase(passphrase, salt, iterations);
  const encrypted = await aesGcmEncrypt(aesKey, privateKey);
  return {
    encrypted: uint8ToBase64(encrypted),
    salt: uint8ToBase64(salt),
    iterations,
  };
}

export async function decryptPrivateKey(
  encryptedBase64: string,
  saltBase64: string,
  iterations: number,
  passphrase: string,
): Promise<Uint8Array> {
  const salt = base64ToUint8(saltBase64);
  const aesKey = await deriveKeyFromPassphrase(passphrase, salt, iterations);
  const encrypted = base64ToUint8(encryptedBase64);
  return aesGcmDecrypt(aesKey, encrypted);
}

// --- Repo key management ---

export function generateRepoKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(REPO_KEY_LENGTH));
}

export async function encryptRepoKeyForUser(
  repoKey: Uint8Array,
  recipientPublicKeyRaw: Uint8Array,
  senderPrivateKeyPkcs8: Uint8Array,
): Promise<string> {
  const recipientPub = await crypto.subtle.importKey(
    'raw', recipientPublicKeyRaw, {name: 'X25519'} as EcKeyImportParams, false, [],
  );
  const senderPriv = await crypto.subtle.importKey(
    'pkcs8', senderPrivateKeyPkcs8, {name: 'X25519'} as EcKeyImportParams, false, ['deriveBits'],
  );
  const sharedBits = new Uint8Array(await crypto.subtle.deriveBits(
    {name: 'X25519', public: recipientPub} as EcdhKeyDeriveParams, senderPriv, 256,
  ));
  const sharedKeyMaterial = await crypto.subtle.importKey(
    'raw', sharedBits, 'HKDF', false, ['deriveKey'],
  );
  const wrappingKey = await crypto.subtle.deriveKey(
    {name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('gitea-e2e-repo-key')},
    sharedKeyMaterial,
    {name: 'AES-GCM', length: 256},
    false,
    ['encrypt'],
  );
  const encrypted = await aesGcmEncrypt(wrappingKey, repoKey);
  const senderPubKey = await getSenderPublicKey(senderPrivateKeyPkcs8);
  const result = new Uint8Array(senderPubKey.length + encrypted.length);
  result.set(senderPubKey);
  result.set(encrypted, senderPubKey.length);
  return uint8ToBase64(result);
}

export async function decryptRepoKey(
  encryptedBase64: string,
  recipientPrivateKeyPkcs8: Uint8Array,
): Promise<Uint8Array> {
  const data = base64ToUint8(encryptedBase64);
  const senderPubRaw = data.slice(0, 32);
  const encrypted = data.slice(32);

  const senderPub = await crypto.subtle.importKey(
    'raw', senderPubRaw, {name: 'X25519'} as EcKeyImportParams, false, [],
  );
  const recipientPriv = await crypto.subtle.importKey(
    'pkcs8', recipientPrivateKeyPkcs8, {name: 'X25519'} as EcKeyImportParams, false, ['deriveBits'],
  );
  const sharedBits = new Uint8Array(await crypto.subtle.deriveBits(
    {name: 'X25519', public: senderPub} as EcdhKeyDeriveParams, recipientPriv, 256,
  ));
  const sharedKeyMaterial = await crypto.subtle.importKey(
    'raw', sharedBits, 'HKDF', false, ['deriveKey'],
  );
  const wrappingKey = await crypto.subtle.deriveKey(
    {name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('gitea-e2e-repo-key')},
    sharedKeyMaterial,
    {name: 'AES-GCM', length: 256},
    false,
    ['decrypt'],
  );
  return aesGcmDecrypt(wrappingKey, encrypted);
}

async function getSenderPublicKey(privateKeyPkcs8: Uint8Array): Promise<Uint8Array> {
  const privKey = await crypto.subtle.importKey(
    'pkcs8', privateKeyPkcs8, {name: 'X25519'} as EcKeyImportParams, true, ['deriveBits'],
  );
  const jwk = await crypto.subtle.exportKey('jwk', privKey);
  return base64UrlToUint8(jwk.x!);
}

// --- Content encryption/decryption ---

export async function encryptContent(
  content: string,
  repoKey: Uint8Array,
): Promise<string> {
  if (!content) return content;
  const aesKey = await crypto.subtle.importKey(
    'raw', repoKey, {name: 'AES-GCM', length: 256}, false, ['encrypt'],
  );
  const plaintext = new TextEncoder().encode(content);
  const encrypted = await aesGcmEncrypt(aesKey, plaintext);
  return E2E_PREFIX + uint8ToBase64(encrypted);
}

export async function decryptContent(
  content: string,
  repoKey: Uint8Array,
): Promise<string> {
  if (!content || !isE2EEncrypted(content)) return content;
  const payload = content.slice(E2E_PREFIX.length);
  const aesKey = await crypto.subtle.importKey(
    'raw', repoKey, {name: 'AES-GCM', length: 256}, false, ['decrypt'],
  );
  const encrypted = base64ToUint8(payload);
  const decrypted = await aesGcmDecrypt(aesKey, encrypted);
  return new TextDecoder().decode(decrypted);
}

// Zero out a Uint8Array to prevent sensitive data from lingering in memory.
export function zeroMemory(data: Uint8Array): void {
  crypto.getRandomValues(data);
  data.fill(0);
}

// --- Base64 utilities ---

export function uint8ToBase64(data: Uint8Array): string {
  let binary = '';
  for (const byte of data) {
    binary += String.fromCharCode(byte);
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
