// Client-side E2E key management for Gitea.
// Uses HYBRID post-quantum crypto: X25519 + ML-KEM-768.
// Private keys cached in sessionStorage (cleared when tab closes).
// The server NEVER has access to plaintext private keys or repo keys.

import {
  initCrypto, zeroMemory,
  generateHybridKeyPair, encryptPrivateKeys, decryptPrivateKeys,
  generateRepoKey, encryptRepoKeyHybrid, decryptRepoKeyHybrid,
  bundlePublicKeys, unbundlePublicKeys,
  uint8ToBase64, base64ToUint8,
} from './encryption.ts';
import {POST, GET} from './fetch.ts';

const SESSION_X25519_PRIV = 'e2e_x25519_priv';
const SESSION_MLKEM_PRIV = 'e2e_mlkem_priv';
const SESSION_PUB_BUNDLE = 'e2e_pub_bundle';

// --- Session key cache ---

export function getCachedX25519PrivateKey(): Uint8Array | null {
  const stored = sessionStorage.getItem(SESSION_X25519_PRIV);
  return stored ? base64ToUint8(stored) : null;
}

export function getCachedMlkemPrivateKey(): Uint8Array | null {
  const stored = sessionStorage.getItem(SESSION_MLKEM_PRIV);
  return stored ? base64ToUint8(stored) : null;
}

export function getCachedPublicBundle(): Uint8Array | null {
  const stored = sessionStorage.getItem(SESSION_PUB_BUNDLE);
  return stored ? base64ToUint8(stored) : null;
}

function cacheKeys(x25519Priv: Uint8Array, mlkemPriv: Uint8Array, pubBundle: Uint8Array): void {
  sessionStorage.setItem(SESSION_X25519_PRIV, uint8ToBase64(x25519Priv));
  sessionStorage.setItem(SESSION_MLKEM_PRIV, uint8ToBase64(mlkemPriv));
  sessionStorage.setItem(SESSION_PUB_BUNDLE, uint8ToBase64(pubBundle));
}

export function clearCachedKeys(): void {
  // Zero out cached key data before removing
  const x25519 = getCachedX25519PrivateKey();
  const mlkem = getCachedMlkemPrivateKey();
  if (x25519) zeroMemory(x25519);
  if (mlkem) zeroMemory(mlkem);
  repoKeyCache.forEach((key) => zeroMemory(key));
  repoKeyCache.clear();
  sessionStorage.removeItem(SESSION_X25519_PRIV);
  sessionStorage.removeItem(SESSION_MLKEM_PRIV);
  sessionStorage.removeItem(SESSION_PUB_BUNDLE);
}

export function hasUnlockedKeys(): boolean {
  return getCachedX25519PrivateKey() !== null && getCachedMlkemPrivateKey() !== null;
}

// --- User key pair operations (hybrid: X25519 + ML-KEM-768) ---

export async function setupUserKeyPair(passphrase: string): Promise<void> {
  await initCrypto();

  const kp = await generateHybridKeyPair();
  const {encrypted, salt, iterations} = await encryptPrivateKeys(kp, passphrase);
  const pubBundle = bundlePublicKeys(kp.x25519PublicKey, kp.mlkemPublicKey);

  await POST(`${window.config.appSubUrl}/api/v1/user/encryption`, {
    data: new URLSearchParams({
      public_key: uint8ToBase64(pubBundle),
      encrypted_private_key: encrypted,
      kdf_salt: salt,
      kdf_iterations: String(iterations),
    }),
  });

  cacheKeys(kp.x25519PrivateKey, kp.mlkemPrivateKey, pubBundle);
}

export async function unlockUserKeys(passphrase: string): Promise<boolean> {
  await initCrypto();

  const resp = await GET(`${window.config.appSubUrl}/api/v1/user/encryption`);
  const data = await resp.json();

  if (!data.has_key) return false;

  try {
    const {x25519, mlkem} = await decryptPrivateKeys(
      data.encrypted_private_key,
      data.kdf_salt,
      data.kdf_iterations,
      passphrase,
    );
    const pubBundle = base64ToUint8(data.public_key);
    cacheKeys(x25519, mlkem, pubBundle);
    return true;
  } catch {
    return false;
  }
}

export async function hasUserKeyPair(): Promise<boolean> {
  const resp = await GET(`${window.config.appSubUrl}/api/v1/user/encryption`);
  const data = await resp.json();
  return data.has_key;
}

// --- Repo key operations (hybrid encrypted) ---

const repoKeyCache = new Map<number, Uint8Array>();

export async function getRepoKey(repoID: number, repoLink: string): Promise<Uint8Array | null> {
  if (repoKeyCache.has(repoID)) {
    return repoKeyCache.get(repoID)!;
  }

  const x25519Priv = getCachedX25519PrivateKey();
  const mlkemPriv = getCachedMlkemPrivateKey();
  if (!x25519Priv || !mlkemPriv) return null;

  await initCrypto();

  const resp = await GET(`${window.config.appSubUrl}/api/v1/repos/${repoLink}/encryption/keys`);
  const data = await resp.json();

  if (!data.e2e_enabled) return null;

  try {
    const repoKey = await decryptRepoKeyHybrid(data.encrypted_repo_key, x25519Priv, mlkemPriv);
    repoKeyCache.set(repoID, repoKey);
    return repoKey;
  } catch {
    return null;
  }
}

export async function enableE2EForRepo(repoLink: string, collaboratorUsernames: string[] = []): Promise<void> {
  const x25519Priv = getCachedX25519PrivateKey();
  const pubBundle = getCachedPublicBundle();
  if (!x25519Priv || !pubBundle) {
    throw new Error('Keys not unlocked. Enter your passphrase first.');
  }

  await initCrypto();
  const repoKey = generateRepoKey();

  // Encrypt repo key for the current user (hybrid)
  const encryptedForSelf = await encryptRepoKeyHybrid(repoKey, pubBundle, x25519Priv);
  await POST(`${window.config.appSubUrl}/api/v1/repos/${repoLink}/encryption/keys`, {
    data: new URLSearchParams({encrypted_repo_key: encryptedForSelf}),
  });

  // Encrypt repo key for each collaborator (hybrid)
  for (const username of collaboratorUsernames) {
    const pubResp = await GET(`${window.config.appSubUrl}/api/v1/users/${username}/encryption/publickey`);
    const pubData = await pubResp.json();
    if (!pubData.public_key) continue;

    const collabPubBundle = base64ToUint8(pubData.public_key);
    const encryptedForCollab = await encryptRepoKeyHybrid(repoKey, collabPubBundle, x25519Priv);
    await POST(`${window.config.appSubUrl}/api/v1/repos/${repoLink}/encryption/keys`, {
      data: new URLSearchParams({
        encrypted_repo_key: encryptedForCollab,
        user_id: String(pubData.user_id),
      }),
    });
  }
}
