// Client-side E2E key management for Gitea.
// Handles passphrase prompts, key caching, and repo key retrieval.
// Private keys are cached in sessionStorage (cleared when tab closes).

import {
  generateUserKeyPair, encryptPrivateKey, decryptPrivateKey,
  generateRepoKey, encryptRepoKeyForUser, decryptRepoKey,
  uint8ToBase64, base64ToUint8, zeroMemory,
} from './encryption.ts';
import {POST, GET} from './fetch.ts';

const SESSION_PRIVKEY = 'e2e_private_key';
const SESSION_PUBKEY = 'e2e_public_key';
const repoKeyCache = new Map<number, Uint8Array>();

// --- Session key cache ---

export function getCachedPrivateKey(): Uint8Array | null {
  const stored = sessionStorage.getItem(SESSION_PRIVKEY);
  if (!stored) return null;
  return base64ToUint8(stored);
}

export function getCachedPublicKey(): Uint8Array | null {
  const stored = sessionStorage.getItem(SESSION_PUBKEY);
  if (!stored) return null;
  return base64ToUint8(stored);
}

function cacheKeys(privateKey: Uint8Array, publicKey: Uint8Array): void {
  sessionStorage.setItem(SESSION_PRIVKEY, uint8ToBase64(privateKey));
  sessionStorage.setItem(SESSION_PUBKEY, uint8ToBase64(publicKey));
}

export function clearCachedKeys(): void {
  const priv = getCachedPrivateKey();
  const pub = getCachedPublicKey();
  if (priv) zeroMemory(priv);
  if (pub) zeroMemory(pub);
  for (const key of repoKeyCache.values()) {
    zeroMemory(key);
  }
  repoKeyCache.clear();
  sessionStorage.removeItem(SESSION_PRIVKEY);
  sessionStorage.removeItem(SESSION_PUBKEY);
}

export function hasUnlockedKeys(): boolean {
  return getCachedPrivateKey() !== null;
}

// --- User key pair operations ---

export async function setupUserKeyPair(passphrase: string): Promise<void> {
  const {publicKey, privateKey} = await generateUserKeyPair();
  const {encrypted, salt, iterations} = await encryptPrivateKey(privateKey, passphrase);

  await POST(`${window.config.appSubUrl}/api/v1/user/encryption`, {
    data: new URLSearchParams({
      public_key: uint8ToBase64(publicKey),
      encrypted_private_key: encrypted,
      kdf_salt: salt,
      kdf_iterations: String(iterations),
    }),
  });

  cacheKeys(privateKey, publicKey);
}

export async function unlockUserKeys(passphrase: string): Promise<boolean> {
  const resp = await GET(`${window.config.appSubUrl}/api/v1/user/encryption`);
  const data = await resp.json();

  if (!data.has_key) return false;

  try {
    const privateKey = await decryptPrivateKey(
      data.encrypted_private_key,
      data.kdf_salt,
      data.kdf_iterations,
      passphrase,
    );
    cacheKeys(privateKey, base64ToUint8(data.public_key));
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

// --- Repo key operations ---

export async function getRepoKey(repoID: number, repoLink: string): Promise<Uint8Array | null> {
  if (repoKeyCache.has(repoID)) {
    return repoKeyCache.get(repoID)!;
  }

  const privateKey = getCachedPrivateKey();
  if (!privateKey) return null;

  const resp = await GET(`${window.config.appSubUrl}/api/v1/repos/${repoLink}/encryption/keys`);
  const data = await resp.json();

  if (!data.e2e_enabled) return null;

  try {
    const repoKey = await decryptRepoKey(data.encrypted_repo_key, privateKey);
    repoKeyCache.set(repoID, repoKey);
    return repoKey;
  } catch {
    return null;
  }
}

export async function enableE2EForRepo(repoLink: string, collaboratorUsernames: string[] = []): Promise<void> {
  const privateKey = getCachedPrivateKey();
  const publicKey = getCachedPublicKey();
  if (!privateKey || !publicKey) {
    throw new Error('Keys not unlocked. Enter your passphrase first.');
  }

  const repoKey = generateRepoKey();

  const encryptedForSelf = await encryptRepoKeyForUser(repoKey, publicKey, privateKey);
  await POST(`${window.config.appSubUrl}/api/v1/repos/${repoLink}/encryption/keys`, {
    data: new URLSearchParams({encrypted_repo_key: encryptedForSelf}),
  });

  for (const username of collaboratorUsernames) {
    const pubResp = await GET(`${window.config.appSubUrl}/api/v1/users/${username}/encryption/publickey`);
    const pubData = await pubResp.json();
    if (!pubData.public_key) continue;

    const collabPubKey = base64ToUint8(pubData.public_key);
    const encryptedForCollab = await encryptRepoKeyForUser(repoKey, collabPubKey, privateKey);
    await POST(`${window.config.appSubUrl}/api/v1/repos/${repoLink}/encryption/keys`, {
      data: new URLSearchParams({
        encrypted_repo_key: encryptedForCollab,
        user_id: String(pubData.user_id),
      }),
    });
  }
}
