// Integrity verification for E2E encryption code.
// Detects if the server has tampered with the WASM binary or crypto code.
//
// LIMITATION: A truly malicious server that controls ALL served JS can always
// circumvent client-side checks. For maximum security, users should:
// - Verify the WASM hash out-of-band (e.g., from a signed release)
// - Use browser extensions to pin/verify scripts
// - Build and self-host from audited source code

import {GET} from './fetch.ts';

const WASM_PATH = `${window.config?.appSubUrl || ''}/assets/wasm/gitea_crypto_bg.wasm`;

export async function computeWasmHash(): Promise<string> {
  const response = await GET(WASM_PATH);
  const buffer = await response.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = new Uint8Array(hashBuffer);
  return Array.from(hashArray, (b) => b.toString(16).padStart(2, '0')).join('');
}

export async function verifyWasmIntegrity(expectedHash: string): Promise<boolean> {
  const actualHash = await computeWasmHash();
  return actualHash === expectedHash.toLowerCase();
}

export async function getWasmIntegrityInfo(): Promise<{hash: string, path: string}> {
  return {
    hash: await computeWasmHash(),
    path: WASM_PATH,
  };
}

export function verifyCryptoApiAvailable(): boolean {
  return (
    'crypto' in globalThis &&
    'subtle' in crypto &&
    typeof crypto.subtle.generateKey === 'function' &&
    typeof crypto.subtle.encrypt === 'function' &&
    typeof crypto.subtle.decrypt === 'function' &&
    typeof crypto.subtle.deriveBits === 'function' &&
    typeof crypto.subtle.importKey === 'function' &&
    typeof crypto.getRandomValues === 'function'
  );
}
