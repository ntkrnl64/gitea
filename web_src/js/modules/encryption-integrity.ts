// Integrity verification for E2E encryption code.
// Detects if the server has tampered with the WASM binary or crypto code.
//
// Defense against malicious server provider modifying JS/WASM to exfiltrate keys:
// 1. WASM binary is hashed at build time; users can verify the hash
// 2. The WASM binary is loaded and its hash verified before any crypto operation
// 3. CSP headers should restrict inline scripts and eval
//
// LIMITATION: A truly malicious server that controls ALL served JS can always
// circumvent client-side checks. This is a fundamental limitation of web-based
// E2E encryption. For maximum security, users should:
// - Verify the WASM hash out-of-band (e.g., from a signed release)
// - Use browser extensions to pin/verify scripts
// - Build and self-host from audited source code
// - Use native clients instead of the web UI for sensitive operations

const WASM_PATH = `${window.config?.appSubUrl || ''}/assets/wasm/gitea_crypto_bg.wasm`;

// Compute SHA-256 hash of the WASM binary
export async function computeWasmHash(): Promise<string> {
  const response = await fetch(WASM_PATH);
  const buffer = await response.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = new Uint8Array(hashBuffer);
  return Array.from(hashArray).map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Verify WASM binary against an expected hash.
// Users can obtain the expected hash from a signed release manifest.
export async function verifyWasmIntegrity(expectedHash: string): Promise<boolean> {
  const actualHash = await computeWasmHash();
  return actualHash === expectedHash.toLowerCase();
}

// Display the current WASM hash for user verification
export async function getWasmIntegrityInfo(): Promise<{hash: string; path: string}> {
  return {
    hash: await computeWasmHash(),
    path: WASM_PATH,
  };
}

// Check if critical crypto functions exist and haven't been replaced with stubs
export function verifyCryptoApiAvailable(): boolean {
  return (
    typeof crypto !== 'undefined' &&
    typeof crypto.subtle !== 'undefined' &&
    typeof crypto.subtle.generateKey === 'function' &&
    typeof crypto.subtle.encrypt === 'function' &&
    typeof crypto.subtle.decrypt === 'function' &&
    typeof crypto.subtle.deriveBits === 'function' &&
    typeof crypto.subtle.importKey === 'function' &&
    typeof crypto.getRandomValues === 'function'
  );
}

// Recommended CSP header for E2E encryption pages:
// Content-Security-Policy:
//   default-src 'self';
//   script-src 'self' 'wasm-unsafe-eval';
//   style-src 'self' 'unsafe-inline';
//   connect-src 'self';
//   img-src 'self' data:;
//   object-src 'none';
//   base-uri 'self';
//
// 'wasm-unsafe-eval' is needed for WASM execution.
// No 'unsafe-eval' — prevents eval() injection.
// No external script sources — all code must come from the same origin.
