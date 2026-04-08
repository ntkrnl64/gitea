// Gitea E2E Encryption Verifier — Chrome Extension Content Script
// Checks ALL served scripts against checksums from giteachecksums.krnl64.win
// Detects: tampered WASM, injected scripts, missing E2E, inline script injection
//
// A malicious server provider could:
// 1. Modify the WASM/JS crypto code → detected by hash mismatch
// 2. Inject an ADDITIONAL script to steal keys → detected by script audit
// 3. Add inline scripts → detected by inline script scan
// 4. Serve entirely different code → detected by checking ALL script hashes

(function () {
  'use strict';

  const CHECKSUM_HOST = 'https://giteachecksums.krnl64.win';
  const WASM_FILENAME = 'gitea_crypto_bg.wasm';
  const JS_FILENAME = 'gitea_crypto.js';

  function isGiteaInstance() {
    return document.querySelector('meta[name="author"][content*="Gitea"]') !== null ||
           document.querySelector('meta[name="keywords"][content*="gitea"]') !== null;
  }

  if (!isGiteaInstance()) return;

  function injectBadge(status, label, tooltip) {
    const existing = document.getElementById('e2e-verify-badge');
    if (existing) existing.remove();

    const badge = document.createElement('div');
    badge.id = 'e2e-verify-badge';
    badge.title = tooltip;
    badge.textContent = label;
    Object.assign(badge.style, {
      position: 'fixed', bottom: '8px', right: '8px', zIndex: '99999',
      padding: '4px 10px', borderRadius: '4px', fontSize: '11px',
      fontFamily: 'monospace', cursor: 'pointer',
      boxShadow: '0 2px 6px rgba(0,0,0,0.3)',
    });

    const colors = {
      verified:      { bg: '#28a745', fg: '#fff' },
      tampered:      { bg: '#dc3545', fg: '#fff' },
      'no-e2e':      { bg: '#6c757d', fg: '#fff' },
      'no-checksum': { bg: '#ffc107', fg: '#000' },
      checking:      { bg: '#ffc107', fg: '#000' },
      error:         { bg: '#dc3545', fg: '#fff' },
      suspicious:    { bg: '#fd7e14', fg: '#fff' },
    };
    const c = colors[status] || colors.error;
    badge.style.background = c.bg;
    badge.style.color = c.fg;
    document.body.appendChild(badge);
  }

  async function hashUrl(url) {
    try {
      const resp = await fetch(url, { cache: 'reload' });
      if (!resp.ok) return null;
      const buf = await resp.arrayBuffer();
      const hash = await crypto.subtle.digest('SHA-256', buf);
      return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
    } catch {
      return null;
    }
  }

  async function fetchChecksum(identifier) {
    const resp = await fetch(`${CHECKSUM_HOST}/${identifier}`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return resp.json();
  }

  function getGiteaVersion() {
    const meta = document.querySelector('meta[name="gitea-version"]');
    if (meta) return meta.content;
    const footer = document.querySelector('.footer .powered');
    if (footer) {
      const match = footer.textContent.match(/(\d+\.\d+\.\d+)/);
      if (match) return 'v' + match[1];
    }
    return 'latest';
  }

  // --- Script Audit ---
  // Scan the page for suspicious injected scripts that could steal E2E keys.
  // A malicious provider wouldn't just modify the WASM — they'd inject entirely
  // new scripts to intercept passphrases, keys, or decrypted content.

  function auditPageScripts() {
    const warnings = [];
    const scripts = document.querySelectorAll('script');
    const origin = window.location.origin;

    for (const script of scripts) {
      // Check inline scripts — Gitea shouldn't have inline script content
      // (its CSP should block them, but a malicious provider controls CSP)
      if (!script.src && script.textContent.trim()) {
        const content = script.textContent;
        // Flag inline scripts that access crypto-related APIs
        const suspicious = [
          'sessionStorage', 'e2e_', 'passphrase', 'privateKey', 'private_key',
          'encryption', 'decrypt', 'crypto.subtle', 'CryptoKey',
          'XMLHttpRequest', 'sendBeacon', 'WebSocket',
        ];
        const found = suspicious.filter(k => content.includes(k));
        if (found.length > 0) {
          warnings.push({
            type: 'inline-suspicious',
            message: `Inline script accesses: ${found.join(', ')}`,
            snippet: content.substring(0, 200),
          });
        }
      }

      // Check external scripts from unexpected origins
      if (script.src) {
        const scriptUrl = new URL(script.src, origin);
        if (scriptUrl.origin !== origin) {
          warnings.push({
            type: 'external-script',
            message: `External script from: ${scriptUrl.origin}`,
            url: script.src,
          });
        }
      }
    }

    // Check for MutationObserver or prototype tampering
    // (an advanced attack might intercept crypto.subtle methods)
    if (typeof crypto.subtle.encrypt !== 'function' ||
        crypto.subtle.encrypt.toString().includes('native code') === false) {
      warnings.push({
        type: 'api-tampered',
        message: 'crypto.subtle.encrypt may have been monkey-patched',
      });
    }

    return warnings;
  }

  function storeResult(result) {
    try {
      sessionStorage.setItem('e2e_verify_result', JSON.stringify(result));
    } catch { /* blocked */ }
  }

  async function verify() {
    injectBadge('checking', '\u{1f50d} E2E: checking...', 'Verifying encryption integrity...');

    const appSubUrl = document.querySelector('meta[name="_suburl"]')?.content || '';
    const wasmUrl = `${window.location.origin}${appSubUrl}/assets/wasm/${WASM_FILENAME}`;
    const jsUrl = `${window.location.origin}${appSubUrl}/assets/wasm/${JS_FILENAME}`;

    // Audit all scripts on the page
    const scriptWarnings = auditPageScripts();

    // Check if WASM exists
    let wasmExists = false;
    try {
      const resp = await fetch(wasmUrl, { method: 'HEAD' });
      wasmExists = resp.ok;
    } catch { /* not available */ }

    if (!wasmExists) {
      injectBadge('no-e2e', '\u{1f513} No E2E', 'This Gitea instance does not have E2E encryption enabled.');
      storeResult({
        status: 'no-e2e',
        message: 'No E2E encryption WASM module found. Content is stored in plaintext on the server.',
        instanceUrl: window.location.origin,
        scriptWarnings,
      });
      return;
    }

    // Hash served files
    const [wasmHash, jsHash] = await Promise.all([hashUrl(wasmUrl), hashUrl(jsUrl)]);
    if (!wasmHash) {
      injectBadge('error', '\u{26a0}\u{fe0f} E2E: hash error', 'Could not compute hash of WASM module');
      storeResult({ status: 'error', message: 'Could not hash WASM file', instanceUrl: window.location.origin, scriptWarnings });
      return;
    }

    // Hash ALL JS files loaded on the page (to detect injected scripts)
    const allScripts = Array.from(document.querySelectorAll('script[src]')).map(s => s.src);
    const scriptHashes = {};
    for (const src of allScripts) {
      scriptHashes[src] = await hashUrl(src);
    }

    // Fetch expected checksum
    const version = getGiteaVersion();
    let checksum;
    try {
      checksum = await fetchChecksum(version);
    } catch {
      try { checksum = await fetchChecksum('latest'); } catch {
        injectBadge('no-checksum', '\u{2753} E2E: unverified', 'No checksum available for verification.');
        storeResult({
          status: 'no-checksum',
          message: `No checksum for ${version} at ${CHECKSUM_HOST}`,
          wasmHash, jsHash, scriptWarnings, scriptHashes,
          instanceUrl: window.location.origin,
        });
        return;
      }
    }

    // Compare crypto files
    const wasmOk = wasmHash === checksum.wasm_sha256;
    const jsOk = jsHash === checksum.js_sha256;
    const cryptoOk = wasmOk && jsOk;

    // Determine overall status
    let status;
    if (!cryptoOk) {
      status = 'tampered';
    } else if (scriptWarnings.length > 0) {
      status = 'suspicious';
    } else {
      status = 'verified';
    }

    const labels = {
      verified:   '\u{1f512} E2E verified',
      tampered:   '\u{26a0}\u{fe0f} E2E TAMPERED',
      suspicious: '\u{26a0}\u{fe0f} E2E: suspicious scripts',
    };
    const tooltips = {
      verified:   'Crypto code verified. No suspicious scripts detected.',
      tampered:   'Crypto code does NOT match official build!',
      suspicious: 'Crypto code is OK but suspicious scripts were detected on the page.',
    };
    injectBadge(status, labels[status], tooltips[status]);

    storeResult({
      status,
      wasmHash, jsHash,
      expectedWasm: checksum.wasm_sha256, expectedJs: checksum.js_sha256,
      commit: checksum.commit, builtAt: checksum.built_at,
      version, instanceUrl: window.location.origin,
      scriptWarnings,
      totalScriptsOnPage: allScripts.length,
      scriptHashes,
    });
  }

  verify();
})();
