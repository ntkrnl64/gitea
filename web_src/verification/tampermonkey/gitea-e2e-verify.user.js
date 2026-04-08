// ==UserScript==
// @name         Gitea E2E Encryption Verifier
// @namespace    https://giteachecksums.krnl64.win
// @version      1.0.0
// @description  Verifies the integrity of Gitea's E2E encryption WASM module against signed checksums. Detects if the server has tampered with the crypto code.
// @author       ntkrnl64
// @match        *://*/*
// @grant        GM_xmlhttpRequest
// @grant        GM_addStyle
// @connect      giteachecksums.krnl64.win
// @run-at       document-idle
// ==/UserScript==

(function () {
  'use strict';

  // === Configuration ===
  const CHECKSUM_HOST = 'https://giteachecksums.krnl64.win';
  // Path in the checksum branch (served as raw files via Gitea/Pages)
  // Format: CHECKSUM_HOST/<commit_sha> or CHECKSUM_HOST/latest or CHECKSUM_HOST/<tag>
  const WASM_FILENAME = 'gitea_crypto_bg.wasm';
  const JS_FILENAME = 'gitea_crypto.js';

  // === Detect Gitea instance ===
  function isGiteaInstance() {
    return document.querySelector('meta[name="author"][content*="Gitea"]') !== null ||
           document.querySelector('meta[name="keywords"][content*="gitea"]') !== null ||
           document.querySelector('.js-global-error') !== null ||
           document.querySelector('[class*="gitea"]') !== null;
  }

  if (!isGiteaInstance()) return;

  // === Styles ===
  GM_addStyle(`
    #e2e-verify-badge {
      position: fixed;
      bottom: 12px;
      right: 12px;
      z-index: 99999;
      padding: 6px 12px;
      border-radius: 6px;
      font-size: 12px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
      cursor: pointer;
      box-shadow: 0 2px 8px rgba(0,0,0,0.2);
      transition: all 0.3s;
      user-select: none;
    }
    #e2e-verify-badge.checking { background: #ffc107; color: #000; }
    #e2e-verify-badge.verified { background: #28a745; color: #fff; }
    #e2e-verify-badge.failed { background: #dc3545; color: #fff; }
    #e2e-verify-badge.no-e2e { background: #6c757d; color: #fff; }
    #e2e-verify-badge:hover { opacity: 0.9; transform: scale(1.05); }
    #e2e-verify-details {
      position: fixed;
      bottom: 48px;
      right: 12px;
      z-index: 99998;
      background: #1e1e1e;
      color: #d4d4d4;
      border: 1px solid #444;
      border-radius: 8px;
      padding: 12px 16px;
      font-size: 11px;
      font-family: "Cascadia Code", "Fira Code", monospace;
      max-width: 500px;
      box-shadow: 0 4px 16px rgba(0,0,0,0.4);
      display: none;
      line-height: 1.6;
      word-break: break-all;
    }
    #e2e-verify-details.visible { display: block; }
    #e2e-verify-details .label { color: #569cd6; }
    #e2e-verify-details .ok { color: #4ec9b0; }
    #e2e-verify-details .bad { color: #f44747; }
    #e2e-verify-details .dim { color: #808080; }
  `);

  // === Badge UI ===
  const badge = document.createElement('div');
  badge.id = 'e2e-verify-badge';
  badge.className = 'checking';
  badge.textContent = 'E2E: checking...';
  document.body.appendChild(badge);

  const details = document.createElement('div');
  details.id = 'e2e-verify-details';
  document.body.appendChild(details);

  badge.addEventListener('click', () => details.classList.toggle('visible'));

  // === Hash a fetched resource ===
  async function hashUrl(url) {
    const resp = await fetch(url, { cache: 'reload' });
    if (!resp.ok) return null;
    const buf = await resp.arrayBuffer();
    const hash = await crypto.subtle.digest('SHA-256', buf);
    return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // === Fetch checksum from external host ===
  function fetchChecksum(identifier) {
    return new Promise((resolve, reject) => {
      GM_xmlhttpRequest({
        method: 'GET',
        url: `${CHECKSUM_HOST}/${identifier}`,
        onload(resp) {
          if (resp.status === 200) {
            try { resolve(JSON.parse(resp.responseText)); }
            catch { reject(new Error('Invalid checksum JSON')); }
          } else {
            reject(new Error(`HTTP ${resp.status}`));
          }
        },
        onerror(err) { reject(err); },
      });
    });
  }

  // === Find Gitea version / commit ===
  function getGiteaVersion() {
    // Try meta tag
    const meta = document.querySelector('meta[name="gitea-version"]');
    if (meta) return meta.content;
    // Try footer
    const footer = document.querySelector('.footer .powered');
    if (footer) {
      const match = footer.textContent.match(/(\d+\.\d+\.\d+)/);
      if (match) return 'v' + match[1];
    }
    return 'latest';
  }

  function noE2EDetails() {
    return `
      <strong>No E2E Encryption</strong><br><br>
      <span class="label">This Gitea instance does not have E2E encryption enabled.</span><br><br>
      <span class="dim">This means:</span><br>
      <span class="dim">&bull; Content is stored in plaintext on the server</span><br>
      <span class="dim">&bull; The server provider can read all issues, comments, and files</span><br>
      <span class="dim">&bull; Database backups contain readable content</span><br><br>
      <span class="dim">To enable E2E encryption, the instance admin must configure the</span><br>
      <span class="dim">[encryption] section in app.ini and deploy the WASM crypto module.</span>
    `;
  }

  // === Main verification ===
  async function verify() {
    try {
      // Find WASM path
      const appSubUrl = document.querySelector('meta[name="_suburl"]')?.content || '';
      const wasmUrl = `${window.location.origin}${appSubUrl}/assets/wasm/${WASM_FILENAME}`;
      const jsUrl = `${window.location.origin}${appSubUrl}/assets/wasm/${JS_FILENAME}`;

      // Check if WASM exists (E2E might not be enabled)
      let wasmResp;
      try {
        wasmResp = await fetch(wasmUrl, { method: 'HEAD' });
      } catch {
        badge.className = 'no-e2e';
        badge.textContent = 'No E2E';
        details.innerHTML = noE2EDetails();
        return;
      }

      if (!wasmResp.ok) {
        badge.className = 'no-e2e';
        badge.textContent = 'No E2E';
        details.innerHTML = noE2EDetails();
        return;
      }

      // Hash the served WASM and JS
      const [wasmHash, jsHash] = await Promise.all([
        hashUrl(wasmUrl),
        hashUrl(jsUrl),
      ]);

      if (!wasmHash) {
        badge.className = 'failed';
        badge.textContent = 'E2E: hash failed';
        return;
      }

      // Fetch expected checksum from external host
      const version = getGiteaVersion();
      let checksum;
      try {
        checksum = await fetchChecksum(version);
      } catch {
        // Try "latest" as fallback
        try {
          checksum = await fetchChecksum('latest');
        } catch {
          badge.className = 'failed';
          badge.textContent = 'E2E: no checksum';
          details.innerHTML = `
            <span class="label">Instance WASM SHA-256:</span><br>${wasmHash}<br><br>
            <span class="bad">Could not fetch checksum from ${CHECKSUM_HOST}</span><br>
            <span class="dim">Tried: ${version}, latest</span>
          `;
          return;
        }
      }

      // Compare
      const wasmOk = wasmHash === checksum.wasm_sha256;
      const jsOk = jsHash === checksum.js_sha256;
      const allOk = wasmOk && jsOk;

      if (allOk) {
        badge.className = 'verified';
        badge.textContent = 'E2E: verified';
      } else {
        badge.className = 'failed';
        badge.textContent = 'E2E: TAMPERED';
      }

      details.innerHTML = `
        <strong>E2E Encryption Integrity Check</strong><br><br>
        <span class="label">WASM SHA-256 (served):</span><br>
        <span class="${wasmOk ? 'ok' : 'bad'}">${wasmHash}</span><br><br>
        <span class="label">WASM SHA-256 (expected):</span><br>
        <span class="ok">${checksum.wasm_sha256}</span><br><br>
        <span class="label">JS SHA-256 (served):</span><br>
        <span class="${jsOk ? 'ok' : 'bad'}">${jsHash}</span><br><br>
        <span class="label">JS SHA-256 (expected):</span><br>
        <span class="ok">${checksum.js_sha256}</span><br><br>
        <span class="label">Status:</span>
        <span class="${allOk ? 'ok' : 'bad'}">${allOk ? 'VERIFIED — crypto code is authentic' : 'MISMATCH — crypto code may be tampered!'}</span><br><br>
        <span class="dim">Source: ${CHECKSUM_HOST}/${version}</span><br>
        <span class="dim">Built: ${checksum.built_at || 'unknown'}</span><br>
        <span class="dim">Commit: ${checksum.commit || 'unknown'}</span>
      `;
    } catch (err) {
      badge.className = 'failed';
      badge.textContent = 'E2E: error';
      details.innerHTML = `<span class="bad">Verification error: ${err.message}</span>`;
    }
  }

  verify();
})();
