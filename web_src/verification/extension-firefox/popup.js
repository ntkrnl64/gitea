// Popup script for the Gitea E2E Verifier — Firefox edition.
// Uses browser.tabs.executeScript (MV2) to read sessionStorage from active tab.

async function loadResults() {
  const content = document.getElementById('content');

  try {
    const tabs = await browser.tabs.query({ active: true, currentWindow: true });
    if (!tabs[0]?.id) {
      content.innerHTML = '<span class="dim">No active tab</span>';
      return;
    }

    const results = await browser.tabs.executeScript(tabs[0].id, {
      code: 'sessionStorage.getItem("e2e_verify_result")',
    });

    const result = results[0];
    if (!result) {
      content.innerHTML = '<span class="dim">No Gitea instance detected on this page.</span>';
      return;
    }

    render(JSON.parse(result));
  } catch (err) {
    content.innerHTML = `<span class="bad">Error: ${esc(err.message)}</span>`;
  }
}

function render(data) {
  const content = document.getElementById('content');

  switch (data.status) {
    case 'verified':
      content.innerHTML = `
        <div class="status-box status-verified">\u{2705} VERIFIED — Crypto code is authentic</div>
        <div class="row"><span class="label">Instance:</span> ${esc(data.instanceUrl)}</div>
        <hr>
        <div class="row"><span class="label">WASM SHA-256 (served):</span></div>
        <div class="hash ok">${esc(data.wasmHash)}</div>
        <div class="row"><span class="label">WASM SHA-256 (expected):</span></div>
        <div class="hash ok">${esc(data.expectedWasm)}</div>
        <hr>
        <div class="row"><span class="label">JS SHA-256 (served):</span></div>
        <div class="hash ok">${esc(data.jsHash)}</div>
        <div class="row"><span class="label">JS SHA-256 (expected):</span></div>
        <div class="hash ok">${esc(data.expectedJs)}</div>
        <hr>
        <div class="row dim">Source commit: ${esc(data.commit || 'unknown')}</div>
        <div class="row dim">Built: ${esc(data.builtAt || 'unknown')}</div>
        <div class="row dim">Checksums: giteachecksums.krnl64.win/${esc(data.version)}</div>
      `;
      break;

    case 'tampered':
      content.innerHTML = `
        <div class="status-box status-tampered">\u{26a0}\u{fe0f} WARNING — Crypto code has been modified!</div>
        <div class="row"><span class="label">Instance:</span> ${esc(data.instanceUrl)}</div>
        <hr>
        <div class="row"><span class="label">WASM SHA-256 (served):</span></div>
        <div class="hash ${data.wasmHash === data.expectedWasm ? 'ok' : 'bad'}">${esc(data.wasmHash)}</div>
        <div class="row"><span class="label">WASM SHA-256 (expected):</span></div>
        <div class="hash ok">${esc(data.expectedWasm)}</div>
        <hr>
        <div class="row"><span class="label">JS SHA-256 (served):</span></div>
        <div class="hash ${data.jsHash === data.expectedJs ? 'ok' : 'bad'}">${esc(data.jsHash)}</div>
        <div class="row"><span class="label">JS SHA-256 (expected):</span></div>
        <div class="hash ok">${esc(data.expectedJs)}</div>
        <hr>
        <div class="info-box">
          <span class="bad">The server may have modified the encryption code to steal your keys.</span><br>
          <span class="bad">Do NOT enter your E2E passphrase on this instance.</span>
        </div>
      `;
      break;

    case 'no-e2e':
      content.innerHTML = `
        <div class="status-box status-no-e2e">\u{1f513} No E2E Encryption</div>
        <div class="row"><span class="label">Instance:</span> ${esc(data.instanceUrl)}</div>
        <div class="info-box">
          <span class="warn">This Gitea instance does not have E2E encryption enabled.</span><br><br>
          <span class="dim">This means:</span><br>
          <span class="dim">\u{2022} Content is stored in plaintext on the server</span><br>
          <span class="dim">\u{2022} The server provider can read all issues, comments, and files</span><br>
          <span class="dim">\u{2022} Database backups contain readable content</span><br><br>
          <span class="dim">To enable E2E encryption, the instance admin must configure the</span><br>
          <span class="dim">[encryption] section in app.ini and deploy the WASM crypto module.</span>
        </div>
      `;
      break;

    case 'no-checksum':
      content.innerHTML = `
        <div class="status-box status-unknown">\u{2753} Cannot Verify</div>
        <div class="row"><span class="label">Instance:</span> ${esc(data.instanceUrl)}</div>
        <div class="info-box">
          <span class="warn">${esc(data.message)}</span><br><br>
          <span class="dim">The WASM module exists but no matching checksum was found at</span><br>
          <span class="dim">giteachecksums.krnl64.win. This could mean:</span><br>
          <span class="dim">\u{2022} The instance runs a custom or unreleased build</span><br>
          <span class="dim">\u{2022} The checksum server is unreachable</span><br>
          <span class="dim">\u{2022} The version identifier could not be detected</span>
        </div>
        <hr>
        <div class="row"><span class="label">WASM SHA-256 (served):</span></div>
        <div class="hash dim">${esc(data.wasmHash)}</div>
        ${data.jsHash ? `<div class="row"><span class="label">JS SHA-256 (served):</span></div><div class="hash dim">${esc(data.jsHash)}</div>` : ''}
      `;
      break;

    default:
      content.innerHTML = `
        <div class="status-box status-unknown">\u{26a0}\u{fe0f} ${esc(data.message || data.status)}</div>
        <div class="row"><span class="label">Instance:</span> ${esc(data.instanceUrl || 'unknown')}</div>
      `;
  }
}

function esc(s) {
  if (!s) return '';
  const d = document.createElement('div');
  d.appendChild(document.createTextNode(s));
  return d.innerHTML;
}

loadResults();
