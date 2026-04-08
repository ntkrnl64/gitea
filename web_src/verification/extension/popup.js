// Popup for Gitea E2E Verifier — Chrome (MV3)

async function loadResults() {
  const content = document.getElementById('content');
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) { content.innerHTML = '<span class="dim">No active tab</span>'; return; }
    const [{result}] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => sessionStorage.getItem('e2e_verify_result'),
    });
    if (!result) { content.innerHTML = '<span class="dim">No Gitea instance detected on this page.</span>'; return; }
    render(JSON.parse(result));
  } catch (err) {
    content.innerHTML = `<span class="bad">Error: ${esc(err.message)}</span>`;
  }
}

function renderWarnings(warnings) {
  if (!warnings || warnings.length === 0) return '<div class="row ok">No suspicious scripts detected.</div>';
  let html = '<div class="row bad">Suspicious activity detected:</div>';
  for (const w of warnings) {
    html += `<div class="info-box"><span class="bad">${esc(w.type)}:</span> ${esc(w.message)}`;
    if (w.snippet) html += `<br><span class="dim" style="font-size:9px">${esc(w.snippet.substring(0, 150))}...</span>`;
    if (w.url) html += `<br><span class="dim">${esc(w.url)}</span>`;
    html += '</div>';
  }
  return html;
}

function render(data) {
  const content = document.getElementById('content');
  const warnHtml = renderWarnings(data.scriptWarnings);
  const scriptsInfo = data.totalScriptsOnPage != null
    ? `<div class="row dim">Total scripts on page: ${data.totalScriptsOnPage}</div>` : '';

  switch (data.status) {
    case 'verified':
      content.innerHTML = `
        <div class="status-box status-verified">\u{2705} VERIFIED</div>
        <div class="row"><span class="label">Instance:</span> ${esc(data.instanceUrl)}</div>
        <hr>
        <div class="row"><span class="label">WASM SHA-256:</span></div>
        <div class="hash ok">${esc(data.wasmHash)}</div>
        <div class="row"><span class="label">JS SHA-256:</span></div>
        <div class="hash ok">${esc(data.jsHash)}</div>
        <hr>
        <strong>Script Audit</strong><br>${warnHtml}${scriptsInfo}
        <hr>
        <div class="row dim">Commit: ${esc(data.commit || '?')} | Built: ${esc(data.builtAt || '?')}</div>
      `;
      break;

    case 'tampered':
      content.innerHTML = `
        <div class="status-box status-tampered">\u{26a0}\u{fe0f} TAMPERED</div>
        <div class="row"><span class="label">Instance:</span> ${esc(data.instanceUrl)}</div>
        <hr>
        <div class="row"><span class="label">WASM (served):</span></div>
        <div class="hash ${data.wasmHash === data.expectedWasm ? 'ok' : 'bad'}">${esc(data.wasmHash)}</div>
        <div class="row"><span class="label">WASM (expected):</span></div>
        <div class="hash ok">${esc(data.expectedWasm)}</div>
        <div class="row"><span class="label">JS (served):</span></div>
        <div class="hash ${data.jsHash === data.expectedJs ? 'ok' : 'bad'}">${esc(data.jsHash)}</div>
        <div class="row"><span class="label">JS (expected):</span></div>
        <div class="hash ok">${esc(data.expectedJs)}</div>
        <hr>
        <strong>Script Audit</strong><br>${warnHtml}${scriptsInfo}
        <hr>
        <div class="info-box"><span class="bad">Do NOT enter your passphrase. The server may be stealing keys.</span></div>
      `;
      break;

    case 'suspicious':
      content.innerHTML = `
        <div class="status-box" style="background:#fd7e14;color:#fff">\u{26a0}\u{fe0f} SUSPICIOUS SCRIPTS</div>
        <div class="row"><span class="label">Instance:</span> ${esc(data.instanceUrl)}</div>
        <div class="info-box"><span class="warn">Crypto WASM/JS hashes match, but suspicious scripts were detected on the page.
        A malicious provider may have injected additional code to steal your keys without modifying the crypto module.</span></div>
        <hr>
        <div class="row"><span class="label">WASM SHA-256:</span></div>
        <div class="hash ok">${esc(data.wasmHash)}</div>
        <div class="row"><span class="label">JS SHA-256:</span></div>
        <div class="hash ok">${esc(data.jsHash)}</div>
        <hr>
        <strong>Script Audit</strong><br>${warnHtml}${scriptsInfo}
        <hr>
        <div class="info-box"><span class="bad">Proceed with caution. Inspect the flagged scripts before entering your passphrase.</span></div>
      `;
      break;

    case 'no-e2e':
      content.innerHTML = `
        <div class="status-box status-no-e2e">\u{1f513} No E2E Encryption</div>
        <div class="row"><span class="label">Instance:</span> ${esc(data.instanceUrl)}</div>
        <div class="info-box">
          <span class="warn">This Gitea instance does not have E2E encryption enabled.</span><br><br>
          <span class="dim">\u{2022} Content is stored in plaintext on the server</span><br>
          <span class="dim">\u{2022} The server provider can read all issues, comments, and files</span><br>
          <span class="dim">\u{2022} Database backups contain readable content</span>
        </div>
        ${data.scriptWarnings?.length ? '<hr><strong>Script Audit</strong><br>' + warnHtml : ''}
      `;
      break;

    case 'no-checksum':
      content.innerHTML = `
        <div class="status-box status-unknown">\u{2753} Cannot Verify</div>
        <div class="row"><span class="label">Instance:</span> ${esc(data.instanceUrl)}</div>
        <div class="info-box"><span class="warn">${esc(data.message)}</span></div>
        <div class="row"><span class="label">WASM SHA-256:</span></div>
        <div class="hash dim">${esc(data.wasmHash)}</div>
        ${data.scriptWarnings?.length ? '<hr><strong>Script Audit</strong><br>' + warnHtml : ''}
      `;
      break;

    default:
      content.innerHTML = `<div class="status-box status-unknown">${esc(data.message || data.status)}</div>`;
  }
}

function esc(s) {
  if (!s) return '';
  const d = document.createElement('div');
  d.appendChild(document.createTextNode(String(s)));
  return d.innerHTML;
}

loadResults();
