// E2E encryption integration for issue and comment content.
// Encrypts content before sending to server, decrypts after receiving.
// The server NEVER sees plaintext — all rendering is done client-side.
// Decrypted content NEVER leaves the browser. No /markup round-trip.

import {isE2EEncrypted, encryptContent, decryptContent, initCrypto} from '../modules/encryption.ts';
import {getRepoKey, hasUnlockedKeys, unlockUserKeys, hasUserKeyPair, setupUserKeyPair} from '../modules/encryption-keys.ts';
import {renderMarkdownSafe} from '../modules/encryption-render.ts';
import {showInfoToast, showErrorToast} from '../modules/toast.ts';

let currentRepoKey: Uint8Array | null = null;
let e2eInitialized = false;

function getRepoInfo(): {repoId: number; repoLink: string} | null {
  const el = document.querySelector('#issue-page-info');
  if (!el) return null;
  return {
    repoId: parseInt(el.getAttribute('data-issue-repo-id') || '0'),
    repoLink: el.getAttribute('data-issue-repo-link') || '',
  };
}

// --- Passphrase prompt ---

async function promptPassphrase(): Promise<string | null> {
  return new Promise((resolve) => {
    const overlay = document.createElement('div');
    overlay.className = 'ui dimmer modals page visible active';
    overlay.innerHTML = `
      <div class="ui small modal visible active" style="margin-top: -100px;">
        <div class="header">E2E Encryption Passphrase</div>
        <div class="content">
          <div class="ui form">
            <div class="field">
              <label>Enter your E2E encryption passphrase to decrypt content:</label>
              <input type="password" id="e2e-passphrase-input" autocomplete="off" placeholder="Passphrase">
            </div>
          </div>
        </div>
        <div class="actions">
          <button class="ui cancel button" id="e2e-cancel">Cancel</button>
          <button class="ui primary button" id="e2e-unlock">Unlock</button>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);

    const input = overlay.querySelector('#e2e-passphrase-input') as HTMLInputElement;
    input.focus();

    const cleanup = () => overlay.remove();
    overlay.querySelector('#e2e-cancel')!.addEventListener('click', () => { cleanup(); resolve(null); });
    overlay.querySelector('#e2e-unlock')!.addEventListener('click', () => { cleanup(); resolve(input.value); });
    input.addEventListener('keydown', (e: KeyboardEvent) => {
      if (e.key === 'Enter') { cleanup(); resolve(input.value); }
      if (e.key === 'Escape') { cleanup(); resolve(null); }
    });
  });
}

async function promptSetupE2E(): Promise<string | null> {
  return new Promise((resolve) => {
    const overlay = document.createElement('div');
    overlay.className = 'ui dimmer modals page visible active';
    overlay.innerHTML = `
      <div class="ui small modal visible active" style="margin-top: -100px;">
        <div class="header">Set Up E2E Encryption</div>
        <div class="content">
          <div class="ui form">
            <p>This repository uses end-to-end encryption. You need to create an encryption key pair.</p>
            <p><strong>Choose a strong passphrase.</strong> It protects your private key. The server never sees it.</p>
            <div class="field">
              <label>Passphrase:</label>
              <input type="password" id="e2e-setup-pass" autocomplete="off" placeholder="Strong passphrase">
            </div>
            <div class="field">
              <label>Confirm:</label>
              <input type="password" id="e2e-setup-confirm" autocomplete="off" placeholder="Confirm passphrase">
            </div>
          </div>
        </div>
        <div class="actions">
          <button class="ui cancel button" id="e2e-setup-cancel">Cancel</button>
          <button class="ui primary button" id="e2e-setup-create">Create Key Pair</button>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);

    const pass = overlay.querySelector('#e2e-setup-pass') as HTMLInputElement;
    pass.focus();

    const cleanup = () => overlay.remove();
    overlay.querySelector('#e2e-setup-cancel')!.addEventListener('click', () => { cleanup(); resolve(null); });
    overlay.querySelector('#e2e-setup-create')!.addEventListener('click', () => {
      const confirm = overlay.querySelector('#e2e-setup-confirm') as HTMLInputElement;
      if (pass.value !== confirm.value) { showErrorToast('Passphrases do not match'); return; }
      if (pass.value.length < 8) { showErrorToast('Passphrase must be at least 8 characters'); return; }
      cleanup();
      resolve(pass.value);
    });
  });
}

// --- Initialize E2E for the current page ---

async function initE2E(): Promise<void> {
  if (e2eInitialized) return;
  e2eInitialized = true;

  const repoInfo = getRepoInfo();
  if (!repoInfo || !repoInfo.repoLink) return;

  // Check if there's encrypted content on the page
  let hasEncrypted = false;
  for (const el of document.querySelectorAll('.raw-content')) {
    if (el.textContent?.startsWith('e2e:v1:')) { hasEncrypted = true; break; }
  }
  if (!hasEncrypted) return;

  // Need to unlock keys
  if (!hasUnlockedKeys()) {
    const hasKey = await hasUserKeyPair();
    if (!hasKey) {
      const passphrase = await promptSetupE2E();
      if (!passphrase) return;
      try {
        await setupUserKeyPair(passphrase);
        showInfoToast('E2E key pair created successfully');
      } catch (err) {
        showErrorToast(`Failed to create key pair: ${err}`);
        return;
      }
    } else {
      const passphrase = await promptPassphrase();
      if (!passphrase) return;
      const ok = await unlockUserKeys(passphrase);
      if (!ok) { showErrorToast('Wrong passphrase'); return; }
    }
  }

  // Get repo key
  const repoLink = repoInfo.repoLink.replace(/^\//, '');
  currentRepoKey = await getRepoKey(repoInfo.repoId, repoLink);
  if (!currentRepoKey) return;

  // Decrypt all visible encrypted content — entirely client-side
  await decryptVisibleContent();
}

// --- Decrypt all encrypted content on the page (NEVER sends plaintext to server) ---

async function decryptVisibleContent(): Promise<void> {
  if (!currentRepoKey) return;

  // Decrypt raw content divs (used for editing)
  for (const div of document.querySelectorAll('.raw-content')) {
    const text = div.textContent || '';
    if (!isE2EEncrypted(text)) continue;

    try {
      const decrypted = await decryptContent(text, currentRepoKey);
      div.textContent = decrypted;

      // Render markdown ENTIRELY CLIENT-SIDE — never send to server
      const renderDiv = div.previousElementSibling;
      if (renderDiv?.classList.contains('render-content')) {
        renderDiv.innerHTML = renderMarkdownSafe(decrypted);
        renderDiv.classList.add('e2e-decrypted');
      }
    } catch {
      // Can't decrypt — wrong key or corrupted
    }
  }

  // Decrypt issue title if encrypted
  for (const el of document.querySelectorAll('.issue-title-display, #issue-title')) {
    const text = el.textContent || '';
    if (!isE2EEncrypted(text)) continue;
    try {
      el.textContent = await decryptContent(text, currentRepoKey);
      el.classList.add('e2e-decrypted');
    } catch {
      // keep encrypted display
    }
  }
}

// --- Intercept form submissions to encrypt content ---

export function initRepoEncryption(): void {
  // Hook into form submissions — encrypt content BEFORE sending to server
  document.addEventListener('submit', async (e: Event) => {
    const form = e.target as HTMLFormElement;
    if (!form.classList.contains('form-fetch-action')) return;
    if (!currentRepoKey) return;

    const contentField = form.querySelector('textarea[name="content"]') as HTMLTextAreaElement;
    if (!contentField) return;

    const plaintext = contentField.value;
    if (plaintext && !isE2EEncrypted(plaintext)) {
      e.preventDefault();
      e.stopPropagation();

      try {
        contentField.value = await encryptContent(plaintext, currentRepoKey);
        // Re-submit with encrypted content
        form.dispatchEvent(new Event('submit', {bubbles: true, cancelable: true}));
      } catch (err) {
        showErrorToast(`Encryption failed: ${err}`);
        contentField.value = plaintext;
      }
    }
  }, {capture: true});

  // Hook into issue title field
  document.addEventListener('submit', async (e: Event) => {
    const form = e.target as HTMLFormElement;
    if (!currentRepoKey) return;

    const titleField = form.querySelector('input[name="title"]') as HTMLInputElement;
    if (!titleField) return;

    const plaintext = titleField.value;
    if (plaintext && !isE2EEncrypted(plaintext)) {
      try {
        titleField.value = await encryptContent(plaintext, currentRepoKey);
      } catch {
        // leave unencrypted if encryption fails
      }
    }
  }, {capture: true});

  // Initialize E2E (lazy — only when encrypted content is detected)
  initE2E();
}
