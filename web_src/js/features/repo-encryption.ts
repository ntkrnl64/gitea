// E2E encryption integration for issue and comment content.
// Encrypts content before sending to server, decrypts after receiving.
// The server NEVER sees plaintext — all rendering is done client-side.
// Decrypted content NEVER leaves the browser. No /markup round-trip.

import {isE2EEncrypted, encryptContent, decryptContent} from '../modules/encryption.ts';
import {getRepoKey, hasUnlockedKeys, unlockUserKeys, hasUserKeyPair, setupUserKeyPair} from '../modules/encryption-keys.ts';
import {renderMarkdownSafe} from '../modules/encryption-render.ts';
import {showInfoToast, showErrorToast} from '../modules/toast.ts';

let currentRepoKey: Uint8Array | null = null;
let e2eInitialized = false;

function getRepoInfo(): {repoId: number, repoLink: string} | null {
  const el = document.querySelector('#issue-page-info');
  if (!el) return null;
  return {
    repoId: parseInt(el.getAttribute('data-issue-repo-id') || '0'),
    repoLink: el.getAttribute('data-issue-repo-link') || '',
  };
}

async function promptPassphrase(): Promise<string | null> {
  return new Promise((resolve) => {
    const overlay = document.createElement('div');
    overlay.className = 'ui dimmer modals page visible active';
    const modal = document.createElement('div');
    modal.className = 'ui small modal visible active';
    modal.style.marginTop = '-100px';

    const header = document.createElement('div');
    header.className = 'header';
    header.textContent = 'E2E Encryption Passphrase';

    const content = document.createElement('div');
    content.className = 'content';
    const form = document.createElement('div');
    form.className = 'ui form';
    const field = document.createElement('div');
    field.className = 'field';
    const label = document.createElement('label');
    label.textContent = 'Enter your E2E encryption passphrase to decrypt content:';
    const input = document.createElement('input');
    input.type = 'password';
    input.autocomplete = 'off';
    input.placeholder = 'Passphrase';
    field.append(label, input);
    form.append(field);
    content.append(form);

    const actions = document.createElement('div');
    actions.className = 'actions';
    const cancelBtn = document.createElement('button');
    cancelBtn.className = 'ui cancel button';
    cancelBtn.textContent = 'Cancel';
    const unlockBtn = document.createElement('button');
    unlockBtn.className = 'ui primary button';
    unlockBtn.textContent = 'Unlock';
    actions.append(cancelBtn, unlockBtn);

    modal.append(header, content, actions);
    overlay.append(modal);
    document.body.append(overlay);
    input.focus();

    const cleanup = () => overlay.remove();
    cancelBtn.addEventListener('click', () => { cleanup(); resolve(null) });
    unlockBtn.addEventListener('click', () => { cleanup(); resolve(input.value) });
    input.addEventListener('keydown', (e: KeyboardEvent) => {
      if (e.key === 'Enter') { cleanup(); resolve(input.value) }
      if (e.key === 'Escape') { cleanup(); resolve(null) }
    });
  });
}

async function promptSetupE2E(): Promise<string | null> {
  return new Promise((resolve) => {
    const overlay = document.createElement('div');
    overlay.className = 'ui dimmer modals page visible active';
    const modal = document.createElement('div');
    modal.className = 'ui small modal visible active';
    modal.style.marginTop = '-100px';

    const header = document.createElement('div');
    header.className = 'header';
    header.textContent = 'Set Up E2E Encryption';

    const content = document.createElement('div');
    content.className = 'content';
    const form = document.createElement('div');
    form.className = 'ui form';

    const desc = document.createElement('p');
    desc.textContent = 'This repository uses end-to-end encryption. Choose a strong passphrase to protect your private key. The server never sees it.';

    const field1 = document.createElement('div');
    field1.className = 'field';
    const label1 = document.createElement('label');
    label1.textContent = 'Passphrase:';
    const passInput = document.createElement('input');
    passInput.type = 'password';
    passInput.autocomplete = 'off';
    passInput.placeholder = 'Strong passphrase';
    field1.append(label1, passInput);

    const field2 = document.createElement('div');
    field2.className = 'field';
    const label2 = document.createElement('label');
    label2.textContent = 'Confirm:';
    const confirmInput = document.createElement('input');
    confirmInput.type = 'password';
    confirmInput.autocomplete = 'off';
    confirmInput.placeholder = 'Confirm passphrase';
    field2.append(label2, confirmInput);

    form.append(desc, field1, field2);
    content.append(form);

    const actions = document.createElement('div');
    actions.className = 'actions';
    const cancelBtn = document.createElement('button');
    cancelBtn.className = 'ui cancel button';
    cancelBtn.textContent = 'Cancel';
    const createBtn = document.createElement('button');
    createBtn.className = 'ui primary button';
    createBtn.textContent = 'Create Key Pair';
    actions.append(cancelBtn, createBtn);

    modal.append(header, content, actions);
    overlay.append(modal);
    document.body.append(overlay);
    passInput.focus();

    const cleanup = () => overlay.remove();
    cancelBtn.addEventListener('click', () => { cleanup(); resolve(null) });
    createBtn.addEventListener('click', () => {
      if (passInput.value !== confirmInput.value) { showErrorToast('Passphrases do not match'); return }
      if (passInput.value.length < 8) { showErrorToast('Passphrase must be at least 8 characters'); return }
      cleanup();
      resolve(passInput.value);
    });
  });
}

async function initE2E(): Promise<void> {
  if (e2eInitialized) return;
  e2eInitialized = true;

  const repoInfo = getRepoInfo();
  if (!repoInfo || !repoInfo.repoLink) return;

  let hasEncrypted = false;
  for (const el of document.querySelectorAll('.raw-content')) {
    if (el.textContent?.startsWith('e2e:v1:')) { hasEncrypted = true; break }
  }
  if (!hasEncrypted) return;

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
      if (!ok) { showErrorToast('Wrong passphrase'); return }
    }
  }

  const repoLink = repoInfo.repoLink.replace(/^\//, '');
  currentRepoKey = await getRepoKey(repoInfo.repoId, repoLink);
  if (!currentRepoKey) return;

  await decryptVisibleContent();
}

async function decryptVisibleContent(): Promise<void> {
  if (!currentRepoKey) return;

  for (const div of document.querySelectorAll('.raw-content')) {
    const text = div.textContent || '';
    if (!isE2EEncrypted(text)) continue;

    try {
      const decrypted = await decryptContent(text, currentRepoKey);
      div.textContent = decrypted;

      const renderDiv = div.previousElementSibling;
      if (renderDiv?.classList.contains('render-content')) {
        renderDiv.innerHTML = renderMarkdownSafe(decrypted);
        renderDiv.classList.add('e2e-decrypted');
      }
    } catch {
      // Can't decrypt — wrong key or corrupted
    }
  }

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

export function initRepoEncryption(): void {
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
        form.dispatchEvent(new Event('submit', {bubbles: true, cancelable: true}));
      } catch (err) {
        showErrorToast(`Encryption failed: ${err}`);
        contentField.value = plaintext;
      }
    }
  }, {capture: true});

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

  initE2E();
}
