// Minimal client-side markdown renderer for E2E encrypted content.
// Renders markdown entirely in the browser — decrypted content
// NEVER leaves the client. No server round-trip for rendering.
//
// HTML literals here are intentional — all user input is pre-escaped via escapeHtml().
/* eslint-disable github/unescaped-html-literal */

function escapeHtml(text: string): string {
  const div = document.createElement('div');
  div.append(document.createTextNode(text));
  return div.innerHTML;
}

export function renderMarkdownSafe(markdown: string): string {
  const lines = markdown.split('\n');
  const html: string[] = [];
  let inCodeBlock = false;
  let inList = false;
  const codeContent: string[] = [];

  for (const line of lines) {
    if (line.startsWith('```')) {
      if (inCodeBlock) {
        html.push(`<pre><code>${escapeHtml(codeContent.join('\n'))}</code></pre>`);
        codeContent.length = 0;
        inCodeBlock = false;
      } else {
        if (inList) { html.push('</ul>'); inList = false }
        inCodeBlock = true;
      }
      continue;
    }
    if (inCodeBlock) {
      codeContent.push(line);
      continue;
    }

    if (line.trim() === '') {
      if (inList) { html.push('</ul>'); inList = false }
      html.push('');
      continue;
    }

    const headerMatch = /^(#{1,6})\s+(.+)/.exec(line);
    if (headerMatch) {
      if (inList) { html.push('</ul>'); inList = false }
      const level = headerMatch[1].length;
      html.push(`<h${level}>${renderInline(headerMatch[2])}</h${level}>`);
      continue;
    }

    if (/^[-*_]{3,}\s*$/.test(line)) {
      if (inList) { html.push('</ul>'); inList = false }
      html.push('<hr>');
      continue;
    }

    if (line.startsWith('> ')) {
      if (inList) { html.push('</ul>'); inList = false }
      html.push(`<blockquote><p>${renderInline(line.slice(2))}</p></blockquote>`);
      continue;
    }

    const ulMatch = /^\s*[-*+]\s+(.+)/.exec(line);
    if (ulMatch) {
      if (!inList) { html.push('<ul>'); inList = true }
      const cbMatch = /^\[([ xX])\]\s*(.*)/.exec(ulMatch[1]);
      if (cbMatch) {
        const checked = cbMatch[1] !== ' ' ? ' checked disabled' : ' disabled';
        html.push(`<li><input type="checkbox"${checked}> ${renderInline(cbMatch[2])}</li>`);
      } else {
        html.push(`<li>${renderInline(ulMatch[1])}</li>`);
      }
      continue;
    }

    const olMatch = /^\d+\.\s+(.+)/.exec(line);
    if (olMatch) {
      if (!inList) { html.push('<ul>'); inList = true }
      html.push(`<li>${renderInline(olMatch[1])}</li>`);
      continue;
    }

    if (inList) { html.push('</ul>'); inList = false }
    html.push(`<p>${renderInline(line)}</p>`);
  }

  if (inCodeBlock) {
    html.push(`<pre><code>${escapeHtml(codeContent.join('\n'))}</code></pre>`);
  }
  if (inList) html.push('</ul>');

  return html.join('\n');
}

function renderInline(text: string): string {
  let result = escapeHtml(text);

  result = result.replace(/`([^`]+)`/g, '<code>$1</code>');
  result = result.replace(/\*\*\*(.+?)\*\*\*/g, '<strong><em>$1</em></strong>');
  result = result.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  result = result.replace(/__(.+?)__/g, '<strong>$1</strong>');
  result = result.replace(/\*(.+?)\*/g, '<em>$1</em>');
  result = result.replace(/_(.+?)_/g, '<em>$1</em>');
  result = result.replace(/~~(.+?)~~/g, '<del>$1</del>');
  result = result.replace(/\[([^\]]+)\]\((https?:\/\/[^)]+)\)/g,
    '<a href="$2" rel="nofollow noopener noreferrer" target="_blank">$1</a>');

  return result;
}
