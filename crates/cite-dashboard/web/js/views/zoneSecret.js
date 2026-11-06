import { h } from '../dom.js';
import { nodeApi } from '../api.js';
import {
  button, confirmDialog, iconButton, openModal, copyText, fmtDate,
} from '../ui.js';
import {
  SECRET_CLOSE_WARNING, ZONE_HEADER, ZONE_STEPS, secretCloseNeedsConfirm, zoneStatusLine,
} from '../accesslib.js';

// Asks the node for a new secret; the node shows it in this one answer and never again
export function rotateZoneSecret(node, siteId) {
  return nodeApi(node).post('/sites/' + encodeURIComponent(siteId) + '/zone-secret', {});
}

const entryOf = (node, data) => {
  const entry = { node, secret: String(data.secret || ''), header: data.header, created_at: data.created_at, fingerprint: data.fingerprint };
  data.secret = '';
  return entry;
};

// Rotates on every node named, then shows the secrets that came back; failures are returned so the caller can report them
export async function rotateAndShow(nodes, siteId, onDone) {
  const results = await Promise.allSettled(nodes.map((node) => rotateZoneSecret(node, siteId)));
  const entries = [];
  const failures = [];
  results.forEach((res, i) => {
    if (res.status === 'fulfilled') entries.push(entryOf(nodes[i], res.value));
    else failures.push({ node: nodes[i], error: res.reason });
  });
  if (entries.length) openZoneSecretPanel({ entries, onDone });
  else if (onDone) onDone();
  return failures;
}

export function zoneStatusText(status) {
  return zoneStatusLine(status, fmtDate);
}

// Shows each secret once. Closing the dialog empties the text and the held copies, so nothing stays in the page.
export function openZoneSecretPanel({ entries, onDone }) {
  let copied = false;
  const held = entries.map((e) => ({ ...e }));
  const slots = [];
  const rows = held.map((entry) => {
    const code = h('code', { class: 'mono wrap-any' }, entry.secret);
    slots.push(code);
    return h('div', { class: 'stack-sm' },
      entries.length > 1 ? h('b', {}, entry.node) : null,
      h('div', { class: 'secret' }, code, iconButton('copy', 'Copy secret', () => {
        copied = true;
        copyText(entry.secret, 'Secret copied');
      })),
      h('p', { class: 'hint' }, `Header ${entry.header || ZONE_HEADER}${entry.fingerprint ? `, fingerprint ${entry.fingerprint}` : ''}${entry.created_at ? `, created ${fmtDate(entry.created_at)}` : ''}`));
  });
  const wipe = () => {
    for (const code of slots) code.textContent = '';
    for (const entry of held) entry.secret = '';
    for (const entry of entries) entry.secret = '';
  };
  const done = button('I have saved it', { kind: 'primary', onClick: async () => {
    if (secretCloseNeedsConfirm(copied)) {
      const ok = await confirmDialog({ title: 'Close without copying', message: SECRET_CLOSE_WARNING, confirmLabel: 'Close anyway', danger: true });
      if (!ok) return;
    }
    modal.close();
  } });
  const modal = openModal({
    title: 'Copy your Cloudflare zone secret',
    wide: true,
    dismissable: false,
    content: h('div', { class: 'stack' },
      h('p', { class: 'notice warn', role: 'alert' }, 'This is the only time the secret is shown. Copy it now. This dialog closes only with the button below, and closing it removes the secret from the page.'),
      rows,
      h('div', { class: 'stack-sm' },
        h('b', {}, `Add it in Cloudflare as the header ${ZONE_HEADER}`),
        h('ol', { class: 'steps' }, ZONE_STEPS.map((step) => h('li', {}, step))))),
    actions: [done],
    onClose: () => {
      wipe();
      if (onDone) onDone();
    },
  });
  return modal;
}
