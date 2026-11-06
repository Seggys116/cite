import { h } from '../dom.js';
import { nodeApi } from '../api.js';
import {
  button, card, copyText, pill, relTime, fmtDate,
} from '../ui.js';
import {
  detectedOf, errorText, pendingChanges, pendingLabel, phaseView, pollDelay, showsBanner, slotRows, unsupported,
} from '../statuslib.js';
import { createPoller } from '../poller.js';

const TONE = { ok: 'ok', bad: 'bad', muted: 'muted' };

function slotTable(rows) {
  if (!rows.length) return h('p', { class: 'muted' }, 'The node reported no slots yet.');
  const head = ['Slot', 'Container', 'Health', 'Phase', 'Commit', 'Restarts'];
  return h('div', { class: 'table-wrap' }, h('table', { class: 'table' },
    h('thead', {}, h('tr', {}, head.map((t) => h('th', {}, t)))),
    h('tbody', {}, rows.map((r) => h('tr', {},
      h('td', {}, pill(r.slot, r.slot === 'green' ? 'green' : 'blue'), r.active ? h('span', { class: 'muted' }, ' live') : null),
      h('td', { class: 'mono' }, r.container || '-'),
      h('td', {}, pill(r.health, TONE[r.tone] || 'muted'), r.oom ? h('span', { class: 'error-text' }, ' out of memory') : null,
        r.exitCode !== null && r.exitCode !== 0 ? h('span', { class: 'muted' }, ` exit ${r.exitCode}`) : null),
      h('td', {}, r.phase || '-', r.lastBuild ? h('span', { class: 'muted' }, ` (last build ${r.lastBuild})`) : null),
      h('td', { class: 'mono' }, r.live || r.head || '-', r.failedSha ? h('span', { class: 'error-text' }, ` failed ${r.failedSha}`) : null),
      h('td', { class: 'mono' }, String(r.restarts)))))));
}

// Live view of the node's manager; it redraws only the parts whose text changed.
export function statusPanel({ node, site, onStatus, onRedeploy }) {
  const chip = h('span', { class: 'phase-chip' });
  const detail = h('span', { class: 'muted' });
  const pending = pill('Changes not built yet', 'warn');
  pending.hidden = true;
  const checked = h('span', { class: 'muted' });
  const bannerText = h('p', { class: 'banner-text mono' });
  const copy = button('Copy reason', { size: 'sm', iconName: 'copy' });
  const redeploy = onRedeploy ? button('Redeploy', { size: 'sm', iconName: 'refresh' }) : null;
  const banner = h('div', { class: 'banner bad', role: 'alert', hidden: true }, h('b', {}, 'This site needs attention'), bannerText, h('div', { class: 'pill-row' }, copy, redeploy));
  const slots = h('div', {});
  const note = h('p', { class: 'muted', hidden: true });
  const body = h('div', { class: 'stack-sm' },
    h('div', { class: 'pill-row' }, chip, detail, pending, checked), banner, slots, note);
  const el = card({
    title: 'Status',
    subtitle: 'What the node is doing with this site right now.',
    actions: button('Refresh', { size: 'sm', iconName: 'refresh', onClick: () => poller.now() }),
    body,
  });
  let last = '';
  let latest = null;

  copy.addEventListener('click', () => copyText(bannerText.textContent, 'Reason copied'));
  if (redeploy) redeploy.addEventListener('click', () => onRedeploy(latest));

  function render(status) {
    latest = status;
    const view = phaseView(status);
    chip.className = `phase-chip phase-${view.kind}${view.busy ? ' busy' : ''}`;
    chip.textContent = view.label;
    detail.textContent = view.detail;
    pending.hidden = !pendingChanges(status);
    pending.title = pendingLabel(status);
    checked.textContent = status.checked_at ? `Checked ${relTime(status.checked_at)}` : '';
    checked.title = status.checked_at ? fmtDate(status.checked_at) : '';
    const reason = showsBanner(status) ? errorText(status) : '';
    banner.hidden = !reason;
    bannerText.textContent = reason;
    const key = JSON.stringify(slotRows(status));
    if (key !== last) {
      last = key;
      slots.replaceChildren(slotTable(slotRows(status)));
    }
  }

  async function load() {
    try {
      const status = await nodeApi(node).get(`/sites/${encodeURIComponent(site.id)}/status`);
      note.hidden = true;
      render(status);
      if (onStatus) onStatus(status, detectedOf(status));
      return status;
    } catch (ex) {
      if (unsupported(ex)) {
        note.textContent = 'This node does not report status. Update the connector to see it.';
        note.hidden = false;
        poller.stop();
      } else {
        note.textContent = `Status is not available right now: ${ex && ex.message ? ex.message : 'the node did not answer'}`;
        note.hidden = false;
      }
      return undefined;
    }
  }

  const poller = createPoller({ load, delay: (s) => (s ? pollDelay(s) : 10000), alive: () => el.isConnected });
  // The element is not in the page yet; the first load waits for the next frame so isConnected is true
  requestAnimationFrame(() => poller.start());
  return { el, refresh: () => poller.now(), stop: () => poller.stop(), latest: () => latest };
}
