import { h } from '../dom.js';
import { nodeApi } from '../api.js';
import {
  button, card, confirmDialog, segmented, toast, toggle, withBusy, formatError,
} from '../ui.js';
import {
  BOT_POLICIES, BOT_SPOOF_NOTE, CLOUDFLARE_ONLY_HELP, FLEXIBLE_WARNING, ZONE_LOCK_HELP, ZONE_LOCK_NEEDS_CLOUDFLARE,
  accessOf, botWarning, flexibleWithoutCloudflare, rangesLine, tlsHelp,
} from '../accesslib.js';
import { rotateAndShow, zoneStatusText } from './zoneSecret.js';

// Who may reach the site and how Cloudflare speaks to the node; shared by the create form and the routing tab.
// On a saved site (site given) it also reports the zone secret and offers to rotate it.
export function accessCard({ node, site }) {
  const value = accessOf(site);
  const only = toggle({
    checked: value.cloudflare_only,
    label: 'Only accept traffic from Cloudflare',
    onChange: (next) => {
      value.cloudflare_only = next;
      if (!next) {
        value.zone_lock = false;
        lockBox.checked = false;
      }
      sync();
    },
  });
  const help = h('span', { class: 'hint', role: 'status', 'aria-live': 'polite' });
  const warn = h('p', { class: 'notice warn', role: 'status', 'aria-live': 'polite', hidden: true }, FLEXIBLE_WARNING);
  const mode = segmented({
    label: 'SSL mode',
    value: value.tls,
    options: [{ value: 'full', label: 'Full' }, { value: 'flexible', label: 'Flexible' }],
    onChange: (next) => {
      value.tls = next;
      sync();
    },
  });
  const ranges = h('p', { class: 'hint', role: 'status', 'aria-live': 'polite', hidden: true });

  const bots = h('select', { class: 'select', 'aria-label': 'Bot policy', value: value.bots },
    BOT_POLICIES.map((p) => h('option', { value: p.value }, p.label)));
  const seo = h('p', { class: 'notice warn', role: 'status', 'aria-live': 'polite', hidden: true });
  bots.addEventListener('change', () => {
    value.bots = bots.value;
    sync();
  });

  const lockBox = h('input', { type: 'checkbox', checked: value.zone_lock, 'aria-label': 'Only my Cloudflare zone' });
  const lockHint = h('span', { class: 'hint', role: 'status', 'aria-live': 'polite' });
  lockBox.addEventListener('change', () => {
    value.zone_lock = lockBox.checked;
    sync();
  });

  function sync() {
    help.textContent = tlsHelp(value.tls);
    warn.hidden = !flexibleWithoutCloudflare(value);
    seo.textContent = botWarning(value.bots);
    seo.hidden = !seo.textContent;
    lockBox.disabled = !value.cloudflare_only;
    lockHint.textContent = value.cloudflare_only ? ZONE_LOCK_HELP : ZONE_LOCK_NEEDS_CLOUDFLARE;
  }

  // An older connector has no range route, so the line is simply left out
  if (node) {
    nodeApi(node).get('/cloudflare/ranges').then((info) => {
      const text = rangesLine(info);
      if (!text) return;
      ranges.textContent = text + ' ';
      ranges.append(h('a', { class: 'link', href: '#/settings/cloudflare' }, 'Change in Settings'));
      ranges.hidden = false;
    }).catch(() => {});
  }

  // Only a saved site with the lock on has a secret to report or rotate
  const secretLine = h('p', { class: 'muted', role: 'status', 'aria-live': 'polite' });
  const rotate = button('Rotate secret', { iconName: 'refresh' });
  const secretRow = h('div', { class: 'stack-sm', hidden: true }, h('b', {}, 'Zone secret'), secretLine, h('div', {}, rotate));
  const refreshSecret = () => {
    secretLine.textContent = '';
    nodeApi(node).get('/sites/' + encodeURIComponent(site.id) + '/zone-secret').then((status) => {
      secretLine.textContent = zoneStatusText(status);
    }).catch((ex) => {
      secretLine.textContent = formatError(ex);
    });
  };
  if (site && site.id && node && accessOf(site).zone_lock) {
    secretRow.hidden = false;
    refreshSecret();
  }
  rotate.addEventListener('click', async () => {
    const ok = await confirmDialog({
      title: 'Rotate zone secret',
      message: 'The current secret stops working at once. Requests through Cloudflare are refused until you set the new secret in your Transform Rule. Rotate it?',
      confirmLabel: 'Rotate secret',
      danger: true,
    });
    if (!ok) return;
    try {
      const failures = await withBusy(rotate, () => rotateAndShow([node], site.id, refreshSecret));
      if (failures.length) toast(formatError(failures[0].error), 'error');
    } catch (ex) {
      toast(formatError(ex), 'error');
    }
  });

  sync();
  const el = card({
    title: 'Access',
    subtitle: 'Limit who can reach this site and choose how Cloudflare connects to the node.',
    body: h('div', { class: 'form' },
      h('div', { class: 'switch-row' }, only,
        h('div', {}, h('b', {}, 'Only accept traffic from Cloudflare'), h('p', { class: 'muted' }, CLOUDFLARE_ONLY_HELP), ranges)),
      h('div', { class: 'field' }, h('span', { class: 'field-label' }, 'SSL mode'), mode, help),
      warn,
      h('div', { class: 'field' },
        h('label', { class: 'check-row' }, lockBox, h('span', {}, 'Only my Cloudflare zone')),
        lockHint),
      secretRow,
      h('div', { class: 'field' }, h('span', { class: 'field-label' }, 'Bot policy'), bots, h('span', { class: 'hint' }, BOT_SPOOF_NOTE), seo)),
  });
  return { el, get: () => ({ ...value }) };
}
