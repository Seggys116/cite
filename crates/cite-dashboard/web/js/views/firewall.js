import { h, icon } from '../dom.js';
import { nodeApi, qs } from '../api.js';
import { currentNode, state } from '../state.js';
import {
  pageHeader, button, iconButton, loadInto, card, pill, dataTable, emptyState, toggle,
  confirmDialog, toast, withBusy, formatError, fmtInt, skeletonRows,
} from '../ui.js';
import { noNodes, nodeNotice, listOf } from './common.js';
import { openRuleBuilder } from './ruleBuilder.js';
import { matcherSummary } from '../conditionlib.js';
import { effectView, presetNeedsScopeWarning, resaveBody } from '../rulelib.js';

const PRESET_ICONS = { sensitive: 'lock', cms: 'layers', scanner: 'search', method: 'ban', redirect: 'swap', https: 'lock' };

function presetCard(preset, node, reload) {
  const key = Object.keys(PRESET_ICONS).find((k) => preset.name.includes(k));
  const count = (preset.rules || []).length;
  const apply = button('Apply', { size: 'sm', iconName: 'plus' });
  apply.addEventListener('click', async () => {
    if (presetNeedsScopeWarning(preset)) {
      const ok = await confirmDialog({
        title: `Apply ${preset.title}`,
        message: 'This preset has no site set, so it acts on every site on the node. Edit the rule afterwards to limit it to one site. Apply it?',
        confirmLabel: 'Apply preset',
      });
      if (!ok) return;
    }
    try {
      const added = await withBusy(apply, () => nodeApi(node).post('/firewall/presets/' + encodeURIComponent(preset.name) + '/apply'));
      toast(`${listOf(added).length} rules added from ${preset.title}`, 'success');
      reload();
    } catch (ex) {
      toast(formatError(ex), 'error');
    }
  });
  return h('article', { class: 'preset' },
    h('div', { class: 'preset-icon' }, icon(PRESET_ICONS[key] || 'shield')),
    h('h3', {}, preset.title),
    h('p', { class: 'muted' }, preset.description),
    h('footer', {}, pill(`${count} rule${count === 1 ? '' : 's'}`, 'muted'), apply));
}

function render({ rules, presets, summary, sites }, reload, node) {
  // top_blocked keys identify the rule that fired, by id, label or name
  const hits = new Map((summary.top_blocked || []).map((b) => [b.key, b.count]));
  const hitsFor = (r) => hits.get(r.id) || (r.label && hits.get(r.label)) || hits.get(r.name) || 0;
  const siteName = (id) => (sites.find((x) => x.id === id) || { name: id }).name;
  const open = (rule) => openRuleBuilder({ node, rule, sites, onSaved: reload });
  const table = dataTable({
    columns: [
      {
        label: 'On',
        render: (r) => toggle({
          checked: r.enabled,
          label: `Enable ${r.name}`,
          // Rethrowing makes the switch snap back when the node rejects the change.
          onChange: async (value) => {
            try {
              await nodeApi(node).put('/firewall/rules/' + encodeURIComponent(r.id), resaveBody(r, { enabled: value }));
              r.enabled = value;
            } catch (ex) {
              toast(formatError(ex), 'error');
              throw ex;
            }
          },
        }),
      },
      {
        label: 'Rule',
        cls: 'nowrap',
        render: (r) => h('div', { class: 'cell-stack' }, h('b', { class: 'cell-strong' }, r.name),
          h('span', { class: 'mono muted' }, r.label ? `${r.id} (${r.label})` : r.id)),
      },
      {
        label: 'Effect',
        render: (r) => {
          const fx = effectView(r);
          return h('div', { class: 'cell-stack' }, pill(fx.label, fx.pill), fx.detail ? h('span', { class: 'mono muted wrap-any' }, fx.detail) : null);
        },
      },
      { label: 'Matches', cls: 'cell-clip', render: (r) => h('div', { class: 'chips' }, matcherSummary(r.matchers).map((t) => h('span', { class: 'chip chip-static mono', title: t }, t))) },
      { label: 'Scope', cls: 'nowrap', render: (r) => (r.site ? siteName(r.site) : h('span', { class: 'muted' }, 'All sites')) },
      { label: 'Hits (24h)', align: 'right', render: (r) => h('span', { class: 'mono' }, fmtInt(hitsFor(r))) },
      {
        label: '',
        align: 'right',
        render: (r) => h('div', { class: 'row-actions' },
          iconButton('edit', 'Edit ' + r.name, () => open(r)),
          iconButton('trash', 'Delete ' + r.name, async () => {
            const ok = await confirmDialog({ title: 'Delete rule', message: `Delete ${r.name}? Matching traffic will pass through again.`, confirmLabel: 'Delete rule', danger: true });
            if (!ok) return;
            try {
              await nodeApi(node).del('/firewall/rules/' + encodeURIComponent(r.id));
              toast('Rule deleted', 'success');
              reload();
            } catch (ex) {
              toast(formatError(ex), 'error');
            }
          })),
      },
    ],
    rows: rules,
    empty: emptyState({
      iconName: 'shield',
      title: 'No firewall rules',
      text: 'Add a rule, or start from a preset below.',
      action: button('Add rule', { kind: 'primary', iconName: 'plus', onClick: () => open(null) }),
    }),
  });
  return h('div', { class: 'stack' },
    card({
      title: 'Rules',
      subtitle: 'Blocking rules are evaluated in order and the first match wins. Redirects and header rules apply after them.',
      actions: [h('a', { class: 'btn btn-sm', href: '#/redirects' }, 'Manage redirects')],
      flush: true,
      body: table,
    }),
    h('h2', { class: 'section-title' }, 'Presets'),
    h('div', { class: 'grid-presets' }, presets.map((p) => presetCard(p, node, reload))));
}

export function firewallView(ctx) {
  ctx.setCrumbs([{ label: 'Firewall' }]);
  const node = currentNode();
  const body = h('div', {});
  let sitesCache = [];
  let reload = null;
  const add = button('Add rule', { kind: 'primary', iconName: 'plus', onClick: () => openRuleBuilder({ node, rule: null, sites: sitesCache, onSaved: () => reload() }) });
  const head = pageHeader({ title: 'Firewall', subtitle: node ? 'Rules enforced by ' + node : 'Block, redirect or rewrite requests at the edge', actions: state.nodes.length ? add : null });
  ctx.root.append(...[head, nodeNotice(node), body].filter(Boolean));
  if (!node) {
    body.appendChild(noNodes());
    return;
  }
  const n = nodeApi(node);
  let openNew = ctx.params[0] === 'new';
  reload = loadInto(body, async () => {
    const [rules, presets, summary, sites] = await Promise.all([
      n.get('/firewall/rules'), n.get('/firewall/presets'), n.get('/analytics/summary' + qs({ window: '24h' })).catch(() => ({})), n.get('/sites'),
    ]);
    sitesCache = sites;
    return { rules, presets, summary, sites };
  }, (data, again) => {
    if (openNew) {
      openNew = false;
      queueMicrotask(() => openRuleBuilder({ node, rule: null, sites: data.sites, onSaved: again }));
    }
    return render(data, again, node);
  }, { skeleton: () => skeletonRows(6) });
}
