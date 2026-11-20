import { h, icon } from '../dom.js';
import { nodeApi, qs } from '../api.js';
import { state } from '../state.js';
import {
  pageHeader, button, iconButton, loadInto, card, pill, dot, dataTable, emptyState, toggle,
  toast, withBusy, formatError, fmtInt, skeletonRows,
} from '../ui.js';
import { noNodes, listOf } from './common.js';
import { openRuleBuilder } from './ruleBuilder.js';
import { pickTargets } from './targetDialog.js';
import { matcherSummary } from '../conditionlib.js';
import { effectView, presetNeedsScopeWarning, resaveBody } from '../rulelib.js';
import { applyToNodes, resultKind, resultMessage } from '../targetlib.js';
import {
  enabledEverywhere, mergePresets, mergeRules, mergeSites, presetBlurb, presetRulesModel, rowHits, unreachableNote,
} from '../firewalllib.js';

const PRESET_ICONS = { sensitive: 'lock', cms: 'layers', scanner: 'search', method: 'ban', redirect: 'swap', https: 'lock' };

// Names of the nodes this page reads from: all of them, or the one that is selected
export function scopeNodes() {
  return state.node === 'all' ? state.nodes.map((n) => n.name) : [state.node];
}

export function onlineNodes() {
  return state.nodes.filter((n) => n.online !== false).map((n) => n.name);
}

// The header line that always says which nodes this screen covers
export function scopeLine() {
  if (!state.nodes.length) return 'Block, redirect or rewrite requests at the edge';
  if (state.node !== 'all') return h('span', { class: 'fw-scope' }, state.node);
  return h('span', { class: 'fw-scope' }, 'All nodes',
    h('span', { class: 'fw-node-chips' }, state.nodes.map((n) => h('span', { class: 'chip chip-static' }, n.name))));
}

// Reads one path from each node; a node that fails is reported by name and never blanks the rest
export function readNodes(names, path) {
  return applyToNodes(names, (name) => nodeApi(name).get(path));
}

const valuesOf = (results) => results.filter((r) => r.ok).map((r) => ({ node: r.node, value: r.value }));

async function loadFirewall(names) {
  const [rules, presets, summary, sites] = await Promise.all([
    readNodes(names, '/firewall/rules'), readNodes(names, '/firewall/presets'),
    readNodes(names, '/analytics/summary' + qs({ window: '24h' })), readNodes(names, '/sites'),
  ]);
  const reached = rules.filter((r) => r.ok);
  if (!reached.length) throw rules[0].error;
  const down = rules.filter((r) => !r.ok).map((r) => r.node);
  const perNode = (results, key) => valuesOf(results).map((r) => ({ node: r.node, [key]: listOf(r.value) }));
  const siteLists = perNode(sites, 'sites');
  return {
    down,
    rows: mergeRules(perNode(rules, 'rules')),
    presets: mergePresets(perNode(presets, 'presets')),
    sites: mergeSites(siteLists),
    sitesByNode: Object.fromEntries(siteLists.map((s) => [s.node, s.sites])),
    summaries: Object.fromEntries(valuesOf(summary).map((s) => [s.node, s.value || {}])),
  };
}

function ruleList(model) {
  return h('ul', { class: 'fw-rule-list' }, model.map((m) => h('li', {},
    h('div', { class: 'fw-rule-head' }, h('b', {}, m.name), pill(m.action, m.pill)),
    h('div', { class: 'fw-patterns' },
      m.patterns.map((p) => h('code', { class: 'mono fw-pattern' }, p)),
      m.target ? h('code', { class: 'mono fw-pattern' }, `to ${m.target}`) : null,
      !m.patterns.length && !m.target ? h('span', { class: 'muted' }, 'Every request') : null))));
}

function presetCard(preset, reload) {
  const key = Object.keys(PRESET_ICONS).find((k) => preset.name.includes(k));
  const model = presetRulesModel(preset);
  const count = model.length;
  const apply = button('Apply', { size: 'sm', iconName: 'plus' });
  apply.addEventListener('click', async () => {
    const only = onlineNodes();
    if (!only.length) {
      toast('No node is online to apply it to', 'error');
      return;
    }
    const message = presetNeedsScopeWarning(preset) ? 'No site is set, so it acts on every site on the node.' : '';
    const picked = await pickTargets({ title: `Apply ${preset.title}`, message, verb: 'Apply', scope: state.node, only });
    if (!picked) return;
    const results = await withBusy(apply, () => applyToNodes(picked, (name) => nodeApi(name).post('/firewall/presets/' + encodeURIComponent(preset.name) + '/apply')));
    toast(resultMessage(`Applied ${preset.title}`, results, formatError), resultKind(results));
    if (results.some((r) => r.ok)) reload();
  });

  const popId = `fw-pop-${preset.name}`;
  const pop = h('div', { class: 'fw-pop', id: popId, role: 'tooltip' }, ruleList(model));
  pop.hidden = true;
  const trigger = pill(`${count} rule${count === 1 ? '' : 's'}`, 'muted');
  trigger.classList.add('fw-count');
  trigger.setAttribute('tabindex', '0');
  trigger.setAttribute('role', 'button');
  trigger.setAttribute('aria-describedby', popId);
  const show = () => { pop.hidden = false; };
  const hide = () => { pop.hidden = true; };
  trigger.addEventListener('mouseenter', show);
  trigger.addEventListener('mouseleave', hide);
  trigger.addEventListener('focus', show);
  trigger.addEventListener('blur', hide);
  trigger.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') hide();
  });

  return h('article', { class: 'preset' },
    h('div', { class: 'preset-icon' }, icon(PRESET_ICONS[key] || 'shield')),
    h('h3', {}, preset.title),
    h('p', { class: 'muted' }, presetBlurb(preset)),
    count ? h('details', { class: 'fw-what' }, h('summary', {}, 'What it blocks'), ruleList(model)) : null,
    h('footer', {}, trigger, apply),
    pop);
}

function nodeChips(row) {
  return row.nodes.map((x) => h('span', { class: 'fw-node' },
    dot(x.enabled ? 'ok' : 'idle', `${x.node}: ${x.enabled ? 'on' : 'off'}`), x.node));
}

function render(data, reload, openBuilder) {
  const { rows, presets, sites, summaries } = data;
  const showNodes = state.node === 'all';
  const siteName = (id) => (sites.find((x) => x.id === id) || { name: id }).name;
  const nodeCells = new Map();

  // Writes only the nodes that hold the rule; with several holders the person picks which ones
  function ruleSwitch(row) {
    const ruleUrl = '/firewall/rules/' + encodeURIComponent(row.id);
    const sw = toggle({
      checked: enabledEverywhere(row),
      label: `Enable ${row.rule.name}`,
      // Throwing makes the switch snap back when the dialog is cancelled or every node rejects the change.
      onChange: async (value) => {
        const verb = value ? 'Turn on' : 'Turn off';
        let picked = row.holders;
        if (row.holders.length > 1) {
          picked = await pickTargets({ title: `${verb} ${row.rule.name}`, verb, scope: state.node, only: row.holders });
          if (!picked) throw new Error('Cancelled');
        }
        const results = await applyToNodes(picked, (name) => {
          const held = row.nodes.find((x) => x.node === name);
          return nodeApi(name).put(ruleUrl, resaveBody(held.rule, { enabled: value }));
        });
        for (const r of results) {
          if (!r.ok) continue;
          const held = row.nodes.find((x) => x.node === r.node);
          held.enabled = value;
          held.rule.enabled = value;
        }
        const cell = nodeCells.get(row.key);
        if (cell) cell.replaceChildren(...nodeChips(row));
        const message = resultMessage(`Turned ${value ? 'on' : 'off'} ${row.rule.name}`, results, formatError);
        toast(message, resultKind(results));
        if (!results.some((r) => r.ok)) throw new Error(message);
        sw.setChecked(enabledEverywhere(row));
      },
    });
    return sw;
  }

  async function remove(row) {
    const picked = await pickTargets({
      title: 'Delete rule',
      message: `Delete ${row.rule.name}? Matching traffic will pass through again.`,
      verb: 'Delete rule',
      scope: state.node,
      danger: true,
      only: row.holders,
    });
    if (!picked) return;
    const results = await applyToNodes(picked, (name) => nodeApi(name).del('/firewall/rules/' + encodeURIComponent(row.id)));
    toast(resultMessage(`Deleted ${row.rule.name}`, results, formatError), resultKind(results));
    if (results.some((r) => r.ok)) reload();
  }

  const table = dataTable({
    columns: [
      { label: 'On', render: (row) => ruleSwitch(row) },
      {
        label: 'Rule',
        cls: 'nowrap',
        render: (row) => {
          const r = row.rule;
          return h('div', { class: 'cell-stack' },
            h('b', { class: 'cell-strong' }, r.name, row.differs ? [' ', h('span', { class: 'fw-differs' }, pill('differs', 'warn'))] : null),
            h('span', { class: 'mono muted' }, r.label ? `${r.id} (${r.label})` : r.id));
        },
      },
      showNodes ? {
        label: 'Nodes',
        render: (row) => {
          const cell = h('div', { class: 'fw-nodes' }, nodeChips(row));
          nodeCells.set(row.key, cell);
          return cell;
        },
      } : null,
      {
        label: 'Effect',
        render: (row) => {
          const fx = effectView(row.rule);
          return h('div', { class: 'cell-stack' }, pill(fx.label, fx.pill), fx.detail ? h('span', { class: 'mono muted wrap-any' }, fx.detail) : null);
        },
      },
      {
        label: 'Matches',
        cls: 'fw-matches-cell',
        render: (row) => {
          const items = matcherSummary(row.rule.matchers);
          return h('div', { class: 'fw-matches' }, items.length
            ? items.map((t) => h('span', { class: 'chip chip-static mono fw-chip', title: t }, t))
            : h('span', { class: 'muted' }, 'Any request'));
        },
      },
      { label: 'Scope', cls: 'nowrap', render: (row) => (row.rule.site ? siteName(row.rule.site) : h('span', { class: 'muted' }, 'All sites')) },
      { label: 'Hits (24h)', align: 'right', render: (row) => h('span', { class: 'mono' }, fmtInt(rowHits(row, summaries))) },
      {
        label: '',
        align: 'right',
        render: (row) => h('div', { class: 'row-actions' },
          iconButton('edit', 'Edit ' + row.rule.name, () => openBuilder(row.rule, row.nodes)),
          iconButton('trash', 'Delete ' + row.rule.name, () => remove(row))),
      },
    ].filter(Boolean),
    rows,
    empty: emptyState({
      iconName: 'shield',
      title: 'No firewall rules',
      text: 'Add a rule, or start from a preset below.',
      action: button('Add rule', { kind: 'primary', iconName: 'plus', onClick: () => openBuilder(null, []) }),
    }),
  });
  const note = unreachableNote(data.down);
  return h('div', { class: 'stack' },
    note ? h('p', { class: 'notice warn', role: 'status' }, note) : null,
    card({
      title: 'Rules',
      subtitle: 'First match wins. Redirects and headers apply after blocks.',
      actions: [h('a', { class: 'btn btn-sm', href: '#/redirects' }, 'Manage redirects')],
      flush: true,
      body: table,
    }),
    h('h2', { class: 'section-title' }, 'Presets'),
    h('div', { class: 'grid-presets' }, presets.map((p) => presetCard(p, reload))));
}

export function firewallView(ctx) {
  ctx.setCrumbs([{ label: 'Firewall' }]);
  const body = h('div', {});
  let sitesCache = [];
  let sitesByNode = {};
  let reload = null;
  const openBuilder = (rule, holders, onSaved = () => reload()) => openRuleBuilder({
    rule, holders, sites: sitesCache, sitesByNode, onSaved,
  });
  const add = button('Add rule', { kind: 'primary', iconName: 'plus', onClick: () => openBuilder(null, []) });
  const head = pageHeader({ title: 'Firewall', subtitle: scopeLine(), actions: state.nodes.length ? add : null });
  ctx.root.append(head, body);
  if (!state.nodes.length) {
    body.appendChild(noNodes());
    return;
  }
  const names = scopeNodes();
  let openNew = ctx.params[0] === 'new';
  reload = loadInto(body, async () => {
    const data = await loadFirewall(names);
    sitesCache = data.sites;
    sitesByNode = data.sitesByNode;
    return data;
  }, (data, again) => {
    if (openNew) {
      openNew = false;
      queueMicrotask(() => openBuilder(null, [], again));
    }
    return render(data, again, (rule, holders) => openBuilder(rule, holders, again));
  }, { skeleton: () => skeletonRows(6) });
}
