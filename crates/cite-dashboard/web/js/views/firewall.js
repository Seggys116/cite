import { h, icon } from '../dom.js';
import { nodeApi, qs } from '../api.js';
import { currentNode, state } from '../state.js';
import {
  pageHeader, button, iconButton, loadInto, card, pill, dataTable, emptyState, field, toggle, chipInput,
  openDrawer, confirmDialog, toast, withBusy, formatError, newId, checkRegex, fmtInt, skeletonRows,
} from '../ui.js';
import { noNodes, nodeNotice, listOf } from './common.js';

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT'];
const CIDR_RE = /^[0-9a-fA-F:.]+(\/\d{1,3})?$/;

const ACTIONS = {
  deny: { label: 'Deny', kind: 'bad', text: 'Answer with 403 Forbidden. Clear to the client and cheap for the edge.' },
  drop: { label: 'Drop silently', kind: 'warn', text: 'Close the connection with no reply at all, so scanners learn nothing.' },
  tarpit: { label: 'Tarpit', kind: 'info', text: 'Hold the connection open and answer slowly to waste the scanner\'s time.' },
};

const PRESET_ICONS = { sensitive: 'lock', cms: 'layers', scanner: 'search', method: 'ban' };

function matcherSummary(m) {
  const out = [];
  if (m.path_prefix) out.push('prefix ' + m.path_prefix);
  if (m.path_regex) out.push('path ~ ' + m.path_regex);
  if (m.methods && m.methods.length) out.push(m.methods.join(' '));
  if (m.user_agent_regex) out.push('ua ~ ' + m.user_agent_regex);
  if (m.cidrs && m.cidrs.length) out.push(m.cidrs.length > 2 ? `${m.cidrs.slice(0, 2).join(', ')} +${m.cidrs.length - 2}` : m.cidrs.join(', '));
  if (m.host) out.push('host ' + m.host);
  return out;
}

function regexField(label, value, hint) {
  const input = h('input', { class: 'input mono', type: 'text', value: value || '', spellcheck: 'false', 'aria-label': label });
  const note = h('span', { class: 'error-text', hidden: true });
  input.addEventListener('input', () => {
    const problem = input.value ? checkRegex(input.value) : null;
    note.textContent = problem || '';
    note.hidden = !problem;
  });
  return { input, el: field(label, h('div', {}, input, note), hint), invalid: () => Boolean(input.value && checkRegex(input.value)) };
}

function openRuleEditor(node, rule, sites, onSaved) {
  const m = rule ? rule.matchers : {};
  const name = h('input', { class: 'input', type: 'text', value: rule ? rule.name : '', placeholder: 'Block WordPress probes', 'aria-label': 'Rule name' });
  let action = rule ? rule.action : 'deny';
  const actionCards = Object.entries(ACTIONS).map(([key, a]) => {
    const radio = h('input', { type: 'radio', name: 'fw-action', value: key, checked: key === action, onChange: () => { action = key; } });
    return h('label', { class: 'radio-card' }, radio, h('div', {}, h('b', {}, a.label), h('p', { class: 'muted' }, a.text)));
  });
  const prefix = h('input', { class: 'input mono', type: 'text', value: m.path_prefix || '', placeholder: '/wp-admin', spellcheck: 'false', 'aria-label': 'Path prefix' });
  const pathRe = regexField('Path regex', m.path_regex, 'Matched anywhere in the request path.');
  const uaRe = regexField('User agent regex', m.user_agent_regex, 'Matched against the User-Agent header.');
  const host = h('input', { class: 'input mono', type: 'text', value: m.host || '', placeholder: 'shop.example.com', spellcheck: 'false', 'aria-label': 'Host' });
  const picked = new Set(m.methods || []);
  const methodBoxes = METHODS.map((method) => h('label', { class: 'check-pill' },
    h('input', { type: 'checkbox', checked: picked.has(method), onChange: (e) => { if (e.target.checked) picked.add(method); else picked.delete(method); } }), method));
  const cidrs = chipInput({ values: m.cidrs || [], label: 'Client CIDR ranges', placeholder: '203.0.113.0/24, then Enter', validate: (v) => (CIDR_RE.test(v) ? null : `"${v}" is not an address or CIDR range.`) });
  const scope = h('select', { class: 'select', 'aria-label': 'Scope', value: rule && rule.site ? rule.site : '' },
    h('option', { value: '' }, 'All sites on this node'), sites.map((x) => h('option', { value: x.id }, x.name)));
  const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const save = button(rule ? 'Save rule' : 'Add rule', { kind: 'primary', iconName: 'check' });
  let drawer = null;
  const fail = (message) => {
    err.textContent = message;
    err.hidden = false;
  };

  save.addEventListener('click', async () => {
    const matchers = {
      path_regex: pathRe.input.value.trim() || null,
      path_prefix: prefix.value.trim() || null,
      methods: [...picked],
      user_agent_regex: uaRe.input.value.trim() || null,
      cidrs: cidrs.get(),
      host: host.value.trim() || null,
    };
    if (!name.value.trim()) return fail('Give the rule a name.');
    if (pathRe.invalid() || uaRe.invalid()) return fail('Fix the invalid regular expression first.');
    if (!matchers.path_regex && !matchers.path_prefix && !matchers.methods.length && !matchers.user_agent_regex && !matchers.cidrs.length && !matchers.host) {
      return fail('A rule needs at least one matcher, otherwise it would block everything.');
    }
    const body = { id: rule ? rule.id : newId('rule'), name: name.value.trim(), enabled: rule ? rule.enabled : true, action, matchers, site: scope.value || null };
    try {
      await withBusy(save, () => (rule ? nodeApi(node).put('/firewall/rules/' + encodeURIComponent(rule.id), body) : nodeApi(node).post('/firewall/rules', body)));
      toast(`Rule ${body.name} saved`, 'success');
      drawer.close();
      onSaved();
    } catch (ex) {
      fail(formatError(ex));
    }
  });

  drawer = openDrawer({
    title: rule ? 'Edit rule' : 'Add firewall rule',
    subtitle: 'Every filled matcher must match for the rule to fire.',
    wide: true,
    content: h('div', { class: 'form' },
      field('Name', name),
      h('div', { class: 'field' }, h('span', { class: 'field-label' }, 'Action'), h('div', { class: 'stack-sm' }, actionCards)),
      h('div', { class: 'two-col narrow' }, field('Path prefix', prefix), field('Host', host)),
      pathRe.el,
      field('Methods', h('div', { class: 'check-pills' }, methodBoxes), 'Leave all unticked to match any method.', { group: true }),
      uaRe.el,
      field('Client addresses', cidrs.el, 'IPv4 or IPv6 addresses and CIDR ranges.', { group: true }),
      field('Scope', scope),
      err),
    footer: [button('Cancel', { onClick: () => drawer.close() }), save],
  });
}

function presetCard(preset, node, reload) {
  const key = Object.keys(PRESET_ICONS).find((k) => preset.name.includes(k));
  const apply = button('Apply', { size: 'sm', iconName: 'plus' });
  apply.addEventListener('click', async () => {
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
    h('footer', {}, pill(`${(preset.rules || []).length} rules`, 'muted'), apply));
}

function render({ rules, presets, summary, sites }, reload, node) {
  // top_blocked keys identify the rule that fired, by id or by name
  const hits = new Map((summary.top_blocked || []).map((b) => [b.key, b.count]));
  const hitsFor = (r) => hits.get(r.id) || hits.get(r.name) || 0;
  const siteName = (id) => (sites.find((x) => x.id === id) || { name: id }).name;
  const table = dataTable({
    columns: [
      {
        label: 'On',
        render: (r) => toggle({
          checked: r.enabled,
          label: `Enable ${r.name}`,
          onChange: async (value) => {
            try {
              await nodeApi(node).put('/firewall/rules/' + encodeURIComponent(r.id), { ...r, enabled: value });
              r.enabled = value;
            } catch (ex) {
              toast(formatError(ex), 'error');
              throw ex;
            }
          },
        }),
      },
      { label: 'Rule', render: (r) => h('div', { class: 'cell-stack' }, h('b', { class: 'cell-strong' }, r.name), h('span', { class: 'mono muted' }, r.id)) },
      { label: 'Action', render: (r) => pill(ACTIONS[r.action].label, ACTIONS[r.action].kind) },
      { label: 'Matches', render: (r) => h('div', { class: 'chips' }, matcherSummary(r.matchers).map((t) => h('span', { class: 'chip chip-static mono', title: t }, t))) },
      { label: 'Scope', render: (r) => (r.site ? siteName(r.site) : h('span', { class: 'muted' }, 'All sites')) },
      { label: 'Hits (24h)', align: 'right', render: (r) => h('span', { class: 'mono' }, fmtInt(hitsFor(r))) },
      {
        label: '',
        align: 'right',
        render: (r) => h('div', { class: 'row-actions' },
          iconButton('edit', 'Edit ' + r.name, () => openRuleEditor(node, r, sites, reload)),
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
      action: button('Add rule', { kind: 'primary', iconName: 'plus', onClick: () => openRuleEditor(node, null, sites, reload) }),
    }),
  });
  return h('div', { class: 'stack' },
    card({ title: 'Rules', subtitle: 'Evaluated in order; the first match wins', flush: true, body: table }),
    h('h2', { class: 'section-title' }, 'Presets'),
    h('div', { class: 'grid-presets' }, presets.map((p) => presetCard(p, node, reload))));
}

export function firewallView(ctx) {
  ctx.setCrumbs([{ label: 'Firewall' }]);
  const node = currentNode();
  const body = h('div', {});
  let sitesCache = [];
  let reload = null;
  const add = button('Add rule', { kind: 'primary', iconName: 'plus', onClick: () => openRuleEditor(node, null, sitesCache, () => reload()) });
  const head = pageHeader({ title: 'Firewall', subtitle: node ? 'Rules enforced by ' + node : 'Block, drop or tarpit unwanted traffic', actions: state.nodes.length ? add : null });
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
      queueMicrotask(() => openRuleEditor(node, null, data.sites, again));
    }
    return render(data, again, node);
  }, { skeleton: () => skeletonRows(6) });
}
