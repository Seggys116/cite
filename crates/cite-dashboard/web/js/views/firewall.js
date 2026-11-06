import { h, icon } from '../dom.js';
import { nodeApi, qs } from '../api.js';
import { currentNode, state } from '../state.js';
import {
  pageHeader, button, iconButton, loadInto, card, pill, dataTable, emptyState, field, toggle, chipInput, segmented,
  openDrawer, confirmDialog, toast, withBusy, formatError, newId, checkRegex, fmtInt, skeletonRows,
} from '../ui.js';
import { noNodes, nodeNotice, listOf } from './common.js';
import {
  KEEP_SECRET_NOTE, KINDS, PLACEHOLDERS, REDIRECT_STATUSES, buildRule, corsFromForm, corsProblem, effectView, emptyForm, matcherSummary,
  parseTemplate, presetNeedsScopeWarning, resaveBody, ruleToForm,
} from '../rulelib.js';

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT'];
// Loose shape check for fast feedback; the node validates the ranges itself.
const CIDR_RE =/^[0-9a-fA-F:.]+(\/\d{1,3})?$/;

const ACTIONS = {
  deny: { label: 'Deny', kind: 'bad', text: 'Answer with 403 Forbidden. Clear to the client and cheap for the edge.' },
  drop: { label: 'Drop silently', kind: 'warn', text: 'Close the connection with no reply at all, so scanners learn nothing.' },
  tarpit: { label: 'Tarpit', kind: 'info', text: 'Hold the connection open and answer slowly to waste the scanner\'s time.' },
};

const PRESET_ICONS = { sensitive: 'lock', cms: 'layers', scanner: 'search', method: 'ban', redirect: 'swap', https: 'lock' };

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

function option(value, label) {
  return h('option', { value }, label);
}

// The redirect target with buttons that insert the placeholders, and a live check of the template
function redirectPane(initial) {
  const to = h('input', { class: 'input mono', type: 'text', value: initial.to, placeholder: '{scheme}://{www_host}{path}{query}', spellcheck: 'false', autocomplete: 'off', 'aria-label': 'Redirect target' });
  const status = h('select', { class: 'select', 'aria-label': 'Redirect status', value: String(initial.status) },
    REDIRECT_STATUSES.map((code) => option(String(code), `${code} ${code === 301 || code === 308 ? 'permanent' : 'temporary'}`)));
  const note = h('span', { class: 'error-text', role: 'status', 'aria-live': 'polite', hidden: true });
  const check = () => {
    const parsed = to.value ? parseTemplate(to.value) : {};
    note.textContent = parsed.error ? `The target ${parsed.error}.` : '';
    note.hidden = !parsed.error;
  };
  to.addEventListener('input', check);
  const chips = PLACEHOLDERS.map((token) => h('button', {
    class: 'chip mono', type: 'button', title: `Insert ${token}`, 'aria-label': `Insert ${token}`,
    onClick: () => {
      const at = to.selectionStart ?? to.value.length;
      const end = to.selectionEnd ?? at;
      to.value = to.value.slice(0, at) + token + to.value.slice(end);
      to.focus();
      to.setSelectionRange(at + token.length, at + token.length);
      check();
    },
  }, token));
  check();
  return {
    el: h('div', { class: 'form' },
      field('Redirect to', h('div', { class: 'stack-sm' }, to, h('div', { class: 'chips' }, chips), note),
        'An absolute http or https address, or a path starting with /. Click a placeholder to insert it.', { group: true }),
      field('Status', status, 'Use 301 or 308 for a move that stays, 302 or 307 for a temporary one.')),
    read: () => ({ to: to.value, status: Number(status.value) }),
  };
}

// One row per header change; a removal takes no value
function headerOpsPane(initial) {
  const rows = initial.map((op) => ({ ...op }));
  const list = h('div', { class: 'stack-sm' });
  const draw = () => {
    list.replaceChildren();
    rows.forEach((row, i) => {
      const target = h('select', { class: 'select', 'aria-label': `Change ${i + 1} applies to`, value: row.target }, option('response', 'Response'), option('request', 'Request'));
      const op = h('select', { class: 'select', 'aria-label': `Change ${i + 1} operation`, value: row.op }, option('set', 'Set'), option('add', 'Add'), option('remove', 'Remove'));
      const name = h('input', { class: 'input mono', type: 'text', value: row.name, placeholder: 'X-Frame-Options', spellcheck: 'false', autocomplete: 'off', 'aria-label': `Change ${i + 1} header name` });
      const value = h('input', { class: 'input mono', type: 'text', value: row.value, placeholder: 'DENY', spellcheck: 'false', autocomplete: 'off', disabled: row.op === 'remove', 'aria-label': `Change ${i + 1} header value` });
      target.addEventListener('change', () => { row.target = target.value; });
      op.addEventListener('change', () => {
        row.op = op.value;
        value.disabled = op.value === 'remove';
      });
      name.addEventListener('input', () => { row.name = name.value; });
      value.addEventListener('input', () => { row.value = value.value; });
      list.append(h('div', { class: 'header-row' }, target, op, name, value, iconButton('x', `Remove change ${i + 1}`, () => {
        rows.splice(i, 1);
        draw();
      })));
    });
  };
  draw();
  const add = button('Add header change', { size: 'sm', iconName: 'plus', onClick: () => { rows.push({ target: 'response', op: 'set', name: '', value: '' }); draw(); } });
  return { el: h('div', { class: 'stack-sm' }, list, add), read: () => rows.map((r) => ({ ...r })) };
}

// CORS fields with the node's rules checked as you type, so a wildcard with credentials is caught before saving
function corsPane(initial) {
  const on = h('input', { type: 'checkbox', checked: initial.enabled, 'aria-label': 'Handle CORS for matching requests' });
  const text = (label, value, placeholder) => h('input', { class: 'input mono', type: 'text', value, placeholder, spellcheck: 'false', autocomplete: 'off', 'aria-label': label });
  const origins = h('textarea', { class: 'textarea mono', rows: '3', placeholder: 'https://app.example.com', spellcheck: 'false', autocomplete: 'off', 'aria-label': 'Allowed origins, one per line' });
  origins.value = initial.origins;
  const methods = text('Allowed methods', initial.methods, 'GET POST');
  const allow = text('Allowed request headers', initial.allow_headers, 'Content-Type Authorization');
  const expose = text('Exposed response headers', initial.expose_headers, 'X-Request-Id');
  const credentials = h('input', { type: 'checkbox', checked: initial.credentials, 'aria-label': 'Allow credentials' });
  const age = h('input', { class: 'input mono', type: 'number', min: '0', max: '86400', value: initial.max_age, 'aria-label': 'Preflight max age in seconds' });
  const note = h('span', { class: 'error-text', role: 'status', 'aria-live': 'polite', hidden: true });
  const body = h('div', { class: 'form' },
    field('Allowed origins', origins, 'One exact origin per line, such as https://app.example.com, or a single * for any origin.'),
    h('div', { class: 'two-col narrow' }, field('Methods', methods, 'Space or comma separated, uppercase.'), field('Max age (seconds)', age, '0 to 86400.')),
    h('div', { class: 'two-col narrow' }, field('Allowed request headers', allow), field('Exposed response headers', expose)),
    h('label', { class: 'check-row' }, credentials, h('span', {}, 'Allow credentials (cookies and authorization headers)')),
    note);
  const read = () => ({
    enabled: on.checked, origins: origins.value, methods: methods.value, allow_headers: allow.value, expose_headers: expose.value, credentials: credentials.checked, max_age: age.value,
  });
  const sync = () => {
    body.hidden = !on.checked;
    const problem = on.checked ? corsProblem(corsFromForm(read())) : null;
    note.textContent = problem || '';
    note.hidden = !problem;
  };
  for (const el of [on, origins, methods, allow, expose, credentials, age]) el.addEventListener('input', sync);
  sync();
  return { el: h('div', { class: 'stack-sm' }, h('label', { class: 'check-row' }, on, h('span', {}, 'Handle CORS for matching requests')), body), read };
}

// The header matcher; a secret value is typed into a password box and never filled back in
function headerMatcherPane(initial) {
  const name = h('input', { class: 'input mono', type: 'text', value: initial.name, placeholder: 'X-Env', spellcheck: 'false', autocomplete: 'off', 'aria-label': 'Header name' });
  const mode = h('select', { class: 'select', 'aria-label': 'Header test', value: initial.mode }, option('equals', 'Equals'), option('regex', 'Matches regex'));
  // The value can be a credential, so password managers are told not to offer to save or fill it
  const value = h('input', {
    class: 'input mono', type: 'text', value: initial.value, spellcheck: 'false', autocomplete: 'new-password', autocapitalize: 'off',
    'data-lpignore': 'true', 'data-1p-ignore': 'true', 'data-bwignore': 'true', 'data-form-type': 'other', 'aria-label': 'Header value',
  });
  const negate = h('input', { type: 'checkbox', checked: initial.negate, 'aria-label': 'Match when the header test fails' });
  const secret = h('input', { type: 'checkbox', checked: initial.secret, 'aria-label': 'Treat the value as a secret' });
  const hint = h('span', { class: 'hint', role: 'status', 'aria-live': 'polite' });
  const sync = () => {
    value.type = secret.checked && mode.value === 'equals' ? 'password' : 'text';
    secret.disabled = mode.value === 'regex';
    if (mode.value === 'regex') secret.checked = false;
    value.placeholder = secret.checked && initial.stored ? 'Unchanged' : '';
    hint.textContent = secret.checked && initial.stored
      ? KEEP_SECRET_NOTE
      : secret.checked ? 'The value is not shown again after you save.' : 'Leave the name empty to skip this test.';
  };
  for (const el of [mode, secret]) el.addEventListener('change', sync);
  sync();
  return {
    el: h('div', { class: 'stack-sm' },
      h('div', { class: 'three-col' }, field('Header name', name), field('Test', mode), field('Value', value)),
      h('div', { class: 'pill-row' },
        h('label', { class: 'check-row' }, negate, h('span', {}, 'Match when the test fails (unless)')),
        h('label', { class: 'check-row' }, secret, h('span', {}, 'Secret value'))),
      hint),
    read: () => ({ name: name.value, mode: mode.value, value: value.value, negate: negate.checked, secret: secret.checked, stored: Boolean(initial.stored) }),
    wipe: () => { value.value = ''; },
  };
}

function openRuleEditor(node, rule, sites, onSaved) {
  const start = rule ? ruleToForm(rule) : emptyForm();
  const m = start.matchers;
  const name = h('input', { class: 'input', type: 'text', value: start.name, placeholder: 'Block WordPress probes', 'aria-label': 'Rule name' });
  const label = h('input', { class: 'input mono', type: 'text', value: start.label, placeholder: 'Defaults to the rule id', spellcheck: 'false', autocomplete: 'off', 'aria-label': 'Rule label' });
  let kind = start.kind;
  let action = start.action;
  const kindText = h('p', { class: 'hint', role: 'status', 'aria-live': 'polite' });
  const actionCards = Object.entries(ACTIONS).map(([key, a]) => {
    const radio = h('input', { type: 'radio', name: 'fw-action', value: key, checked: key === action, onChange: () => { action = key; } });
    return h('label', { class: 'radio-card' }, radio, h('div', {}, h('b', {}, a.label), h('p', { class: 'muted' }, a.text)));
  });
  const blockPane = h('div', { class: 'field' }, h('span', { class: 'field-label' }, 'Action'), h('div', { class: 'stack-sm' }, actionCards));
  const redirect = redirectPane(start.redirect);
  const headerOps = headerOpsPane(start.headers);
  const cors = corsPane(start.cors);
  const headersPane = h('div', { class: 'form' },
    field('Header changes', headerOps.el, 'Set replaces a header, Add appends one and Remove deletes it. Request changes reach your site; response changes reach the visitor.', { group: true }),
    cors.el);
  const panes = { block: blockPane, redirect: redirect.el, headers: headersPane };
  const syncKind = () => {
    for (const [key, pane] of Object.entries(panes)) pane.hidden = key !== kind;
    kindText.textContent = KINDS.find((k) => k.value === kind).text;
  };
  const kindControl = segmented({
    label: 'Rule kind', value: kind,
    options: KINDS.map((k) => ({ value: k.value, label: k.label })),
    onChange: (v) => { kind = v; syncKind(); },
  });

  const prefix = h('input', { class: 'input mono', type: 'text', value: m.path_prefix, placeholder: '/wp-admin', spellcheck: 'false', 'aria-label': 'Path prefix' });
  const pathRe = regexField('Path regex', m.path_regex, 'Matched anywhere in the request path.');
  const uaRe = regexField('User agent regex', m.user_agent_regex, 'Matched against the User-Agent header.');
  const refererRe = regexField('Referer regex', m.referer_regex, 'Matched against the Referer header. ^$ also matches a request without one.');
  const host = h('input', { class: 'input mono', type: 'text', value: m.host, placeholder: 'shop.example.com', spellcheck: 'false', 'aria-label': 'Host' });
  const scheme = h('select', { class: 'select', 'aria-label': 'Connection scheme', value: m.scheme }, option('', 'Any'), option('http', 'http'), option('https', 'https'));
  const header = headerMatcherPane(m.header);
  const picked = new Set(m.methods || []);
  const methodBoxes = METHODS.map((method) => h('label', { class: 'check-pill' },
    h('input', { type: 'checkbox', checked: picked.has(method), onChange: (e) => { if (e.target.checked) picked.add(method); else picked.delete(method); } }), method));
  const cidrs = chipInput({ values: m.cidrs || [], label: 'Client CIDR ranges', placeholder: '203.0.113.0/24, then Enter', validate: (v) => (CIDR_RE.test(v) ? null : `"${v}" is not an address or CIDR range.`) });
  const scope = h('select', { class: 'select', 'aria-label': 'Scope', value: start.site },
    h('option', { value: '' }, 'All sites on this node'), sites.map((x) => h('option', { value: x.id }, x.name)));
  const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const save = button(rule ? 'Save rule' : 'Add rule', { kind: 'primary', iconName: 'check' });
  let drawer = null;
  const fail = (message) => {
    err.textContent = message;
    err.hidden = false;
  };

  save.addEventListener('click', async () => {
    err.hidden = true;
    if (pathRe.invalid() || uaRe.invalid() || refererRe.invalid()) return fail('Fix the invalid regular expression first.');
    const form = {
      ...start,
      id: rule ? rule.id : newId('rule'),
      name: name.value,
      label: label.value,
      kind,
      action,
      site: scope.value,
      matchers: {
        path_prefix: prefix.value, path_regex: pathRe.input.value, methods: [...picked], user_agent_regex: uaRe.input.value, cidrs: cidrs.get(),
        host: host.value, scheme: scheme.value, referer_regex: refererRe.input.value, header: header.read(),
      },
      redirect: redirect.read(),
      headers: headerOps.read(),
      cors: cors.read(),
    };
    const built = buildRule(form);
    if (built.error) return fail(built.error);
    const body = built.rule;
    try {
      await withBusy(save, () => (rule ? nodeApi(node).put('/firewall/rules/' + encodeURIComponent(rule.id), body) : nodeApi(node).post('/firewall/rules', body)));
      header.wipe();
      toast(`Rule ${body.name} saved`, 'success');
      drawer.close();
      onSaved();
    } catch (ex) {
      fail(formatError(ex));
    }
  });

  syncKind();
  drawer = openDrawer({
    title: rule ? 'Edit rule' : 'Add firewall rule',
    subtitle: 'Every filled matcher must match for the rule to fire.',
    wide: true,
    onClose: () => header.wipe(),
    content: h('div', { class: 'form' },
      h('div', { class: 'two-col narrow' }, field('Name', name), field('Label', label, 'Optional. Shown in logs and the blocked-by-rule table instead of the id.')),
      h('div', { class: 'field' }, h('span', { class: 'field-label' }, 'Kind'), kindControl, kindText),
      blockPane, redirect.el, headersPane,
      h('h4', { class: 'section-title' }, 'Matchers'),
      h('div', { class: 'two-col narrow' }, field('Path prefix', prefix), field('Host', host)),
      pathRe.el,
      field('Methods', h('div', { class: 'check-pills' }, methodBoxes), 'Leave all unticked to match any method.', { group: true }),
      uaRe.el,
      h('div', { class: 'two-col narrow' }, field('Connection scheme', scheme, 'How the visitor connected. Behind Cloudflare Flexible SSL it is Cloudflare\'s view.'), refererRe.el),
      field('Request header', header.el, null, { group: true }),
      field('Client addresses', cidrs.el, 'IPv4 or IPv6 addresses and CIDR ranges.', { group: true }),
      field('Scope', scope),
      err),
    footer: [button('Cancel', { onClick: () => drawer.close() }), save],
  });
}

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
    card({ title: 'Rules', subtitle: 'Blocking rules are evaluated in order and the first match wins. Redirects and header rules apply after them.', flush: true, body: table }),
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
      queueMicrotask(() => openRuleEditor(node, null, data.sites, again));
    }
    return render(data, again, node);
  }, { skeleton: () => skeletonRows(6) });
}
