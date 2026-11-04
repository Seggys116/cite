import { h, clear } from '../dom.js';
import { api } from '../api.js';
import { state } from '../state.js';
import {
  pageHeader, button, iconButton, card, field, segmented, chipInput, pill, toast, withBusy,
  formatError, slugify, checkRegex,
} from '../ui.js';
import { noNodes, listOf } from './common.js';

const ADDR_RE = /^[^\s:/]+:\d{1,5}$/;
const HOST_RE = /^(\*\.)?[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i;
const ID_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;

// Editable list of upstream addresses with weights, shared by site creation and deploy forms
export function targetEditor({ targets = [] } = {}) {
  const rows = targets.map((t) => ({ addr: t.addr, weight: t.weight ?? 100 }));
  if (!rows.length) rows.push({ addr: '', weight: 100 });
  const list = h('div', { class: 'target-list' });
  const draw = () => {
    clear(list);
    rows.forEach((row, i) => {
      const addr = h('input', {
        class: 'input mono', type: 'text', value: row.addr, placeholder: '10.0.0.12:8080', spellcheck: 'false',
        'aria-label': `Target ${i + 1} address`, onInput: (e) => { row.addr = e.target.value.trim(); },
      });
      const weight = h('input', {
        class: 'input mono weight', type: 'number', min: '0', max: '256', value: String(row.weight),
        'aria-label': `Target ${i + 1} weight`, onInput: (e) => { row.weight = Number(e.target.value) || 0; },
      });
      list.appendChild(h('div', { class: 'target-row' }, addr, weight, iconButton('x', `Remove target ${i + 1}`, () => {
        rows.splice(i, 1);
        if (!rows.length) rows.push({ addr: '', weight: 100 });
        draw();
      })));
    });
  };
  draw();
  const add = button('Add target', { size: 'sm', iconName: 'plus', onClick: () => { rows.push({ addr: '', weight: 100 }); draw(); } });
  return {
    el: h('div', { class: 'target-editor' }, list, add),
    get: () => rows.filter((r) => r.addr).map((r) => ({ addr: r.addr, weight: r.weight })),
    validate() {
      const bad = rows.find((r) => r.addr && !ADDR_RE.test(r.addr));
      return bad ? `"${bad.addr}" is not a host:port address.` : null;
    },
  };
}

export function regexTester(initial = '') {
  const input = h('input', { class: 'input mono', type: 'text', value: initial, placeholder: '^/api/', spellcheck: 'false', 'aria-label': 'Path regex' });
  const sample = h('input', { class: 'input mono', type: 'text', placeholder: '/api/v1/users', spellcheck: 'false', 'aria-label': 'Sample path to test' });
  const status = h('div', { class: 'regex-status', 'aria-live': 'polite' });
  const result = h('div', { class: 'regex-result', 'aria-live': 'polite' });
  const update = () => {
    clear(status);
    clear(result);
    if (!input.value) {
      status.append(pill('Matches every path', 'muted'));
      return;
    }
    const problem = checkRegex(input.value);
    if (problem) {
      status.append(pill('Invalid', 'bad'), h('span', { class: 'error-text' }, problem));
      return;
    }
    status.append(pill('Valid regex', 'ok'));
    if (sample.value) {
      const hit = new RegExp(input.value).test(sample.value);
      result.append(pill(hit ? 'Sample matches' : 'Sample does not match', hit ? 'ok' : 'warn'));
    }
  };
  input.addEventListener('input', update);
  sample.addEventListener('input', update);
  update();
  return {
    el: h('div', { class: 'regex-tool' }, field('Path regex', input, 'Optional. Leave empty to route every path for these hosts.'), status,
      field('Test a path', sample), result),
    value: () => input.value.trim(),
    error: () => (input.value ? checkRegex(input.value) : null),
  };
}

export function newSiteView(ctx) {
  ctx.setCrumbs([{ label: 'Sites', href: '#/sites' }, { label: 'New site' }]);
  if (!state.nodes.length) {
    ctx.root.append(noNodes());
    return;
  }
  let kind = 'site';
  let idTouched = false;
  const name = h('input', { class: 'input', type: 'text', placeholder: 'Storefront', autocomplete: 'off' });
  const id = h('input', { class: 'input mono', type: 'text', placeholder: 'storefront', autocomplete: 'off', spellcheck: 'false' });
  const idHint = h('span', { class: 'hint' }, 'Lowercase letters, digits and dashes. Used in URLs and cannot change later.');
  name.addEventListener('input', () => {
    if (!idTouched) id.value = slugify(name.value);
  });
  id.addEventListener('input', () => { idTouched = true; });
  const hosts = chipInput({ placeholder: 'shop.example.com, then Enter', label: 'Hosts', validate: (v) => (HOST_RE.test(v) ? null : `"${v}" is not a valid host name.`) });
  const pathTool = regexTester('');
  const blue = targetEditor();
  const green = targetEditor();
  const healthPath = h('input', { class: 'input mono', type: 'text', value: '/', 'aria-label': 'Health check path' });
  const kindControl = segmented({
    label: 'Kind', value: kind,
    options: [{ value: 'site', label: 'Site' }, { value: 'api', label: 'API' }],
    onChange: (v) => { kind = v; },
  });

  const onlineNames = state.nodes.map((n) => n.name);
  const preferred = state.node !== 'all' ? [state.node] : onlineNames.slice(0, 1);
  const checks = state.nodes.map((n) => h('input', { type: 'checkbox', checked: preferred.includes(n.name), value: n.name, 'aria-label': 'Place on ' + n.name }));
  const nodeList = h('div', { class: 'node-checks' }, state.nodes.map((n, i) => h('label', { class: 'check-row' }, checks[i], h('span', { class: 'mono' }, n.name),
    n.online ? null : pill('offline', 'bad'))));
  const modeEach = h('input', { type: 'radio', name: 'place', value: 'each', checked: true });
  const modeAll = h('input', { type: 'radio', name: 'place', value: 'replicate' });
  const syncMode = () => {
    nodeList.classList.toggle('disabled', modeAll.checked);
    checks.forEach((c) => { c.disabled = modeAll.checked; });
  };
  modeEach.addEventListener('change', syncMode);
  modeAll.addEventListener('change', syncMode);
  const placement = h('div', { class: 'stack-sm' },
    h('label', { class: 'radio-card' }, modeEach, h('div', {}, h('b', {}, 'Selected nodes'), h('p', { class: 'muted' }, 'Create the site only on the nodes ticked below.'))),
    nodeList,
    h('label', { class: 'radio-card' }, modeAll, h('div', {}, h('b', {}, 'Replicate to all nodes'), h('p', { class: 'muted' }, `Create the same site on all ${state.nodes.length} connected nodes.`))));

  const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const fail = (message) => {
    err.textContent = message;
    err.hidden = !message;
    return false;
  };
  const submit = button('Create site', { kind: 'primary', iconName: 'rocket' });

  const validate = () => {
    if (!name.value.trim()) return fail('Give the site a name.');
    if (!ID_RE.test(id.value)) return fail('The site id must be lowercase letters, digits and dashes.');
    if (!hosts.get().length) return fail('Add at least one host name.');
    if (pathTool.error()) return fail('The path regex is not valid.');
    const problem = blue.validate() || green.validate();
    if (problem) return fail(problem);
    if (!blue.get().length) return fail('Add at least one blue target.');
    if (!healthPath.value.startsWith('/')) return fail('The health check path must start with /.');
    if (modeEach.checked && !checks.some((c) => c.checked)) return fail('Pick at least one node.');
    return fail('');
  };

  submit.addEventListener('click', async () => {
    if (!validate()) return;
    const site = {
      id: id.value,
      name: name.value.trim(),
      hosts: hosts.get(),
      path_regex: pathTool.value() || null,
      kind,
      blue: { targets: blue.get(), label: null },
      green: { targets: green.get(), label: null },
      active: 'blue',
      maintenance: { enabled: false, page_id: null },
      health: { path: healthPath.value, interval_ms: 2000, rise: 2, fall: 3, timeout_ms: 1500 },
      source: null,
    };
    const mode = modeAll.checked ? 'replicate' : 'each';
    const nodes = mode === 'replicate' ? onlineNames : checks.filter((c) => c.checked).map((c) => c.value);
    try {
      const res = await withBusy(submit, () => api.post('/deployments', { nodes, site, mode }));
      const results = listOf(res && res.results ? res.results : null);
      const failed = results.filter((r) => r && (r.error || r.ok === false));
      if (failed.length) {
        fail(failed.map((r) => `${r.node || 'node'}: ${r.error || 'failed'}`).join('; '));
        return;
      }
      toast(`Site ${site.name} created on ${nodes.length} node${nodes.length === 1 ? '' : 's'}`, 'success');
      location.hash = '#/sites';
    } catch (ex) {
      fail(formatError(ex));
    }
  });

  ctx.root.append(
    pageHeader({ title: 'Create site', subtitle: 'Define routing and upstreams, then place it on your nodes' }),
    h('div', { class: 'form-stack' },
      card({ title: 'Basics', body: h('div', { class: 'form' },
        field('Kind', kindControl, 'APIs usually route by path prefix; sites by host name.', { group: true }),
        field('Name', name), field('Id', id, null), idHint) }),
      card({ title: 'Routing', body: h('div', { class: 'form' }, field('Hosts', hosts.el, 'Requests with these Host headers go to this site.', { group: true }), pathTool.el) }),
      card({ title: 'Upstreams', subtitle: 'Both slots can be filled now. Green is where the first deploy lands.', body: h('div', { class: 'form' },
        h('div', { class: 'two-col' },
          h('div', {}, h('h4', { class: 'slot-title' }, pill('blue', 'blue'), 'Blue targets'), blue.el),
          h('div', {}, h('h4', { class: 'slot-title' }, pill('green', 'green'), 'Green targets'), green.el)),
        field('Health check path', healthPath, 'Probed on every target to decide readiness.')) }),
      card({ title: 'Targets', subtitle: 'Place on', body: placement }),
      err,
      h('div', { class: 'form-actions' }, h('a', { class: 'btn', href: '#/sites' }, 'Cancel'), submit)));
  syncMode();
}
