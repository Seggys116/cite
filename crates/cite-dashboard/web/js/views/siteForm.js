import { h, clear } from '../dom.js';
import { api } from '../api.js';
import { state } from '../state.js';
import {
  pageHeader, button, iconButton, card, field, segmented, chipInput, pill, toast, withBusy,
  formatError, slugify, checkRegex,
} from '../ui.js';
import { noNodes, listOf } from './common.js';
import { siteProblem, cleanToken, RUNTIMES, NODE_MAJORS } from '../siteCheck.js';

// Targets are host:port only, with no scheme or path, because they become HAProxy server addresses.
const ADDR_RE =/^[^\s:/]+:\d{1,5}$/;
const HOST_RE = /^(\*\.)?[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i;

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
    // Stop deriving the id once the user edits it, since it cannot change after creation.
    if (!idTouched) id.value = slugify(name.value);
  });
  id.addEventListener('input', () => { idTouched = true; });
  const hosts = chipInput({ placeholder: 'shop.example.com, then Enter', label: 'Hosts', validate: (v) => (HOST_RE.test(v) ? null : `"${v}" is not a valid host name.`) });
  const pathTool = regexTester('');
  const blue = targetEditor();
  const green = targetEditor();
  const healthPath = h('input', { class: 'input mono', type: 'text', value: '/', 'aria-label': 'Health check path' });
  let mode = 'upstreams';
  const repo = h('input', { class: 'input mono', type: 'text', placeholder: 'owner/name', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'GitHub repository' });
  const branch = h('input', { class: 'input mono', type: 'text', value: 'main', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Branch' });
  const runtime = h('select', { class: 'select', 'aria-label': 'Runtime' }, RUNTIMES.map((r) => h('option', { value: r }, r)));
  const nodeMajor = h('select', { class: 'select', 'aria-label': 'Node major version' }, NODE_MAJORS.map((m) => h('option', { value: String(m) }, 'Node ' + m)));
  const poll = h('input', { class: 'input mono', type: 'text', value: '5m', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Poll interval' });
  const token = h('input', { class: 'input mono', type: 'password', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'GitHub token' });
  const upstreamsPane = h('div', { class: 'form' },
    h('div', { class: 'two-col' },
      h('div', {}, h('h4', { class: 'slot-title' }, pill('blue', 'blue'), 'Blue targets'), blue.el),
      h('div', {}, h('h4', { class: 'slot-title' }, pill('green', 'green'), 'Green targets'), green.el)));
  const githubPane = h('div', { class: 'form', hidden: true },
    h('div', { class: 'two-col' }, field('Repository', repo, 'GitHub owner/name, for example acme/storefront.'), field('Branch', branch)),
    h('div', { class: 'two-col' }, field('Runtime', runtime, 'Picks the build and run images.'), field('Node version', nodeMajor)),
    h('div', { class: 'two-col' }, field('Poll interval', poll, 'How often the node checks the branch for new commits, such as 30s, 5m or 1h.'),
      field('GitHub token', token, 'Required for private repositories. Stored only on the node and never shown again.')));
  const syncRuntime = () => { nodeMajor.closest('.field').hidden = runtime.value === 'rust'; };
  runtime.addEventListener('change', syncRuntime);
  const modeControl = segmented({
    label: 'Source', value: mode,
    options: [{ value: 'upstreams', label: 'Existing upstreams' }, { value: 'github', label: 'Build from GitHub' }],
    onChange: (v) => {
      mode = v;
      upstreamsPane.hidden = v === 'github';
      githubPane.hidden = v !== 'github';
    },
  });
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
    const problem = siteProblem({
      name: name.value,
      id: id.value,
      hostCount: hosts.get().length,
      pathError: pathTool.error(),
      mode,
      source: { repo: repo.value, branch: branch.value, runtime: runtime.value, poll: poll.value },
      targetProblem: blue.validate() || green.validate(),
      blueCount: blue.get().length,
      healthPath: healthPath.value,
      pickNodes: modeEach.checked,
      nodePicked: checks.some((c) => c.checked),
    });
    fail(problem || '');
    return !problem;
  };

  submit.addEventListener('click', async () => {
    if (!validate()) return;
    const github = mode === 'github';
    const source = github ? {
      repo: repo.value.trim(),
      branch: branch.value.trim(),
      runtime: runtime.value,
      node_major: runtime.value === 'rust' ? null : Number(nodeMajor.value),
      poll_interval: poll.value.trim(),
    } : null;
    const githubToken = github ? cleanToken(token.value) : undefined;
    // The secret now lives only in this closure, so the field is emptied before the request starts.
    token.value = '';
    const site = {
      id: id.value,
      name: name.value.trim(),
      hosts: hosts.get(),
      path_regex: pathTool.value() || null,
      kind,
      blue: { targets: github ? [] : blue.get(), label: null },
      green: { targets: github ? [] : green.get(), label: null },
      active: 'blue',
      maintenance: { enabled: false, page_id: null },
      health: { path: healthPath.value, interval_ms: 2000, rise: 2, fall: 3, timeout_ms: 1500 },
      source,
    };
    const placeMode = modeAll.checked ? 'replicate' : 'each';
    // Replicate targets only online nodes, so an offline node cannot fail the whole request.
    const nodes = placeMode === 'replicate' ? onlineNames : checks.filter((c) => c.checked).map((c) => c.value);
    try {
      const res = await withBusy(submit, () => api.post('/deployments', { nodes, site, mode: placeMode, github_token: githubToken }));
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
      card({ title: 'Source', subtitle: 'Route to servers you run, or let the node build the site from a GitHub repository.', body: h('div', { class: 'form' },
        field('Source', modeControl, 'Building from GitHub makes the node provision the stack for the live slot, so no targets are needed.', { group: true }),
        upstreamsPane, githubPane) }),
      card({ title: 'Health check', body: h('div', { class: 'form' }, field('Health check path', healthPath, 'Probed on every target to decide readiness.')) }),
      card({ title: 'Placement', subtitle: 'Choose which nodes get this site', body: placement }),
      err,
      h('div', { class: 'form-actions' }, h('a', { class: 'btn', href: '#/sites' }, 'Cancel'), submit)));
  syncMode();
  syncRuntime();
}
