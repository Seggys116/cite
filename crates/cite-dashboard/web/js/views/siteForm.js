import { h, clear } from '../dom.js';
import { api, nodeApi } from '../api.js';
import { state } from '../state.js';
import {
  pageHeader, button, iconButton, field, segmented, chipInput, toast, kvList, formatError, slugify,
} from '../ui.js';
import { noNodes, listOf } from './common.js';
import {
  TOKEN_TOGGLE, tokenPlan, tokenState, cleanToken,
} from '../siteCheck.js';
import { nodeInfoCached } from '../caplib.js';
import { sourceFields } from './sourceFields.js';
import { createVerdict, rotationFailureLines } from '../accesslib.js';
import { PATH_TYPES } from '../conditionlib.js';
import {
  SOURCES, STEPS, buildSite, emptySiteForm, firstProblem, reviewLines, stepProblem,
} from '../sitewizard.js';
import { accessCard } from './accessCard.js';
import { conditionList } from './conditions.js';
import { rotateAndShow } from './zoneSecret.js';
import { wizard } from './wizard.js';

// Targets are host:port only, with no scheme or path, because they become HAProxy server addresses.
const ADDR_RE =/^[^\s:/]+:\d{1,5}$/;
const HOST_RE = /^(\*\.)?[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i;

// Editable list of upstream addresses with weights, shared by site creation and deploy forms
export function targetEditor({ targets = [], onChange } = {}) {
  const rows = targets.map((t) => ({ addr: t.addr, weight: t.weight ?? 100 }));
  if (!rows.length) rows.push({ addr: '', weight: 100 });
  const list = h('div', { class: 'target-list' });
  const changed = () => {
    if (onChange) onChange();
  };
  const draw = () => {
    clear(list);
    rows.forEach((row, i) => {
      const addr = h('input', {
        class: 'input mono', type: 'text', value: row.addr, placeholder: '10.0.0.12:8080', spellcheck: 'false',
        'aria-label': `Target ${i + 1} address`, onInput: (e) => { row.addr = e.target.value.trim(); changed(); },
      });
      const weight = h('input', {
        class: 'input mono weight', type: 'number', min: '0', max: '256', value: String(row.weight),
        'aria-label': `Target ${i + 1} weight`, onInput: (e) => { row.weight = Number(e.target.value) || 0; changed(); },
      });
      list.appendChild(h('div', { class: 'target-row' }, addr, weight, iconButton('x', `Remove target ${i + 1}`, () => {
        rows.splice(i, 1);
        if (!rows.length) rows.push({ addr: '', weight: 100 });
        draw();
        changed();
      })));
    });
  };
  draw();
  const add = button('Add target', { size: 'sm', iconName: 'plus', onClick: () => { rows.push({ addr: '', weight: 100 }); draw(); changed(); } });
  return {
    el: h('div', { class: 'target-editor' }, list, add),
    get: () => rows.filter((r) => r.addr).map((r) => ({ addr: r.addr, weight: r.weight })),
    validate() {
      const bad = rows.find((r) => r.addr && !ADDR_RE.test(r.addr));
      return bad ? `"${bad.addr}" is not a host:port address.` : null;
    },
  };
}

function choiceCards(name, items, current, onPick) {
  return h('div', { class: 'choice-cards', role: 'radiogroup', 'aria-label': name }, items.map((item) => {
    const radio = h('input', { type: 'radio', name, value: item.value, checked: item.value === current, onChange: () => onPick(item.value) });
    return h('label', { class: 'radio-card' }, radio, h('div', {}, h('b', {}, item.title), h('p', { class: 'muted' }, item.text)));
  }));
}

export function newSiteView(ctx) {
  ctx.setCrumbs([{ label: 'Sites', href: '#/sites' }, { label: 'New site' }]);
  if (!state.nodes.length) {
    ctx.root.append(noNodes());
    return;
  }
  const form = emptySiteForm();
  const onlineNames = state.nodes.map((n) => n.name);
  const preferred = state.node !== 'all' ? [state.node] : onlineNames.slice(0, 1);
  form.nodes = [...preferred];

  // Controls whose state lives in the control itself are made once and moved into each step that shows them
  let idTouched = false;
  let tokenOpen = false;
  const nodeStates = new Map();
  const nodeInfos = new Map();
  const token = h('input', {
    class: 'input mono', type: 'password', autocomplete: 'new-password', spellcheck: 'false', 'aria-label': 'GitHub token',
    'data-lpignore': 'true', 'data-1p-ignore': 'true', 'data-bwignore': 'true',
  });
  const hosts = chipInput({
    placeholder: 'shop.example.com, then Enter', label: 'Domains', validate: (v) => (HOST_RE.test(v) ? null : `"${v}" is not a valid host name.`),
    onChange: (list) => { form.hosts = list; refresh(); },
  });
  const blue = targetEditor({ onChange: () => { syncTargets(); refresh(); } });
  const green = targetEditor({ onChange: () => { syncTargets(); refresh(); } });
  const access = accessCard({ node: preferred[0] || onlineNames[0], site: null, siteId: () => form.id, onChange: (value) => { form.access = value; } });
  form.access = access.get();
  const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
  let flow = null;
  const refresh = () => {
    if (flow) flow.refresh();
  };

  function syncTargets() {
    form.blue = blue.get();
    form.green = green.get();
    form.targetProblem = blue.validate() || green.validate();
  }

  const selectedNodes = () => (form.replicate ? onlineNames : form.nodes);
  const currentPlan = () => tokenPlan(selectedNodes().map((n) => nodeStates.get(n) || 'unknown'));
  const checkCtx = () => ({ tokenPlan: currentPlan(), token: token.value });
  const input = (label, key, props = {}) => {
    const el = h('input', { class: 'input mono', type: 'text', value: form[key], spellcheck: 'false', autocomplete: 'off', 'aria-label': label, ...props });
    el.addEventListener('input', () => { form[key] = el.value; refresh(); });
    return el;
  };

  // The token field is folded away when every selected node already holds a token
  function tokenPane() {
    const plan = currentPlan();
    const box = h('div', { class: 'field' },
      h('span', { class: 'field-label' }, plan.required ? 'GitHub token (required)' : 'GitHub token'), token,
      h('span', { class: 'hint' }, plan.show ? plan.help : 'Used only for this site. Stored only on the node and never shown again.'));
    box.hidden = !plan.show && !tokenOpen;
    const open = button(TOKEN_TOGGLE, { size: 'sm' });
    open.addEventListener('click', () => {
      tokenOpen = true;
      box.hidden = false;
      open.hidden = true;
      token.focus();
    });
    open.hidden = plan.show || tokenOpen;
    token.oninput = refresh;
    return h('div', { class: 'stack-sm' }, plan.show ? null : h('p', { class: 'muted' }, plan.help), open, box);
  }

  // The same field set the site page uses, built once and moved into the step each time it is shown
  let sourceUi = null;
  function githubDetails() {
    if (!sourceUi) sourceUi = sourceFields({ form: form.src, info: nodeInfos.get(selectedNodes()[0]) || null, onChange: refresh });
    return h('div', { class: 'form' }, sourceUi.el, tokenPane());
  }

  function serverDetails() {
    const healthPath = input('Health check path', 'healthPath');
    return h('div', { class: 'form' },
      h('div', { class: 'two-col' },
        h('div', {}, h('h4', { class: 'slot-title' }, 'Live servers'), blue.el),
        h('div', {}, h('h4', { class: 'slot-title' }, 'Standby servers (optional)'), green.el)),
      field('Health check path', healthPath, 'Requested on every server to decide whether it is ready.'));
  }

  function domainDetails() {
    const kindControl = segmented({
      label: 'Kind', value: form.kind,
      options: [{ value: 'site', label: 'Site' }, { value: 'api', label: 'API' }],
      onChange: (v) => { form.kind = v; },
    });
    const name = input('Site name', 'name', { class: 'input', placeholder: 'Storefront' });
    const id = input('Site id', 'id', { placeholder: 'storefront' });
    name.addEventListener('input', () => {
      // Stop deriving the id once the user edits it, since it cannot change after creation.
      if (!idTouched) {
        id.value = slugify(name.value).slice(0, 40).replace(/-+$/, '');
        form.id = id.value;
        refresh();
      }
    });
    id.addEventListener('input', () => { idTouched = true; });
    hosts.set(form.hosts);
    return h('div', { class: 'form' },
      field('Kind', kindControl, 'APIs usually route by path prefix; sites by domain.', { group: true }),
      h('div', { class: 'two-col' }, field('Name', name), field('Id', id, 'Lowercase letters, digits and dashes. Cannot change later.')),
      field('Domains', hosts.el, 'Requests for these domains go to this site.', { group: true }),
      h('div', { class: 'stack-sm' },
        h('span', { class: 'field-label' }, 'Only for these paths (optional)'),
        h('p', { class: 'hint' }, 'Leave empty to serve every path on the domains. Add several; a request matching any of them is routed here.'),
        conditionList({ rows: form.paths, types: PATH_TYPES, label: 'Path', addLabel: 'Add a path', onChange: () => refresh() }).el));
  }

  function whereDetails() {
    const each = h('input', { type: 'radio', name: 'place', value: 'each', checked: !form.replicate });
    const all = h('input', { type: 'radio', name: 'place', value: 'replicate', checked: form.replicate });
    const checks = state.nodes.map((n) => h('input', { type: 'checkbox', checked: form.nodes.includes(n.name), disabled: form.replicate, value: n.name, 'aria-label': 'Place on ' + n.name }));
    const list = h('div', { class: 'node-checks' }, state.nodes.map((n, i) => h('label', { class: 'check-row' }, checks[i], h('span', { class: 'mono' }, n.name),
      n.online ? null : h('span', { class: 'muted' }, '(offline)'))));
    list.classList.toggle('disabled', form.replicate);
    const review = h('div', {});
    const drawReview = () => {
      const tokenText = form.source === 'github' ? (token.value.trim() ? 'a token for this site' : currentPlan().show ? 'none' : 'the node token') : '';
      review.replaceChildren(kvList(reviewLines(form, { tokenText }).map(([k, v]) => [k, h('span', { class: 'wrap-any' }, v)])));
    };
    const sync = () => {
      form.replicate = all.checked;
      form.nodes = checks.filter((c) => c.checked).map((c) => c.value);
      checks.forEach((c) => { c.disabled = all.checked; });
      list.classList.toggle('disabled', all.checked);
      drawReview();
      refresh();
    };
    [each, all, ...checks].forEach((el) => el.addEventListener('change', sync));
    drawReview();
    return h('div', { class: 'form' },
      h('div', { class: 'stack-sm' },
        h('label', { class: 'radio-card' }, each, h('div', {}, h('b', {}, 'Selected nodes'), h('p', { class: 'muted' }, 'Create the site only on the nodes ticked below.'))),
        list,
        h('label', { class: 'radio-card' }, all, h('div', {}, h('b', {}, 'Replicate to all nodes'), h('p', { class: 'muted' }, `Create the same site on all ${state.nodes.length} connected nodes.`)))),
      h('h4', { class: 'section-title' }, 'Review'), review, err);
  }

  const steps = [
    {
      title: STEPS[0].title,
      problem: () => stepProblem(form, 0),
      render: () => h('div', { class: 'form' }, choiceCards('Source', SOURCES, form.source, (v) => { form.source = v; refresh(); })),
    },
    {
      title: STEPS[1].title,
      problem: () => { syncTargets(); return stepProblem(form, 1, checkCtx()); },
      render: () => (form.source === 'github' ? githubDetails() : serverDetails()),
    },
    { title: STEPS[2].title, problem: () => stepProblem(form, 2), render: domainDetails },
    { title: STEPS[3].title, problem: () => stepProblem(form, 3), render: () => access.el },
    { title: STEPS[4].title, problem: () => stepProblem(form, 4, checkCtx()), render: whereDetails },
  ];

  async function create() {
    err.hidden = true;
    syncTargets();
    form.access = access.get();
    const bad = firstProblem(form, checkCtx());
    if (bad) {
      if (bad.step === 1 && sourceUi) sourceUi.touchAll();
      flow.go(bad.step);
      return;
    }
    const github = form.source === 'github';
    const githubToken = github ? cleanToken(token.value) : undefined;
    // The secret now lives only in this closure, so the field is emptied before the request starts.
    token.value = '';
    const site = buildSite(form);
    const placeMode = form.replicate ? 'replicate' : 'each';
    // Replicate targets only online nodes, so an offline node cannot fail the whole request.
    const nodes = placeMode === 'replicate' ? onlineNames : form.nodes;
    try {
      const res = await api.post('/deployments', { nodes, site, mode: placeMode, github_token: githubToken });
      const results = listOf(res && res.results ? res.results : null);
      const verdict = createVerdict({ results, nodes, zoneLock: Boolean(site.access && site.access.zone_lock) });
      const leave = () => { location.hash = '#/sites'; };
      if (!verdict.ok) {
        err.textContent = verdict.error;
        err.hidden = false;
        flow.go(steps.length - 1);
      } else {
        toast(`Site ${site.name} created on ${nodes.length} node${nodes.length === 1 ? '' : 's'}`, 'success');
      }
      // The secret only comes from a rotate call, so a new zone lock fetches one per node that took the site and shows it once
      if (verdict.rotate.length) {
        const failures = await rotateAndShow(verdict.rotate, site.id, verdict.ok ? leave : null);
        rotationFailureLines(failures, formatError).forEach((line) => toast(line, 'error'));
        return;
      }
      if (verdict.ok) leave();
    } catch (ex) {
      err.textContent = formatError(ex);
      err.hidden = false;
      flow.go(steps.length - 1);
    }
  }

  flow = wizard({ steps, finishLabel: 'Create site', onFinish: create, onCancel: () => { location.hash = '#/sites'; } });

  // Each node reports whether it holds a GitHub token; until it answers (or if it is an older connector) the state is unknown
  for (const name of onlineNames) {
    nodeInfoCached(name, () => nodeApi(name).get('/node')).then((info) => {
      nodeStates.set(name, tokenState(info));
      nodeInfos.set(name, info);
      if (sourceUi && name === selectedNodes()[0]) sourceUi.setInfo(info);
    }, () => nodeStates.set(name, 'unknown')).then(refresh);
  }

  ctx.root.append(
    pageHeader({ title: 'Create site', subtitle: 'Choose where the site comes from and which domains reach it' }),
    h('div', { class: 'form-stack' }, flow.el));
}
