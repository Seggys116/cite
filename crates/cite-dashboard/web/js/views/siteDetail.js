import { h, s, clear } from '../dom.js';
import { nodeApi } from '../api.js';
import {
  pageHeader, button, loadInto, card, pill, dataTable, emptyState, field, toggle, chipInput, routeTabs,
  confirmDialog, toast, withBusy, formatError, kvList, skeletonBlock, fmtDate, relTime,
} from '../ui.js';
import { actionPill, slotPill, healthKind, healthDots, siteHref } from './common.js';
import { targetEditor, regexTester } from './siteForm.js';
import { pagePreview } from './maintenance.js';
import { gitRefProblem } from '../siteCheck.js';

const TABS = [
  { id: 'overview', label: 'Overview', icon: 'activity' },
  { id: 'deployments', label: 'Deployments', icon: 'rocket' },
  { id: 'routing', label: 'Routing', icon: 'globe' },
  { id: 'maintenance', label: 'Maintenance', icon: 'wrench' },
  { id: 'danger', label: 'Danger zone', icon: 'alert' },
];

const HOST_RE = /^(\*\.)?[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i;
const other = (slot) => (slot === 'blue' ? 'green' : 'blue');

// Draws clients, the edge and both slots; only the branch to the active slot is animated
function flowDiagram(site) {
  const live = site.live || {};
  const calm = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const activeY = site.active === 'blue' ? 80 : 220;
  const branch = (y) => `M380 150 C450 150 450 ${y} 520 ${y}`;
  const svg = s('svg', { class: 'flow-svg', viewBox: '0 0 720 300', role: 'img', 'aria-label': `Traffic flows to the ${site.active} slot` });

  const box = (x, y, w, hgt, cls, lines) => {
    const g = s('g', { class: cls }, s('rect', { x, y, width: w, height: hgt, rx: 10 }));
    lines.forEach((text, i) => g.append(s('text', { class: i ? 'node-sub' : 'node-title', x: x + w / 2, y: y + hgt / 2 + (lines.length === 1 ? 5 : i ? 18 : -2), 'text-anchor': 'middle' }, text)));
    return g;
  };

  const slot = (name, y) => {
    const targets = (site[name] && site[name].targets) || [];
    const active = site.active === name;
    const g = s('g', { class: `slot slot-${name}${active ? ' active' : ''}` },
      s('rect', { x: 520, y, width: 180, height: 100, rx: 10 }),
      s('text', { class: 'slot-title', x: 536, y: y + 26 }, name.toUpperCase()),
      s('text', { class: 'slot-state', x: 684, y: y + 26, 'text-anchor': 'end' }, active ? 'ACTIVE' : 'IDLE'));
    const shown = targets.length > 3 ? targets.slice(0, 2) : targets;
    shown.forEach((t, i) => {
      const found = (live[name] || []).find((l) => l.addr === t.addr);
      g.append(s('circle', { class: 'hd hd-' + healthKind(found ? found.status : ''), cx: 540, cy: y + 46 + i * 18, r: 4 }),
        s('text', { class: 'slot-addr', x: 552, y: y + 50 + i * 18 }, t.addr));
    });
    if (targets.length > 3) g.append(s('text', { class: 'slot-addr', x: 552, y: y + 50 + 2 * 18 }, `+${targets.length - 2} more`));
    if (!targets.length) g.append(s('text', { class: 'slot-addr', x: 536, y: y + 58 }, 'no targets'));
    return g;
  };

  svg.append(
    s('path', { class: 'flow active ' + site.active, d: 'M130 150 L250 150' }),
    s('path', { class: 'flow ' + (site.active === 'blue' ? 'active blue' : 'idle'), d: branch(80) }),
    s('path', { class: 'flow ' + (site.active === 'green' ? 'active green' : 'idle'), d: branch(220) }),
    box(20, 120, 110, 60, 'node-box', ['Clients']),
    box(250, 110, 130, 80, 'node-box edge', ['Cite edge', 'HAProxy']),
    slot('blue', 30), slot('green', 170),
    s('text', { class: 'share active', x: 456, y: site.active === 'blue' ? 108 : 214, 'text-anchor': 'middle' }, '100%'),
    s('text', { class: 'share', x: 456, y: site.active === 'blue' ? 214 : 108, 'text-anchor': 'middle' }, '0%'));
  if (!calm) {
    const route = `M130 150 L380 150 C450 150 450 ${activeY} 520 ${activeY}`;
    [0, 0.9].forEach((delay) => svg.append(s('circle', { class: 'packet ' + site.active, r: 3.5 },
      s('animateMotion', { dur: '1.8s', begin: delay + 's', repeatCount: 'indefinite', path: route }))));
  }
  return h('div', { class: 'flow-wrap' }, svg);
}

function overviewPanel(site) {
  const live = (site.live && site.live[site.active]) || [];
  return h('div', { class: 'stack' },
    card({ title: 'Traffic flow', subtitle: `All requests currently reach the ${site.active} slot`, body: flowDiagram(site) }),
    h('div', { class: 'two-col' },
      card({ title: 'Routing', body: kvList([
        ['Hosts', h('div', { class: 'chips' }, (site.hosts || []).map((x) => h('span', { class: 'chip chip-static mono' }, x)))],
        ['Path regex', h('code', { class: 'mono' }, site.path_regex || 'any path')],
        ['Kind', site.kind === 'api' ? 'API' : 'Site'],
      ]) }),
      card({ title: 'Health', body: kvList([
        ['Check path', h('code', { class: 'mono' }, site.health.path)],
        ['Interval', `${site.health.interval_ms} ms`],
        ['Rise / fall', `${site.health.rise} / ${site.health.fall}`],
        ['Active targets', healthDots(live)],
      ]) })),
    site.source ? card({ title: 'Source', body: kvList([
      ['Repository', h('code', { class: 'mono' }, site.source.repo)],
      ['Branch', h('code', { class: 'mono' }, site.source.branch || 'main')],
      ['Runtime', site.source.runtime ? `${site.source.runtime}${site.source.node_major ? ' ' + site.source.node_major : ''}` : 'node'],
      ['Poll interval', site.source.poll_interval || '5m'],
    ]) }) : null);
}

function deploymentsPanel(ctx, site, reload) {
  const { node } = ctx;
  const idle = other(site.active);
  const fromGit = Boolean(site.source);
  const editor = targetEditor({ targets: (site[idle] && site[idle].targets) || [] });
  const gitRef = h('input', {
    class: 'input mono', type: 'text', value: (site.source && site.source.branch) || 'main', placeholder: 'main, v1.4.0 or a commit sha',
    autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Git ref',
  });
  const note = h('input', { class: 'input', type: 'text', placeholder: 'What changed in this version', 'aria-label': 'Deployment note' });
  const progress = h('div', { class: 'progress-box', hidden: true, role: 'status' });
  const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const deployBtn = button(`Deploy to ${idle}`, { kind: 'primary', iconName: 'rocket' });

  // The deploy call blocks until health checks pass, so show elapsed time while it runs
  const showProgress = () => {
    const started = Date.now();
    const elapsed = h('b', { class: 'mono' }, '0s');
    clear(progress);
    progress.append(h('div', { class: 'progress' }, h('i', {})),
      h('p', {}, fromGit ? `Building the ${idle} slot from ${gitRef.value.trim()} and waiting for every health check to pass. ` : `Writing targets to the ${idle} slot and waiting for every health check to pass (up to 60 s). `, elapsed));
    progress.hidden = false;
    const timer = setInterval(() => { elapsed.textContent = Math.round((Date.now() - started) / 1000) + 's'; }, 500);
    return () => {
      clearInterval(timer);
      progress.hidden = true;
    };
  };

  deployBtn.addEventListener('click', async () => {
    const problem = fromGit ? gitRefProblem(gitRef.value) : editor.validate();
    err.hidden = true;
    if (problem || (!fromGit && !editor.get().length)) {
      err.textContent = problem || 'Add at least one target to deploy.';
      err.hidden = false;
      return;
    }
    const payload = fromGit ? { git_ref: gitRef.value.trim() } : { targets: editor.get() };
    payload.note = note.value.trim() || undefined;
    const stop = showProgress();
    try {
      await withBusy(deployBtn, () => nodeApi(node).post(`/sites/${encodeURIComponent(site.id)}/deploy`, payload));
      stop();
      toast(`Deployed. ${idle} is now active.`, 'success');
      reload();
    } catch (ex) {
      stop();
      err.textContent = formatError(ex);
      err.hidden = false;
      // A failed health check is a 409 whose record is already in the history, so refresh to show it
      if (ex && ex.status === 409) {
        toast(formatError(ex), 'error');
        reload();
      }
    }
  });

  const rollback = button('Roll back', {
    iconName: 'refresh',
    onClick: async () => {
      const ok = await confirmDialog({ title: 'Roll back', message: `Return traffic to the previous version? The ${other(site.active)} slot becomes active again.`, confirmLabel: 'Roll back', danger: true });
      if (!ok) return;
      try {
        await nodeApi(node).post(`/sites/${encodeURIComponent(site.id)}/rollback`);
        toast('Rolled back', 'success');
        reload();
      } catch (ex) {
        toast(formatError(ex), 'error');
      }
    },
  });

  const history = [...(site.history || [])].reverse();
  return h('div', { class: 'stack' },
    card({
      title: 'Deploy new version',
      subtitle: fromGit
        ? `The ref is built into the idle ${idle} slot, health checked, then traffic flips over.`
        : `Targets are written to the idle ${idle} slot, health checked, then traffic flips over.`,
      body: h('div', { class: 'form' }, fromGit
        ? field('Git ref', gitRef, 'A branch, tag or commit sha from the source repository.')
        : field('Targets for the new version', editor.el, null, { group: true }), field('Note', note), progress, err, h('div', { class: 'form-actions' }, deployBtn)),
    }),
    card({
      title: 'History',
      flush: true,
      actions: history.length ? rollback : null,
      body: dataTable({
        columns: [
          { label: 'When', render: (d) => h('span', { title: fmtDate(d.at) }, relTime(d.at)) },
          { label: 'Action', render: (d) => actionPill(d.action) },
          { label: 'Slot', render: (d) => slotPill(d.slot) },
          { label: 'Note', render: (d) => d.note || h('span', { class: 'muted' }, '-') },
          { label: 'Id', render: (d) => h('span', { class: 'mono muted' }, d.id) },
        ],
        rows: history,
        empty: emptyState({ iconName: 'rocket', title: 'No deployments yet', text: 'Deploy a version to start the history.' }),
      }),
    }));
}

function routingPanel(ctx, site, reload) {
  const name = h('input', { class: 'input', type: 'text', value: site.name, 'aria-label': 'Site name' });
  const hosts = chipInput({ values: site.hosts || [], label: 'Hosts', placeholder: 'Add host, then Enter', validate: (v) => (HOST_RE.test(v) ? null : `"${v}" is not a valid host name.`) });
  const tool = regexTester(site.path_regex || '');
  const numeric = (value, label) => h('input', { class: 'input mono', type: 'number', min: '0', value: String(value), 'aria-label': label });
  const path = h('input', { class: 'input mono', type: 'text', value: site.health.path, 'aria-label': 'Health check path' });
  const interval = numeric(site.health.interval_ms, 'Interval in ms');
  const rise = numeric(site.health.rise, 'Rise');
  const fall = numeric(site.health.fall, 'Fall');
  const timeout = numeric(site.health.timeout_ms, 'Timeout in ms');
  const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const save = button('Save routing', { kind: 'primary', iconName: 'check' });
  save.addEventListener('click', async () => {
    const fail = (m) => {
      err.textContent = m;
      err.hidden = false;
    };
    if (!name.value.trim()) return fail('The site needs a name.');
    if (!hosts.get().length) return fail('Keep at least one host.');
    if (tool.error()) return fail('The path regex is not valid.');
    if (!path.value.startsWith('/')) return fail('The health check path must start with /.');
    err.hidden = true;
    // Editable fields only; id, slots and active are what the Site schema requires and the server ignores them on update
    const next = {
      id: site.id,
      blue: site.blue,
      green: site.green,
      active: site.active,
      name: name.value.trim(),
      hosts: hosts.get(),
      path_regex: tool.value() || null,
      kind: site.kind,
      health: { path: path.value, interval_ms: Number(interval.value), rise: Number(rise.value), fall: Number(fall.value), timeout_ms: Number(timeout.value) },
      source: site.source,
    };
    try {
      await withBusy(save, () => nodeApi(ctx.node).put(`/sites/${encodeURIComponent(site.id)}`, next));
      toast('Routing saved', 'success');
      reload();
    } catch (ex) {
      fail(formatError(ex));
    }
  });
  return h('div', { class: 'stack' },
    card({ title: 'Routing', body: h('div', { class: 'form' }, field('Name', name), field('Hosts', hosts.el, null, { group: true }), tool.el) }),
    card({ title: 'Health check', body: h('div', { class: 'form' },
      field('Path', path),
      h('div', { class: 'four-col' }, field('Interval (ms)', interval), field('Timeout (ms)', timeout), field('Rise', rise), field('Fall', fall))) }),
    err,
    h('div', { class: 'form-actions' }, save));
}

function maintenancePanel(ctx, site, pages, reload) {
  const m = site.maintenance || { enabled: false, page_id: null };
  const select = h('select', { class: 'select', 'aria-label': 'Maintenance page', value: m.page_id || '' },
    h('option', { value: '' }, 'Built-in default page'), pages.map((p) => h('option', { value: p.id }, `${p.name} (${p.status})`)));
  const preview = h('div', { class: 'preview-slot' });
  const drawPreview = () => {
    clear(preview);
    const page = pages.find((p) => p.id === select.value);
    preview.append(page ? pagePreview(page) : h('p', { class: 'muted' }, 'The edge serves its built-in 503 page.'));
  };
  select.addEventListener('change', drawPreview);
  drawPreview();
  const sw = toggle({ checked: Boolean(m.enabled), label: 'Maintenance mode' });
  const apply = button('Apply', { kind: 'primary', iconName: 'check' });
  apply.addEventListener('click', async () => {
    try {
      await withBusy(apply, () => nodeApi(ctx.node).post(`/sites/${encodeURIComponent(site.id)}/maintenance`, { enabled: sw.isChecked(), page_id: select.value || undefined }));
      toast(sw.isChecked() ? 'Maintenance mode enabled' : 'Maintenance mode disabled', 'success');
      reload();
    } catch (ex) {
      toast(formatError(ex), 'error');
    }
  });
  return card({
    title: 'Maintenance mode',
    subtitle: 'Visitors see the chosen page with its status code while upstreams stay untouched.',
    body: h('div', { class: 'form' },
      h('div', { class: 'switch-row' }, sw, h('div', {}, h('b', {}, 'Serve the maintenance page'), h('p', { class: 'muted' }, m.enabled ? 'Currently enabled' : 'Currently disabled'))),
      field('Page', select), preview, h('div', { class: 'form-actions' }, apply)),
  });
}

function dangerPanel(ctx, site) {
  const del = button('Delete site', {
    kind: 'danger',
    iconName: 'trash',
    onClick: async () => {
      const ok = await confirmDialog({ title: 'Delete site', message: `This removes ${site.name} from ${ctx.node} and stops routing its hosts. Deployment history is lost.`, confirmLabel: 'Delete site', danger: true, requireText: site.id });
      if (!ok) return;
      try {
        await nodeApi(ctx.node).del(`/sites/${encodeURIComponent(site.id)}`);
        toast(`Site ${site.name} deleted`, 'success');
        location.hash = '#/sites';
      } catch (ex) {
        toast(formatError(ex), 'error');
      }
    },
  });
  return card({
    title: 'Danger zone',
    cls: 'danger',
    body: h('div', { class: 'danger-row' }, h('div', {}, h('b', {}, 'Delete this site'), h('p', { class: 'muted' }, 'Hosts stop routing immediately. This cannot be undone.')), del),
  });
}

// Route shape: #/sites/{node}/{site}/{tab}
export function siteDetailView(ctx) {
  const [node, id, tabParam] = ctx.params;
  const tab = TABS.some((t) => t.id === tabParam) ? tabParam : 'overview';
  const c = { node };
  ctx.setCrumbs([{ label: 'Sites', href: '#/sites' }, { label: id }]);
  const body = h('div', {});
  ctx.root.append(body);
  const n = nodeApi(node);
  loadInto(body, async () => {
    const [site, pages] = await Promise.all([n.get('/sites/' + encodeURIComponent(id)), n.get('/pages').catch(() => [])]);
    return { site, pages };
  }, ({ site, pages }, reload) => {
    ctx.setCrumbs([{ label: 'Sites', href: '#/sites' }, { label: site.name }]);
    const swap = button(`Switch to ${other(site.active)}`, {
      kind: 'primary',
      iconName: 'swap',
      onClick: async () => {
        const ok = await confirmDialog({ title: 'Switch active slot', message: `Send all traffic for ${site.name} to the ${other(site.active)} slot now?`, confirmLabel: 'Switch' });
        if (!ok) return;
        try {
          await n.post(`/sites/${encodeURIComponent(site.id)}/switch`, { slot: other(site.active) });
          toast(`${other(site.active)} is now active`, 'success');
          reload();
        } catch (ex) {
          toast(formatError(ex), 'error');
        }
      },
    });
    const panels = {
      overview: () => overviewPanel(site),
      deployments: () => deploymentsPanel(c, site, reload),
      routing: () => routingPanel(c, site, reload),
      maintenance: () => maintenancePanel(c, site, pages, reload),
      danger: () => dangerPanel(c, site),
    };
    const pills = h('div', { class: 'pill-row' }, pill(site.kind === 'api' ? 'API' : 'Site', 'muted'), slotPill(site.active),
      site.maintenance && site.maintenance.enabled ? pill('Maintenance', 'warn', 'wrench') : pill('Serving', 'ok'), h('span', { class: 'mono muted' }, `${site.id} on ${node}`));
    return h('div', { class: 'stack' },
      pageHeader({ title: site.name, subtitle: pills, actions: [h('a', { class: 'btn', href: '#/sites' }, 'Back'), swap] }),
      routeTabs(TABS, tab, (t) => siteHref(node, id, t)),
      h('div', { class: 'tab-panel' }, panels[tab]()));
  }, { skeleton: () => h('div', { class: 'stack' }, skeletonBlock(60), skeletonBlock(320)) });
}
