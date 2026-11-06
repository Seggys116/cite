import { h, s, clear } from '../dom.js';
import { nodeApi } from '../api.js';
import {
  pageHeader, button, loadInto, card, pill, dataTable, emptyState, field, toggle, chipInput, routeTabs,
  confirmDialog, toast, withBusy, formatError, kvList, skeletonBlock, fmtDate, relTime,
} from '../ui.js';
import { actionPill, slotPill, healthKind, healthDots, siteHref } from './common.js';
import { targetEditor } from './siteForm.js';
import { conditionList } from './conditions.js';
import {
  PATH_TYPES, pathFieldsFromRows, pathRowsFromSite,
} from '../conditionlib.js';
import { pagePreview } from './maintenance.js';
import { gitRefProblem } from '../siteCheck.js';
import { accessForSave, accessOf, zoneLockTurnedOn } from '../accesslib.js';
import { accessCard } from './accessCard.js';
import { rotateAndShow } from './zoneSecret.js';
import { nodeInfoCached, siteFeatures, showsBuildSettings } from '../caplib.js';
import { canRollback, deployRefFor, deployFailureText, historyRows } from '../historylib.js';
import {
  healthFromFields, healthProblems, hostProblem, nameProblem, routingProblem, siteBody, KINDS,
} from '../sitelib.js';
import { makeDirty, dirtyText } from '../dirtylib.js';
import { statusPanel } from './siteStatus.js';
import { logsPanel } from './siteLogs.js';
import { buildSettingsCard, envCard, tokenCard } from './siteBuild.js';
import { deployWithToasts } from './deployFlow.js';

const ALL_TABS = [
  { id: 'overview', label: 'Overview', icon: 'activity' },
  { id: 'deployments', label: 'Deployments', icon: 'rocket' },
  { id: 'build', label: 'Build', icon: 'wrench', needs: 'build' },
  { id: 'logs', label: 'Logs', icon: 'layers', needs: 'logs' },
  { id: 'routing', label: 'Settings', icon: 'globe' },
  { id: 'maintenance', label: 'Maintenance', icon: 'wrench' },
  { id: 'danger', label: 'Danger zone', icon: 'alert' },
];

// Tabs for features the node does not list are left out instead of showing controls that cannot work
function tabsFor(site, info) {
  const features = siteFeatures(info);
  return ALL_TABS.filter((t) => {
    if (t.needs === 'build') return showsBuildSettings(info, site);
    if (t.needs === 'logs') return Boolean(site.source) && features.logs;
    return true;
  });
}

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

function overviewPanel(site, extra = {}) {
  const live = (site.live && site.live[site.active]) || [];
  return h('div', { class: 'stack' },
    extra.status || null,
    card({ title: 'Traffic flow', subtitle: `All requests currently reach the ${site.active} slot`, body: flowDiagram(site) }),
    h('div', { class: 'two-col' },
      card({ title: 'Routing', body: kvList([
        ['Hosts', h('div', { class: 'chips' }, (site.hosts || []).map((x) => h('span', { class: 'chip chip-static mono' }, x)))],
        ['Paths', pathRowsFromSite(site).length
          ? h('div', { class: 'chips' }, pathRowsFromSite(site).map((r) => h('span', { class: 'chip chip-static mono' }, (r.type === 'path_regex' ? '~ ' : '') + r.value)))
          : h('span', { class: 'muted' }, 'any path')],
        ['Kind', site.kind === 'api' ? 'API' : 'Site'],
      ]) }),
      card({ title: 'Health', body: kvList([
        ['Check path', h('code', { class: 'mono' }, site.health.path)],
        ['Interval', `${site.health.interval_ms} ms`],
        ['Rise / fall', `${site.health.rise} / ${site.health.fall}`],
        ['Active targets', healthDots(live)],
      ]) })),
    site.source ? card({
      title: 'Source',
      actions: extra.editSource ? h('a', { class: 'btn btn-sm', href: siteHref(extra.node, site.id, 'build') }, 'Edit build settings') : null,
      body: kvList([
        ['Repository', h('code', { class: 'mono' }, site.source.repo)],
        ['Branch', h('code', { class: 'mono' }, site.source.branch || 'main')],
        ['Runtime', site.source.runtime ? `${site.source.runtime}${site.source.node_major ? ' ' + site.source.node_major : ''}` : 'node'],
        ['Poll interval', site.source.poll_interval || '5m'],
      ]),
    }) : null);
}

function deploymentsPanel(ctx, site, reload) {
  const { node, info } = ctx;
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

  // A node that cannot deploy in the background holds the request until health checks pass, so show elapsed time while it runs
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

  // A deploy that failed shows the node's whole message here and in a toast; the record is already in the history, so the list is refreshed
  const run = async (args, button0) => {
    err.hidden = true;
    const waits = !siteFeatures(info).deployAsync || !fromGit;
    const stop = waits ? showProgress() : () => {};
    const ok = await withBusy(button0, () => deployWithToasts({ node, siteId: site.id, info, ...args }, {
      onAfter: (res) => {
        stop();
        if (res.failed) {
          err.textContent = deployFailureText(res.error);
          err.hidden = false;
          reload();
        } else if (res.async) {
          location.hash = siteHref(node, site.id, 'overview');
        } else {
          reload();
        }
      },
    }));
    return ok;
  };

  deployBtn.addEventListener('click', () => {
    const problem = fromGit ? gitRefProblem(gitRef.value) : editor.validate();
    err.hidden = true;
    if (problem || (!fromGit && !editor.get().length)) {
      err.textContent = problem || 'Add at least one target to deploy.';
      err.hidden = false;
      return;
    }
    const noteText = note.value.trim() || undefined;
    run(fromGit ? { ref: gitRef.value.trim(), note: noteText } : { targets: editor.get(), note: noteText }, deployBtn);
  });

  const rollbackNow = async () => {
    const ok = await confirmDialog({ title: 'Roll back', message: `Return traffic to the previous version? The ${other(site.active)} slot becomes active again.`, confirmLabel: 'Roll back', danger: true });
    if (!ok) return;
    try {
      await nodeApi(node).post(`/sites/${encodeURIComponent(site.id)}/rollback`);
      toast('Rolled back', 'success');
      reload();
    } catch (ex) {
      toast(formatError(ex), 'error', 15000);
    }
  };
  const rollback = button('Roll back', { iconName: 'refresh', onClick: rollbackNow });
  rollback.disabled = !canRollback(site.history, site.active);
  rollback.title = rollback.disabled ? 'There is no earlier release to return to' : '';

  const history = historyRows(site.history, site.active);
  const rowActions = (d) => h('div', { class: 'row-actions' },
    fromGit && d.canRedeploy ? button('Redeploy', {
      size: 'sm', title: 'Build the latest commit again', onClick: (e) => run({ ref: deployRefFor({}, site.source) }, e.currentTarget),
    }) : null,
    fromGit && d.canDeployCommit ? button('Deploy this commit', {
      size: 'sm', title: `Build ${d.commit}`, onClick: (e) => run({ ref: deployRefFor(d, site.source) }, e.currentTarget),
    }) : null,
    d.current && canRollback(site.history, site.active) ? button('Roll back', { size: 'sm', onClick: rollbackNow }) : null);
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
          {
            label: 'Note',
            render: (d) => (d.note
              ? h('span', { class: d.failed ? 'error-text wrap-any' : 'wrap-any', title: d.note }, d.note)
              : h('span', { class: 'muted' }, '-')),
          },
          { label: 'Commit', render: (d) => (d.commit ? h('code', { class: 'mono' }, d.commit.slice(0, 7)) : h('span', { class: 'muted' }, '-')) },
          { label: 'Id', render: (d) => h('span', { class: 'mono muted' }, d.id) },
          { label: '', align: 'right', render: rowActions },
        ],
        rows: history,
        empty: emptyState({ iconName: 'rocket', title: 'No deployments yet', text: 'Deploy a version to start the history.' }),
      }),
    }));
}

function routingPanel(ctx, site, reload) {
  // check() is called by child controls while they are being built, so its handle is declared before them
  let queued = 0;
  const name = h('input', { class: 'input', type: 'text', value: site.name, 'aria-label': 'Site name' });
  const kind = h('select', { class: 'select', 'aria-label': 'Kind', value: site.kind || 'site' },
    KINDS.map((k) => h('option', { value: k }, k === 'api' ? 'API' : 'Site')));
  let hostList = [...(site.hosts || [])];
  const hosts = chipInput({
    values: hostList, label: 'Hosts', placeholder: 'Add host, then Enter', validate: (v) => hostProblem(v),
    onChange: (list) => { hostList = list; check(); },
  });
  const pathRows = pathRowsFromSite(site);
  const paths = conditionList({ rows: pathRows, types: PATH_TYPES, label: 'Path', addLabel: 'Add a path', onChange: () => check() });
  const numeric = (value, label) => h('input', { class: 'input mono', type: 'number', inputmode: 'numeric', value: String(value), 'aria-label': label });
  const path = h('input', { class: 'input mono', type: 'text', value: site.health.path, spellcheck: 'false', 'aria-label': 'Health check path' });
  const interval = numeric(site.health.interval_ms, 'Interval in ms');
  const rise = numeric(site.health.rise, 'Rise');
  const fall = numeric(site.health.fall, 'Fall');
  const timeout = numeric(site.health.timeout_ms, 'Timeout in ms');
  const access = accessCard({ node: ctx.node, site, onChange: () => check() });
  const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const save = button('Save settings', { kind: 'primary', iconName: 'check' });
  const badge = pill('Unsaved changes', 'warn');
  const dirtyHint = h('span', { class: 'muted', role: 'status', 'aria-live': 'polite' });
  const errs = {
    name: h('span', { class: 'error-text', role: 'status', hidden: true }),
    path: h('span', { class: 'error-text', role: 'status', hidden: true }),
    interval_ms: h('span', { class: 'error-text', role: 'status', hidden: true }),
    timeout_ms: h('span', { class: 'error-text', role: 'status', hidden: true }),
    rise: h('span', { class: 'error-text', role: 'status', hidden: true }),
    fall: h('span', { class: 'error-text', role: 'status', hidden: true }),
  };
  const current = () => ({
    name: name.value,
    kind: kind.value,
    hosts: hostList,
    pathRows,
    health: healthFromFields({ path: path.value, interval_ms: interval.value, timeout_ms: timeout.value, rise: rise.value, fall: fall.value }),
    access: access.get(),
  });
  const dirty = makeDirty(() => ({ ...current(), pathRows: pathFieldsFromRows(pathRows) }));
  // Marks the fields that are wrong as you type; the cheap per-field text is all that changes
  function check() {
    cancelAnimationFrame(queued);
    queued = requestAnimationFrame(() => {
      const c = current();
      const nm = nameProblem(c.name);
      const hp = healthProblems(c.health);
      const messages = { name: nm, ...hp };
      for (const [key, el] of Object.entries(errs)) {
        el.textContent = messages[key] || '';
        el.hidden = !messages[key];
      }
      const isDirty = dirty.dirty();
      badge.hidden = !isDirty;
      dirtyHint.textContent = isDirty ? dirtyText(['settings']) : '';
      save.disabled = !isDirty || Boolean(routingProblem({ ...c, pathRows }));
    });
  }
  for (const el of [name, kind, path, interval, timeout, rise, fall]) {
    el.addEventListener('input', check);
    el.addEventListener('change', check);
  }
  check();
  save.addEventListener('click', async () => {
    const fail = (m) => {
      err.textContent = m;
      err.hidden = false;
    };
    // get() also takes a host that was typed but not yet confirmed with Enter
    hostList = hosts.get();
    const c = current();
    const bad = routingProblem({ ...c, pathRows });
    if (bad) return fail(bad.message);
    err.hidden = true;
    const next = siteBody(site, {
      name: c.name.trim(),
      kind: c.kind,
      hosts: c.hosts,
      ...pathFieldsFromRows(pathRows),
      health: c.health,
    });
    delete next.access;
    const accessValue = accessForSave(access.get(), site.access);
    if (accessValue) next.access = accessValue;
    try {
      await withBusy(save, () => nodeApi(ctx.node).put(`/sites/${encodeURIComponent(site.id)}`, next));
      dirty.reset();
      toast('Settings saved', 'success');
      // The node makes the secret when the lock goes on, and only a rotate call hands it back
      if (zoneLockTurnedOn(accessOf(site), access.get())) {
        const failures = await rotateAndShow([ctx.node], site.id, reload);
        if (failures.length) {
          toast(formatError(failures[0].error), 'error');
          reload();
        }
        return;
      }
      reload();
    } catch (ex) {
      fail(formatError(ex));
    }
  });
  const withError = (label, control, key, hint) => {
    const f = field(label, control, hint);
    f.append(errs[key]);
    return f;
  };
  return h('div', { class: 'stack' },
    card({
      title: 'Site',
      actions: badge,
      body: h('div', { class: 'form' },
        h('div', { class: 'two-col' }, withError('Name', name, 'name'), field('Kind', kind, 'APIs usually route by path prefix; sites by domain.')),
        field('Hosts', hosts.el, null, { group: true }),
        field('Only for these paths (optional)', paths.el, 'Leave empty to serve every path. A request matching any path is routed here.', { group: true })),
    }),
    access.el,
    card({
      title: 'Health check',
      body: h('div', { class: 'form' },
        withError('Path', path, 'path', 'Requested on every target to decide whether it is ready.'),
        h('div', { class: 'four-col' },
          withError('Interval (ms)', interval, 'interval_ms', '100 to 60000.'), withError('Timeout (ms)', timeout, 'timeout_ms', '100 to 10000, not above the interval.'),
          withError('Rise', rise, 'rise', 'Passes to be healthy, 1 to 10.'), withError('Fall', fall, 'fall', 'Failures to be down, 1 to 10.'))),
    }),
    err,
    h('div', { class: 'form-actions' }, dirtyHint, save));
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
  ctx.setCrumbs([{ label: 'Sites', href: '#/sites' }, { label: id }]);
  const body = h('div', {});
  ctx.root.append(body);
  const n = nodeApi(node);
  loadInto(body, async () => {
    const [site, pages, info] = await Promise.all([
      n.get('/sites/' + encodeURIComponent(id)),
      n.get('/pages').catch(() => []),
      nodeInfoCached(node, () => n.get('/node')).catch(() => null),
    ]);
    return { site, pages, info };
  }, ({ site, pages, info }, reload) => {
    ctx.setCrumbs([{ label: 'Sites', href: '#/sites' }, { label: site.name }]);
    const TABS = tabsFor(site, info);
    const tab = TABS.some((t) => t.id === tabParam) ? tabParam : 'overview';
    const c = { node, info };
    const features = siteFeatures(info);
    const canStatus = Boolean(site.source) && features.status;
    let buildCard = null;
    let statusRef = null;
    const makeStatus = () => {
      statusRef = statusPanel({
        node,
        site,
        onStatus: (status, detected) => {
          if (buildCard && detected) buildCard.setDetected(detected);
        },
        onRedeploy: () => deployWithToasts({ node, siteId: site.id, info }, { onAfter: () => statusRef && statusRef.refresh() }),
      });
      return statusRef.el;
    };
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
    const buildPanel = () => {
      switch (tab) {
        case 'deployments': return deploymentsPanel(c, site, reload);
        case 'routing': return routingPanel(c, site, reload);
        case 'maintenance': return maintenancePanel(c, site, pages, reload);
        case 'danger': return dangerPanel(c, site);
        case 'build': {
          const status = canStatus ? makeStatus() : null;
          buildCard = buildSettingsCard({ node, site, info, onSaved: () => reload() });
          return h('div', { class: 'stack' },
            status, buildCard.el,
            features.buildEnv ? envCard({
              node, siteId: site.id, which: 'build-env', title: 'Build environment variables',
              subtitle: 'Visible to the install and build commands.',
              note: 'Values are write-only: only the names are shown after saving. Anything a static build bakes into its output is public.',
            }).el : null,
            features.runtimeEnv ? envCard({
              node, siteId: site.id, which: 'runtime-env', title: 'Runtime environment variables',
              subtitle: 'Given to the running site when it renders on the server.',
              note: 'Values are write-only: only the names are shown after saving.',
            }).el : null,
            features.token ? tokenCard({ node, siteId: site.id, onChanged: () => statusRef && statusRef.refresh() }).el : null);
        }
        case 'logs': return logsPanel({ node, site }).el;
        default: return overviewPanel(site, { status: canStatus ? makeStatus() : null, node, editSource: showsBuildSettings(info, site) });
      }
    };
    const pills = h('div', { class: 'pill-row' }, pill(site.kind === 'api' ? 'API' : 'Site', 'muted'), slotPill(site.active),
      site.maintenance && site.maintenance.enabled ? pill('Maintenance', 'warn', 'wrench') : pill('Serving', 'ok'), h('span', { class: 'mono muted' }, `${site.id} on ${node}`));
    return h('div', { class: 'stack' },
      pageHeader({ title: site.name, subtitle: pills, actions: [h('a', { class: 'btn', href: '#/sites' }, 'Back'), swap] }),
      routeTabs(TABS, tab, (t) => siteHref(node, id, t)),
      h('div', { class: 'tab-panel' }, buildPanel()));
  }, { skeleton: () => h('div', { class: 'stack' }, skeletonBlock(60), skeletonBlock(320)) });
}
