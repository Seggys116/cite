import { h, debounce, clear } from '../dom.js';
import { api, nodeApi, isMock } from '../api.js';
import { state } from '../state.js';
import {
  pageHeader, button, pill, emptyState, errorState, field, openDrawer, confirmDialog, toast, toggle, withBusy,
  formatError, slugify, newId, skeletonCards,
} from '../ui.js';
import { noNodes } from './common.js';
import { pickTargets } from './targetDialog.js';
import { applyToNodes, resultKind, resultMessage } from '../targetlib.js';
import {
  bulkMessage, driftPlan, drainPlan, missingPlan, nodesNeedingPage, planLines, restorePlan, rowPage, savePlan,
  saveConfirmLines, siteMatrix, syncSummary, unionPages,
} from '../pageslib.js';

const PAGE_WIDTH = 1280;

const STARTER_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Back soon</title>
<style>
body { margin: 0; min-height: 100vh; display: grid; place-items: center; font-family: system-ui, sans-serif; background: #0d1117; color: #e6edf3; }
main { max-width: 32rem; padding: 2rem; text-align: center; }
h1 { color: #ffd23f; }
</style>
</head>
<body>
<main>
<h1>Back soon</h1>
<p>We are making improvements and will be back in a few minutes.</p>
</main>
</body>
</html>
`;

// Renders page html in a fully sandboxed frame (no scripts, no same-origin access) scaled to fit its box. The server hosts the html under its own strict policy so inline styles work; mock mode has no server and falls back to srcdoc.
export function pagePreview(page) {
  const frame = h('iframe', { class: 'preview-frame', sandbox: '', title: `Preview of ${page.name || 'page'}`, tabindex: '-1' });
  const box = h('div', { class: 'preview' }, frame);
  const fit = () => frame.style.setProperty('transform', `scale(${(box.clientWidth / PAGE_WIDTH).toFixed(4)})`);
  new ResizeObserver(fit).observe(box);
  let latest = 0;
  box.update = async (html) => {
    if (isMock) {
      frame.setAttribute('srcdoc', html);
      return;
    }
    const ticket = ++latest;
    try {
      const res = await api.post('/preview', { html });
      if (ticket === latest && res && res.id) frame.setAttribute('src', '/preview/' + encodeURIComponent(res.id));
    } catch (ex) {
      if (ticket === latest) toast(formatError(ex), 'error');
    }
  };
  const first = () => box.update(page.html || '');
  if (typeof IntersectionObserver === 'function' && !isMock) {
    const watcher = new IntersectionObserver((entries) => {
      if (!entries.some((e) => e.isIntersecting)) return;
      watcher.disconnect();
      first();
    });
    watcher.observe(box);
  } else {
    first();
  }
  return box;
}

const pageBody = (p) => ({ id: p.id, name: p.name, html: p.html, status: p.status });

// A slug of the name, kept unique across the library so a new page never overwrites another
function freshId(name, union) {
  const base = slugify(name);
  const taken = new Set(union.pages.map((p) => p.id));
  if (base && !taken.has(base)) return base;
  return newId(base || 'page');
}

// getModel returns the latest loaded model so a save always plans against current node contents
function openEditor(getModel, existing, onSaved) {
  const name = h('input', { class: 'input', type: 'text', value: existing ? existing.name : '', placeholder: 'Scheduled maintenance', 'aria-label': 'Page name' });
  const status = h('input', { class: 'input mono', type: 'number', min: '100', max: '599', value: String(existing ? existing.status : 503), 'aria-label': 'Status code' });
  const html = h('textarea', { class: 'textarea mono', rows: '14', spellcheck: 'false', 'aria-label': 'Page HTML', value: existing ? existing.html : STARTER_HTML });
  const preview = pagePreview({ name: name.value, html: html.value });
  // Every preview update posts the html to the server, so typing is debounced; pagePreview drops any reply that is no longer the latest
  html.addEventListener('input', debounce(() => preview.update(html.value), 250));
  const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const save = button(existing ? 'Save page' : 'Create page', { kind: 'primary', iconName: 'check' });
  let drawer = null;
  const fail = (message) => {
    err.textContent = message;
    err.hidden = false;
  };
  save.addEventListener('click', async () => {
    const code = Number(status.value);
    if (!name.value.trim()) return fail('Give the page a name.');
    if (!Number.isInteger(code) || code < 100 || code > 599) return fail('The status code must be between 100 and 599.');
    if (!html.value.trim()) return fail('The page needs some HTML.');
    const { union } = getModel();
    // Only nodes that answered are written; the rest are named in the toast and caught up by "Bring nodes in line"
    const targets = union.nodes;
    if (!targets.length) return fail('No node is online to save to.');
    const body = { id: existing ? existing.id : freshId(name.value, union), name: name.value.trim(), html: html.value, status: code };
    const plan = savePlan(union, body.id, targets);
    const method = new Map(plan.map((p) => [p.node, p.method]));
    const count = `${plan.length} node${plan.length === 1 ? '' : 's'}`;
    // An edit that reaches several nodes, or replaces a copy that differs, lists every change first; cancelling leaves the drawer as it is
    const current = union.pages.find((p) => p.id === body.id);
    const detailed = existing && ((current && current.drift) || plan.length > 1);
    if (detailed || !existing) {
      const ok = await confirmDialog({
        title: existing ? 'Save page' : 'Create page',
        message: detailed
          ? h('span', { class: 'mx-lines' }, saveConfirmLines(union, body.id, plan, body.name).map((line) => h('span', { class: 'mx-line' }, line)))
          : `Create ${body.name} on ${targets.join(', ')}.`,
        confirmLabel: existing ? `Save on ${count}` : `Create on ${count}`,
      });
      if (!ok) return;
    }
    err.hidden = true;
    const results = await withBusy(save, () => applyToNodes(targets, (node) => (method.get(node) === 'put'
      ? nodeApi(node).put('/pages/' + encodeURIComponent(body.id), body)
      : nodeApi(node).post('/pages', body))));
    const skipped = state.nodes.map((n) => n.name).filter((n) => !targets.includes(n));
    const message = resultMessage('Saved', results) + (skipped.length ? `. Not updated: ${skipped.join(', ')}` : '');
    if (!results.some((r) => r.ok)) return fail(message);
    // Every written node succeeded but some were skipped: worth noticing, not an error
    toast(message, resultKind(results) === 'success' && skipped.length ? 'info' : resultKind(results));
    drawer.close();
    onSaved();
  });
  drawer = openDrawer({
    title: existing ? 'Edit page' : 'New maintenance page',
    wide: true,
    content: h('div', { class: 'form' },
      h('div', { class: 'two-col narrow' }, field('Name', name), field('Status code', status)),
      field('HTML', html, 'Plain HTML and CSS. Scripts are blocked in the preview.'),
      h('div', { class: 'field' }, h('span', { class: 'field-label' }, 'Live preview'), preview), err),
    footer: [button('Cancel', { onClick: () => drawer.close() }), save],
  });
}

// One entry per configured node. Offline nodes are not asked; a node that fails is passed on with null pages or sites.
async function loadAll() {
  return Promise.all(state.nodes.map(async (n) => {
    const entry = { node: n.name, online: n.online !== false, pages: null, sites: null, error: null };
    if (!entry.online) return entry;
    const c = nodeApi(n.name);
    const [pages, sites] = await Promise.allSettled([c.get('/pages'), c.get('/sites')]);
    if (pages.status === 'fulfilled' && Array.isArray(pages.value)) entry.pages = pages.value;
    if (sites.status === 'fulfilled' && Array.isArray(sites.value)) entry.sites = sites.value;
    const failed = [pages, sites].find((r) => r.status === 'rejected');
    if (failed) entry.error = formatError(failed.reason);
    else if (!entry.pages || !entry.sites) entry.error = 'Unexpected reply';
    return entry;
  }));
}

function buildModel(perNode) {
  return {
    perNode,
    union: unionPages(perNode.map(({ node, pages }) => ({ node, pages }))),
    matrix: siteMatrix(perNode.map(({ node, online, sites }) => ({ node, online, sites }))),
  };
}

export function maintenanceView(ctx) {
  ctx.setCrumbs([{ label: 'Maintenance' }]);
  let model = null;
  let ticket = 0;
  let librarySig = '';
  // The page picked in each row's select, kept across redraws
  const rowPages = new Map();

  const alerts = h('div', { class: 'mx-alerts' });
  const library = h('section', { class: 'mx-section', 'aria-labelledby': 'mx-pages-title' });
  const sitesBox = h('section', { class: 'mx-section', 'aria-labelledby': 'mx-sites-title' });
  const add = button('New page', { kind: 'primary', iconName: 'plus', onClick: () => model && openEditor(() => model, null, refresh) });
  const head = pageHeader({ title: 'Maintenance', subtitle: 'One set of pages for every node', actions: state.nodes.length ? add : null });
  if (!state.nodes.length) {
    ctx.root.append(head, noNodes());
    return;
  }
  ctx.root.append(head, h('div', { class: 'mx' }, alerts, library, sitesBox));
  // A switch is disabled while its request runs, which drops focus; the key says where to put it back after the redraw
  let pendingFocus = null;

  const pageFor = (row) => {
    const picked = rowPages.has(row.id) ? rowPages.get(row.id) : rowPage(row);
    return picked && model.union.pages.some((p) => p.id === picked) ? picked : '';
  };

  async function refresh() {
    const mine = ++ticket;
    let next;
    try {
      next = buildModel(await loadAll());
    } catch (ex) {
      if (mine !== ticket) return;
      clear(library);
      library.append(errorState(ex, () => {
        clear(library);
        library.append(skeletonCards(3));
        refresh();
      }));
      return;
    }
    if (mine !== ticket) return;
    model = next;
    drawAlerts();
    // Redrawing the cards reloads every preview, so it only happens when the library itself changed
    const sig = JSON.stringify([model.union, model.perNode.map((n) => [n.node, n.online])]);
    if (sig !== librarySig) {
      librarySig = sig;
      drawLibrary();
    }
    drawMatrix();
  }

  function markHeld(pageId, node) {
    const entry = model.union.pages.find((p) => p.id === pageId);
    if (!entry || entry.nodes.includes(node)) return;
    entry.nodes.push(node);
    entry.missing = entry.missing.filter((n) => n !== node);
  }

  async function ensurePage(node, pageId, created) {
    if (!pageId || !nodesNeedingPage(model.union, pageId, [node]).length) return;
    if (!created.has(pageId)) {
      const entry = model.union.pages.find((p) => p.id === pageId);
      created.set(pageId, nodeApi(node).post('/pages', pageBody(entry)).then(() => markHeld(pageId, node)));
    }
    await created.get(pageId);
  }

  const maintenancePath = (row) => `/sites/${encodeURIComponent(row.id)}/maintenance`;

  // The node refuses a page it does not hold, so the page is created there first
  async function enable(row, node, created = new Map()) {
    const pageId = pageFor(row);
    await ensurePage(node, pageId, created);
    await nodeApi(node).post(maintenancePath(row), { enabled: true, page_id: pageId || undefined });
  }

  async function disable(row, node) {
    await nodeApi(node).post(maintenancePath(row), { enabled: false, page_id: row.cells[node].pageId || pageFor(row) || undefined });
  }

  // Throws on failure so the switch snaps back
  async function flip(row, node, next, sw) {
    pendingFocus = sw.dataset.focusKey;
    sw.disabled = true;
    try {
      if (next) await enable(row, node);
      else await disable(row, node);
    } catch (ex) {
      toast(`Could not turn maintenance ${next ? 'on' : 'off'} for ${row.name} on ${node}: ${formatError(ex)}`, 'error');
      throw ex;
    } finally {
      sw.disabled = false;
      if (document.activeElement === document.body) sw.focus();
    }
    toast(`Maintenance ${next ? 'on' : 'off'} for ${row.name} on ${node}`, 'success');
    refresh();
  }

  async function bulk(node, verb, ids, run) {
    const rows = model.matrix.rows.filter((r) => ids.includes(r.id));
    const names = rows.map((r) => r.name).join(', ');
    const drain = verb === 'on';
    const ok = await confirmDialog({
      title: drain ? `Drain ${node}` : `Restore ${node}`,
      message: drain
        ? `Puts ${names} into maintenance on ${node}. Other nodes keep serving.`
        : `Takes ${names} out of maintenance on ${node}.`,
      confirmLabel: drain ? `Drain ${node}` : `Restore ${node}`,
      danger: drain,
    });
    if (!ok) return;
    const created = new Map();
    const results = await applyToNodes(ids, (id) => run(rows.find((r) => r.id === id), created));
    toast(bulkMessage(verb, node, rows, results), resultKind(results));
    refresh();
  }

  async function bringInLine() {
    const missing = missingPlan(model.union);
    const drift = driftPlan(model.union);
    if (!missing.length && !drift.length) return;
    const ok = await confirmDialog({
      title: 'Bring nodes in line',
      message: h('span', { class: 'mx-lines' }, planLines(missing, drift).map((line) => h('span', { class: 'mx-line' }, line))),
      confirmLabel: 'Apply changes',
    });
    if (!ok) return;
    const byNode = new Map();
    const queue = (node, page, method) => {
      if (!byNode.has(node)) byNode.set(node, []);
      byNode.get(node).push({ page, method });
    };
    for (const m of missing) queue(m.node, m.page, 'post');
    for (const d of drift) queue(d.node, d.page, 'put');
    const results = await applyToNodes(Array.from(byNode.keys()), async (node) => {
      const failed = [];
      for (const w of byNode.get(node)) {
        try {
          if (w.method === 'post') await nodeApi(node).post('/pages', pageBody(w.page));
          else await nodeApi(node).put('/pages/' + encodeURIComponent(w.page.id), pageBody(w.page));
        } catch (ex) {
          failed.push(`${w.page.name} (${formatError(ex)})`);
        }
      }
      if (failed.length) throw new Error(failed.join(', '));
    });
    toast(resultMessage('Updated', results), resultKind(results));
    refresh();
  }

  async function removePage(page) {
    const targets = await pickTargets({
      title: 'Delete page', message: `Delete ${page.name} from the nodes you pick.`, verb: 'Delete page', nodes: state.nodes, danger: true, only: page.nodes,
    });
    if (!targets || !targets.length) return;
    const results = await applyToNodes(targets, (node) => nodeApi(node).del('/pages/' + encodeURIComponent(page.id)));
    toast(resultMessage('Deleted', results), resultKind(results));
    refresh();
  }

  function drawAlerts() {
    clear(alerts);
    const { perNode, union } = model;
    const failed = perNode.filter((n) => n.online && n.error);
    if (failed.length) {
      alerts.append(h('p', { class: 'mx-note', role: 'status' }, failed.map((n) => `Could not read ${n.node}: ${n.error}`).join('. ')));
    }
    if (union.pages.length) {
      for (const n of perNode.filter((x) => Array.isArray(x.pages) && !x.pages.length)) {
        alerts.append(h('p', { class: 'mx-note', role: 'status' }, `${n.node} has no maintenance pages yet`));
      }
    }
  }

  function pageCard(page) {
    const differing = new Set(page.variants.slice(1).flatMap((v) => v.nodes));
    const chips = [
      ...page.nodes.map((n) => h('span', {
        class: 'mx-chip' + (differing.has(n) ? ' mx-chip-differs' : ''),
        title: differing.has(n) ? `${n} holds a different version` : `Held by ${n}`,
      }, n)),
      ...page.missing.map((n) => h('span', { class: 'mx-chip mx-chip-missing' }, `missing on ${n}`)),
    ];
    return h('article', { class: 'page-card' },
      pagePreview(page),
      h('div', { class: 'page-card-body' },
        h('header', {}, h('h3', {}, page.name), h('span', { class: 'mx-pills' }, pill(String(page.status), page.status >= 500 ? 'warn' : 'info'), page.drift ? pill('differs', 'warn') : null)),
        h('div', { class: 'mx-chips' }, chips),
        h('footer', {},
          button('Edit', { size: 'sm', iconName: 'edit', onClick: () => openEditor(() => model, page, refresh) }),
          button('Delete', { size: 'sm', kind: 'ghost-danger', iconName: 'trash', onClick: () => removePage(page) }))));
  }

  function drawLibrary() {
    clear(library);
    const { union } = model;
    const sync = syncSummary(union);
    const changes = missingPlan(union).length + driftPlan(union).length;
    library.append(h('div', { class: 'mx-head' },
      h('div', {}, h('h2', { class: 'mx-title', id: 'mx-pages-title' }, 'Pages'), h('p', { class: 'muted mx-sub', role: 'status' }, sync.text)),
      changes ? h('div', { class: 'mx-actions' }, button('Bring nodes in line', { iconName: 'refresh', onClick: bringInLine })) : null));
    if (!union.pages.length) {
      library.append(emptyState({ iconName: 'wrench', title: 'No maintenance pages', text: 'Create a page to show visitors during maintenance.' }));
      return;
    }
    library.append(h('div', { class: 'grid-pages' }, union.pages.map(pageCard)));
  }

  function pageSelect(row) {
    const chosen = pageFor(row);
    const select = h('select', { class: 'select mx-page-select', 'aria-label': `Page for ${row.name}`, title: 'Page served when maintenance is turned on' },
      h('option', { value: '', selected: chosen === '' }, 'Built-in page'),
      model.union.pages.map((p) => h('option', { value: p.id, selected: p.id === chosen }, p.name)));
    select.dataset.focusKey = `page:${row.id}`;
    select.addEventListener('change', () => rowPages.set(row.id, select.value));
    return select;
  }

  function matrixCell(row, node) {
    const cell = row.cells[node.name];
    if (!cell.present) {
      const why = !node.online ? `${node.name} is offline` : node.readable ? `Not on ${node.name}` : `${node.name} could not be read`;
      return h('td', { class: 'mx-cell' + (state.node === node.name ? ' mx-current' : '') },
        h('span', { class: 'mx-dash', title: why }, '–', h('span', { class: 'sr-only' }, why)));
    }
    const sw = toggle({
      checked: cell.enabled,
      label: `Maintenance for ${row.name} on ${node.name}`,
      onChange: (next) => flip(row, node.name, next, sw),
    });
    sw.dataset.focusKey = `switch:${row.id}:${node.name}`;
    const served = cell.pageId && model.union.pages.find((p) => p.id === cell.pageId);
    return h('td', { class: 'mx-cell' + (state.node === node.name ? ' mx-current' : '') },
      h('div', { class: 'mx-cell-body' }, sw,
        h('span', { class: 'mx-state' + (cell.enabled ? ' on' : ''), title: cell.enabled && served ? `Serving ${served.name}` : null }, cell.enabled ? 'Maintenance' : 'Live')));
  }

  function nodeHeader(node, matrix) {
    const usable = node.online && node.readable;
    const drainIds = usable ? drainPlan(matrix, node.name) : [];
    const restoreIds = usable ? restorePlan(matrix, node.name) : [];
    const drain = button('Drain', {
      size: 'sm', title: `Drain ${node.name}`, disabled: !drainIds.length,
      onClick: () => bulk(node.name, 'on', drainPlan(model.matrix, node.name), (row, created) => enable(row, node.name, created)),
    });
    drain.dataset.focusKey = `drain:${node.name}`;
    const restore = restoreIds.length ? button('Restore', {
      size: 'sm', title: `Restore ${node.name}`,
      onClick: () => bulk(node.name, 'off', restorePlan(model.matrix, node.name), (row) => disable(row, node.name)),
    }) : null;
    if (restore) restore.dataset.focusKey = `restore:${node.name}`;
    return h('th', { scope: 'col', class: 'mx-node' + (state.node === node.name ? ' mx-current' : '') },
      h('div', { class: 'mx-node-head' }, h('span', { class: 'mx-node-name mono' }, node.name), node.online ? null : pill('Offline', 'warn')),
      h('div', { class: 'mx-node-actions' }, drain, restore));
  }

  function drawMatrix() {
    const active = document.activeElement;
    const idle = !active || active === document.body;
    const focusKey = active && sitesBox.contains(active) ? active.dataset.focusKey : (idle ? pendingFocus : null);
    pendingFocus = null;
    clear(sitesBox);
    const { matrix } = model;
    sitesBox.append(h('div', { class: 'mx-head' },
      h('div', {}, h('h2', { class: 'mx-title', id: 'mx-sites-title' }, 'Sites by node'), h('p', { class: 'muted mx-sub' }, 'Turn maintenance on for one node at a time'))));
    if (!matrix.rows.length) {
      sitesBox.append(emptyState({ iconName: 'server', title: 'No sites yet', text: 'Sites appear here once a node has them.' }));
      return;
    }
    const body = h('tbody', {}, matrix.rows.map((row) => h('tr', {},
      h('th', { scope: 'row', class: 'mx-site' }, h('span', { class: 'mx-site-name' }, row.name), h('span', { class: 'mx-site-id mono' }, row.id)),
      h('td', { class: 'mx-page' }, pageSelect(row)),
      matrix.nodes.map((n) => matrixCell(row, n)))));
    sitesBox.append(h('div', { class: 'mx-scroll', role: 'region', 'aria-label': 'Maintenance by site and node', tabindex: '0' },
      h('table', { class: 'mx-table' },
        h('caption', { class: 'sr-only' }, 'Maintenance by site and node'),
        h('thead', {}, h('tr', {},
          h('th', { scope: 'col', class: 'mx-site' }, 'Site'),
          h('th', { scope: 'col', class: 'mx-page' }, 'Page'),
          matrix.nodes.map((n) => nodeHeader(n, matrix)))),
        body)));
    if (focusKey) {
      const el = sitesBox.querySelector(`[data-focus-key="${CSS.escape(focusKey)}"]`);
      if (el && !el.disabled) el.focus();
    }
  }

  library.append(skeletonCards(3));
  refresh();
}
