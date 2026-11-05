import { h, icon, clear } from '../dom.js';
import { nodeApi } from '../api.js';
import { state } from '../state.js';
import {
  pageHeader, button, loadInto, card, pill, dataTable, emptyState, dot, skeletonRows,
} from '../ui.js';
import { noNodes, siteHref, slotPill, healthDots } from './common.js';

async function loadSites() {
  const names = state.node === 'all' ? state.nodes.map((n) => n.name) : [state.node];
  const settled = await Promise.allSettled(names.map(async (node) => {
    const list = await nodeApi(node).get('/sites');
    return list.map((site) => ({ ...site, node }));
  }));
  const rows = settled.flatMap((r) => (r.status === 'fulfilled' ? r.value : []));
  const failed = names.filter((_, i) => settled[i].status === 'rejected');
  // Only a total failure is an error; a partial one is shown as a notice above the table.
  if (failed.length === names.length) throw settled[0].reason;
  return { rows, failed };
}

function hostChips(hosts) {
  const shown = hosts.slice(0, 2);
  return h('div', { class: 'chips' }, shown.map((host) => h('span', { class: 'chip chip-static mono', title: host }, host)),
    hosts.length > shown.length ? h('span', { class: 'chip chip-static' }, '+' + (hosts.length - shown.length)) : null);
}

function render({ rows, failed }) {
  const showNode = state.node === 'all';
  const healthCells = new Map();
  const needle = h('input', { class: 'input search', type: 'search', placeholder: 'Filter sites by name or host', 'aria-label': 'Filter sites' });
  const tableHost = h('div', {});
  const key = (r) => r.node + '/' + r.id;

  const columns = [
    { label: 'Site', render: (r) => h('div', { class: 'cell-stack' }, h('b', { class: 'cell-strong' }, r.name), h('span', { class: 'mono muted' }, r.id)) },
    showNode ? { label: 'Node', render: (r) => h('span', { class: 'mono' }, r.node) } : null,
    { label: 'Kind', render: (r) => pill(r.kind === 'api' ? 'API' : 'Site', 'muted') },
    { label: 'Hosts', render: (r) => hostChips(r.hosts || []) },
    { label: 'Active', render: (r) => slotPill(r.active) },
    {
      label: 'Health',
      render: (r) => {
        const cell = h('span', { class: 'dots' }, dot('idle', 'checking'));
        healthCells.set(key(r), cell);
        return cell;
      },
    },
    { label: 'State', render: (r) => (r.maintenance && r.maintenance.enabled ? pill('Maintenance', 'warn', 'wrench') : pill('Serving', 'ok')) },
  ].filter(Boolean);

  const draw = () => {
    const q = needle.value.trim().toLowerCase();
    const shown = rows.filter((r) => !q || r.name.toLowerCase().includes(q) || r.id.includes(q) || (r.hosts || []).some((x) => x.toLowerCase().includes(q)));
    healthCells.clear();
    clear(tableHost);
    tableHost.appendChild(dataTable({
      columns,
      rows: shown,
      onRowClick: (r) => { location.hash = siteHref(r.node, r.id); },
      rowLabel: (r) => 'Open site ' + r.name,
      empty: rows.length
        ? emptyState({ iconName: 'search', title: 'No sites match', text: 'Try a different name or host.' })
        : emptyState({
          iconName: 'globe',
          title: 'No sites yet',
          text: 'Create a site to route a host to a blue/green pair of upstreams.',
          action: h('a', { class: 'btn btn-primary', href: '#/sites/new' }, 'Create site'),
        }),
    }));
    // Health lives on the per-site detail call, so the dots fill in after the table is on screen
    for (const r of shown) {
      nodeApi(r.node).get('/sites/' + encodeURIComponent(r.id)).then((detail) => {
        const cell = healthCells.get(key(r));
        if (!cell || !cell.isConnected) return;
        const live = (detail.live && detail.live[detail.active]) || [];
        clear(cell);
        cell.appendChild(healthDots(live));
      }, () => {
        const cell = healthCells.get(key(r));
        if (cell) {
          clear(cell);
          cell.appendChild(dot('bad', 'unavailable'));
        }
      });
    }
  };
  needle.addEventListener('input', draw);
  draw();

  return h('div', { class: 'stack' },
    failed.length ? h('p', { class: 'notice warn' }, icon('alert'), `Could not load sites from ${failed.join(', ')}.`) : null,
    rows.length ? h('div', { class: 'toolbar' }, needle) : null,
    card({ flush: true, body: tableHost }));
}

export function sitesView(ctx) {
  ctx.setCrumbs([{ label: 'Sites' }]);
  const create = h('a', { class: 'btn btn-primary', href: '#/sites/new' }, icon('plus'), h('span', {}, 'Create site'));
  const body = h('div', {});
  let reload = null;
  ctx.root.append(pageHeader({
    title: 'Sites',
    subtitle: state.node === 'all' ? 'Every site on every node' : 'Sites on ' + state.node,
    actions: [button('', { iconName: 'refresh', title: 'Refresh', onClick: () => reload && reload() }), create],
  }), body);
  if (!state.nodes.length) {
    body.appendChild(noNodes());
    return;
  }
  reload = loadInto(body, loadSites, render, { skeleton: () => skeletonRows(5) });
}
