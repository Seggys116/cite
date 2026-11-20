import { h, icon, clear, debounce } from '../dom.js';
import { nodeApi, qs } from '../api.js';
import { state } from '../state.js';
import { sparkline } from '../charts.js';
import {
  pageHeader, button, loadInto, card, pill, dataTable, emptyState, segmented, skeletonRows,
} from '../ui.js';
import { noNodes, siteHref } from './common.js';
import { fmtRps, loadFromFacets } from '../topologylib.js';
import {
  SCOPE_ALL, SCOPE_ATTENTION, chipTitle, filterRows, groupSites, homeNode, mergeSeries, needsAttention, nodeScope, nodeStatus,
  rowRps, rowStatus, scopeRows, subtitleFor,
} from '../siteslib.js';

const STATE_ICON = { attention: 'alert', failed: 'alert', maintenance: 'wrench' };

// One request per node for the list and one for the load of every site on it, all started together.
// The load never holds the list back: it arrives as a promise and fills the page in afterwards.
async function loadSites() {
  const names = state.node === 'all' ? state.nodes.map((n) => n.name) : [state.node];
  const calls = names.map((node) => {
    const api = nodeApi(node);
    return {
      node,
      sites: api.get('/sites'),
      load: api.get('/analytics/facets' + qs({ window: '15m' })).then((facets) => loadFromFacets(facets), () => null),
    };
  });
  const settled = await Promise.allSettled(calls.map((c) => c.sites));
  // Only a total failure is an error; a partial one is shown as a notice above the table.
  if (settled.every((r) => r.status === 'rejected')) throw settled[0].reason;
  const perNode = calls.map((c, i) => ({
    node: c.node,
    sites: settled[i].status === 'fulfilled' && Array.isArray(settled[i].value) ? settled[i].value : null,
  }));
  const loads = Promise.all(calls.map((c) => c.load)).then((list) => Object.fromEntries(calls.map((c, i) => [c.node, list[i]])));
  return { ...groupSites(perNode), loads };
}

function render({ rows, nodes, unreachable, loads }, setSubtitle) {
  setSubtitle(subtitleFor(rows.length, nodes.length));
  const key = (node, id) => `${node}/${id}`;
  // Health detail and the load series come per site and only when its row is on screen; the caches survive redraws
  const details = new Map();
  const seriesAsked = new Set();
  const series = new Map();
  let loadMap = null;
  let scope = SCOPE_ALL;
  let observer = null;
  // What the current table drew, so late answers can update a row without redrawing it
  const cells = new Map();

  const nodeStatuses = (row) => row.nodes.map((entry) => {
    const d = details.get(key(entry.node, row.id));
    return { node: entry.node, ...nodeStatus(entry.site, d && d.detail, { unreadable: Boolean(d && d.failed) }) };
  });
  const statusOf = (row) => rowStatus(nodeStatuses(row));

  const needle = h('input', { class: 'input search', type: 'search', placeholder: 'Filter sites by name or host', 'aria-label': 'Filter sites' });
  const tableHost = h('div', {});
  const attentionLabel = () => `Needs attention ${rows.filter((r) => needsAttention(statusOf(r))).length}`;
  const scopeBar = segmented({
    label: 'Show sites on',
    value: scope,
    options: [
      { value: SCOPE_ALL, label: 'All nodes' },
      ...(nodes.length > 1 ? nodes.map((n) => ({ value: nodeScope(n), label: n })) : []),
      { value: SCOPE_ATTENTION, label: attentionLabel() },
    ],
    onChange: (value) => {
      scope = value;
      draw();
    },
  });
  const attentionButton = scopeBar.lastElementChild;

  const cellsFor = (row) => {
    if (!cells.has(row.id)) cells.set(row.id, { chips: new Map() });
    return cells.get(row.id);
  };

  const paintChip = (chip, status, node) => {
    const text = chipTitle(node, status);
    chip.title = text;
    chip.setAttribute('aria-label', text);
    chip.firstChild.className = 'dot dot-' + status.health;
  };
  const paintState = (row, cell) => {
    const status = statusOf(row);
    const el = pill(status.label, status.tone, STATE_ICON[status.state] || '');
    if (status.reason) el.title = status.reason;
    cell.replaceChildren(el);
  };
  const paintRate = (row, cell) => {
    const rps = rowRps(row, loadMap);
    cell.textContent = rps === null ? '-' : fmtRps(rps);
    cell.title = rps === null ? 'Load is not available' : 'Requests per second over the last 15 minutes';
  };
  const paintSpark = (row, cell) => {
    const values = series.get(row.id);
    cell.replaceChildren(...(values ? [sparkline(values, { width: 44, height: 18 })] : []));
  };
  const paintRow = (row) => {
    const c = cells.get(row.id);
    if (!c) return;
    const statuses = nodeStatuses(row);
    for (const entry of row.nodes) {
      const chip = c.chips.get(entry.node);
      if (chip) paintChip(chip, statuses.find((s) => s.node === entry.node), entry.node);
    }
    if (c.state) paintState(row, c.state);
  };

  const settle = debounce(() => {
    attentionButton.textContent = attentionLabel();
    // Rows join or leave this view as their health arrives
    if (scope === SCOPE_ATTENTION) draw();
  }, 150);

  const wantDetail = (row) => {
    for (const entry of row.nodes) {
      const k = key(entry.node, row.id);
      if (details.has(k)) continue;
      details.set(k, {});
      nodeApi(entry.node).get('/sites/' + encodeURIComponent(row.id)).then((detail) => {
        details.set(k, { detail });
      }, () => {
        details.set(k, { failed: true });
      }).then(() => {
        paintRow(row);
        settle();
      });
    }
  };
  const wantSeries = (row) => {
    if (seriesAsked.has(row.id)) return;
    seriesAsked.add(row.id);
    Promise.allSettled(row.nodes.map((entry) => nodeApi(entry.node).get('/analytics/timeseries' + qs({ window: '1h', site: row.id })))).then((results) => {
      const lists = results.filter((r) => r.status === 'fulfilled' && r.value && Array.isArray(r.value.points))
        .map((r) => r.value.points.map((p) => p.requests || 0));
      series.set(row.id, mergeSeries(lists));
      const c = cells.get(row.id);
      if (c && c.spark) paintSpark(row, c.spark);
    });
  };
  const wantRow = (row) => {
    wantDetail(row);
    wantSeries(row);
  };

  const columns = [
    {
      label: 'Site',
      render: (r) => h('div', { class: 'cell-stack' },
        h('span', { class: 'site-name' }, h('b', { class: 'cell-strong' }, r.name), r.kind === 'api' ? pill('API', 'muted') : null),
        h('span', { class: 'mono muted' }, r.id)),
    },
    {
      label: 'Hosts',
      render: (r) => h('div', { class: 'host-lines' },
        r.hosts.length ? r.hosts.map((host) => h('span', { class: 'mono host-line', title: host }, host)) : h('span', { class: 'muted' }, '-'),
        r.paths.map((p) => h('span', { class: 'mono muted host-line', title: p }, p))),
    },
    {
      label: 'Nodes',
      render: (r) => {
        const c = cellsFor(r);
        const statuses = nodeStatuses(r);
        return h('div', { class: 'node-chips' }, r.nodes.map((entry) => {
          const chip = h('a', { class: 'node-chip', href: siteHref(entry.node, r.id) }, h('span', { 'aria-hidden': 'true' }), h('span', { class: 'mono' }, entry.node));
          c.chips.set(entry.node, chip);
          paintChip(chip, statuses.find((s) => s.node === entry.node), entry.node);
          return chip;
        }));
      },
    },
    {
      label: 'Load',
      render: (r) => {
        const c = cellsFor(r);
        c.spark = h('span', { class: 'load-spark' });
        c.rate = h('span', { class: 'mono load-rate' });
        paintSpark(r, c.spark);
        paintRate(r, c.rate);
        return h('div', { class: 'load-cell' }, c.spark, c.rate);
      },
    },
    {
      label: 'State',
      render: (r) => {
        const c = cellsFor(r);
        c.state = h('span', { class: 'state-cell' });
        paintState(r, c.state);
        return c.state;
      },
    },
  ];

  const emptyFor = (query) => {
    if (!rows.length) {
      return emptyState({
        iconName: 'globe',
        title: 'No sites yet',
        text: 'Create a site to route a host to a blue/green pair of upstreams.',
        action: h('a', { class: 'btn btn-primary', href: '#/sites/new' }, 'Create site'),
      });
    }
    if (scope === SCOPE_ATTENTION && !query) {
      return emptyState({ iconName: 'check', title: 'Nothing needs attention', text: 'Every site is serving.' });
    }
    return emptyState({ iconName: 'search', title: 'No sites match', text: 'Try a different name or host.' });
  };

  function watch(shown) {
    if (observer) observer.disconnect();
    observer = null;
    // The attention view has to know every site's health to decide who belongs in it
    if (scope === SCOPE_ATTENTION) rows.forEach(wantDetail);
    if (typeof IntersectionObserver === 'undefined') {
      shown.forEach(wantRow);
      return;
    }
    const trs = Array.from(tableHost.querySelectorAll('tbody tr'));
    const byRow = new Map(trs.map((tr, i) => [tr, shown[i]]));
    observer = new IntersectionObserver((entries) => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        observer.unobserve(entry.target);
        const row = byRow.get(entry.target);
        if (row) wantRow(row);
      }
    }, { rootMargin: '240px' });
    trs.forEach((tr) => observer.observe(tr));
  }

  function draw() {
    const query = needle.value.trim();
    const shown = filterRows(scopeRows(rows, scope, statusOf), query);
    cells.clear();
    clear(tableHost);
    tableHost.appendChild(dataTable({
      columns,
      rows: shown,
      onRowClick: (r) => { location.hash = siteHref(homeNode(r, scope), r.id); },
      rowLabel: (r) => 'Open site ' + r.name,
      empty: emptyFor(query),
    }));
    watch(shown);
  }
  needle.addEventListener('input', debounce(draw, 120));
  draw();

  loads.then((map) => {
    loadMap = map;
    for (const row of rows) {
      const c = cells.get(row.id);
      if (c && c.rate) paintRate(row, c.rate);
    }
  });

  return h('div', { class: 'stack' },
    unreachable.length
      ? h('p', { class: 'notice warn' }, icon('alert'),
        `Could not reach ${unreachable.join(', ')}. ${unreachable.length > 1 ? 'Their' : 'Its'} sites are not listed.`)
      : null,
    rows.length ? h('div', { class: 'sites-bar' }, scopeBar, needle) : null,
    card({ flush: true, body: tableHost }));
}

export function sitesView(ctx) {
  ctx.setCrumbs([{ label: 'Sites' }]);
  const create = h('a', { class: 'btn btn-primary', href: '#/sites/new' }, icon('plus'), h('span', {}, 'Create site'));
  const topology = h('a', { class: 'btn', href: '#/topology' }, icon('layers'), h('span', {}, 'Topology'));
  const body = h('div', {});
  let reload = null;
  const head = pageHeader({
    title: 'Sites',
    subtitle: 'Loading sites',
    actions: [button('', { iconName: 'refresh', title: 'Refresh', onClick: () => reload && reload() }), topology, create],
  });
  const sub = head.querySelector('.page-sub');
  const setSubtitle = (text) => {
    if (sub) sub.textContent = text;
  };
  ctx.root.append(head, body);
  if (!state.nodes.length) {
    setSubtitle('No nodes connected');
    body.appendChild(noNodes());
    return;
  }
  reload = loadInto(body, async () => {
    setSubtitle('Loading sites');
    try {
      return await loadSites();
    } catch (err) {
      setSubtitle('Could not load sites');
      throw err;
    }
  }, (data) => render(data, setSubtitle), { skeleton: () => skeletonRows(5) });
}
