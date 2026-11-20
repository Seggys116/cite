import { h, s, icon } from '../dom.js';
import { nodeApi, qs } from '../api.js';
import { state } from '../state.js';
import {
  pageHeader, button, emptyState, errorState, skeletonBlock,
} from '../ui.js';
import { createPoller } from '../poller.js';
import { latestFailure } from '../historylib.js';
import {
  buildTopology, clip, fmtRps, layoutTopology, linksThrough, loadFromFacets, shapeKey, siteKindLabel,
} from '../topologylib.js';
import { noNodes, siteHref } from './common.js';

const REFRESH_MS = 10000;
const SITE_STATE = { serving: ['Serving', 'ok'], failed: ['Deploy failed', 'bad'], maintenance: ['Maintenance', 'warn'] };
const spoken = (rps) => fmtRps(rps).replace('/s', ' requests per second');

// The list answers history but not a failed flag, so derive it the way the Sites page does
const withFailure = (site) => ({ ...site, last_deploy_failed: Boolean(latestFailure(site.history)) });

// One call for the sites and one for the load of every site, for every node at once. A node that cannot be read is
// kept as offline, so it still shows on the chart.
async function loadNodes() {
  return Promise.all(state.nodes.map(async (n) => {
    if (n.online === false) return { name: n.name, online: false, sites: null, load: null };
    const api = nodeApi(n.name);
    const [sites, facets] = await Promise.allSettled([api.get('/sites'), api.get('/analytics/facets' + qs({ window: '15m' }))]);
    const list = sites.status === 'fulfilled' && Array.isArray(sites.value) ? sites.value.map(withFailure) : null;
    return { name: n.name, online: list !== null, sites: list, load: facets.status === 'fulfilled' ? loadFromFacets(facets.value) : null };
  }));
}

const marker = (id, cls) => s('marker', {
  id, viewBox: '0 0 8 8', refX: 7, refY: 4, markerWidth: 8, markerHeight: 8, markerUnits: 'userSpaceOnUse', orient: 'auto',
}, s('path', { d: 'M0,0 L8,4 L0,8z', class: 'topo-arrow ' + cls }));

function legend() {
  const item = (cls, text) => h('span', { class: 'topo-legend-item' }, h('i', { class: 'topo-swatch ' + cls, 'aria-hidden': 'true' }), text);
  return h('p', { class: 'topo-legend' },
    item('busiest', 'Busiest path'),
    item('wide', 'Width follows requests per second'),
    item('standby', 'Dashed: failover or no traffic now'));
}

// Draws the graph and keeps it. A refresh that only moves numbers updates attributes on the same elements; the
// elements are rebuilt only when a box or a link comes or goes, so nothing flickers between polls.
function createChart() {
  const scroll = h('div', { class: 'topo-scroll' });
  const el = h('div', { class: 'topo-chart' }, scroll, legend());
  let svg = null;
  let refs = null;
  let shape = '';
  let current = null;
  let picked = null;

  const open = (siteId) => {
    const site = current && current.graph.sites.find((x) => x.id === siteId);
    if (site && site.nodes.length) location.hash = siteHref(site.nodes[0], siteId);
  };
  const pick = (name) => {
    picked = picked === name ? null : name;
    applyPick();
  };

  function applyPick() {
    if (!current) return;
    const { graph } = current;
    if (picked && !graph.nodes.some((n) => n.name === picked)) picked = null;
    const through = picked ? linksThrough(graph, picked) : null;
    const entryOn = new Set(through ? through.map((l) => l.from) : []);
    const siteOn = new Set(through ? through.map((l) => l.to) : []);
    for (const [id, ref] of refs.entries) ref.g.classList.toggle('dim', Boolean(picked) && !entryOn.has(id));
    for (const [id, ref] of refs.sites) ref.g.classList.toggle('dim', Boolean(picked) && !siteOn.has(id));
    for (const [name, ref] of refs.nodes) {
      ref.g.classList.toggle('dim', Boolean(picked) && name !== picked);
      ref.g.classList.toggle('picked', name === picked);
      ref.g.setAttribute('aria-pressed', String(name === picked));
    }
    for (const l of current.layout.links) refs.links.get(l.id).classList.toggle('dim', Boolean(picked) && l.via !== picked);
  }

  function activate(box) {
    const kind = box.getAttribute('data-kind');
    const id = box.getAttribute('data-id');
    if (kind === 'node') pick(id);
    else if (kind === 'site') open(id);
    else if (kind === 'entry') {
      const entry = current.layout.entries.find((e) => e.id === id);
      if (entry) open(entry.siteId);
    }
  }

  function build(graph, layout) {
    const links = new Map();
    const linkLayer = s('g', { class: 'topo-links' });
    for (const l of layout.links) {
      const path = s('path', { class: 'topo-link', d: l.d, fill: 'none' });
      links.set(l.id, path);
      linkLayer.appendChild(path);
    }
    const boxLayer = s('g', { class: 'topo-boxes' });
    const make = (kind, id, b, role, label) => {
      const g = s('g', {
        class: `topo-box topo-${kind}`, tabindex: '0', role, 'data-kind': kind, 'data-id': id,
      }, s('title', {}, label), s('rect', {
        class: 'topo-rect', x: b.x, y: b.y, width: b.w, height: b.h, rx: 14,
      }));
      boxLayer.appendChild(g);
      return g;
    };
    const text = (g, cls, x, y, value, anchor) => {
      const t = s('text', { class: cls, x, y, 'text-anchor': anchor || null }, value);
      g.appendChild(t);
      return t;
    };

    const entries = new Map();
    for (const b of layout.entries) {
      const g = make('entry', b.id, b, 'link', `${b.host} ${b.path}`);
      text(g, 'topo-host', b.x + 14, b.y + 20, clip(b.host, 18));
      text(g, 'topo-sub topo-mono', b.x + 14, b.y + 37, clip(b.path, 20));
      entries.set(b.id, { g });
    }
    const nodes = new Map();
    for (const b of layout.nodes) {
      const g = make('node', b.name, b, 'button', b.name);
      text(g, 'topo-name', b.x + 14, b.y + 24, clip(b.name, 12));
      const dotEl = s('circle', { class: 'topo-dot', cx: b.x + b.w - 16, cy: b.y + 19, r: 4 });
      g.appendChild(dotEl);
      const status = text(g, 'topo-sub', b.x + 14, b.y + 44, '');
      nodes.set(b.name, { g, dot: dotEl, status });
    }
    const sites = new Map();
    for (const b of layout.sites) {
      const info = graph.sites.find((x) => x.id === b.id);
      const g = make('site', b.id, b, 'link', info.name);
      text(g, 'topo-name', b.x + 14, b.y + 23, clip(info.name, 20));
      text(g, 'topo-sub', b.x + 14, b.y + 40, clip(siteKindLabel(info), 24));
      const rps = text(g, 'topo-sub topo-mono', b.x + 14, b.y + 62, '');
      const pillRect = s('rect', {
        class: 'topo-pill', x: b.x + b.w - 96, y: b.y + 49, width: 84, height: 18, rx: 9,
      });
      g.appendChild(pillRect);
      const pillText = text(g, 'topo-pill-text', b.x + b.w - 54, b.y + 62, '', 'middle');
      sites.set(b.id, { g, rps, pillRect, pillText });
    }

    const next = s('svg', {
      class: 'topo-svg', viewBox: `0 0 ${layout.width} ${layout.height}`, preserveAspectRatio: 'xMidYMin meet', role: 'group', 'aria-label': 'How requests reach each site through the nodes',
    }, s('defs', {}, marker('topo-arrow-faint', 'faint'), marker('topo-arrow-accent', 'accent')), linkLayer, boxLayer);
    next.addEventListener('click', (e) => {
      const box = e.target.closest ? e.target.closest('.topo-box') : null;
      if (box) activate(box);
      else if (picked) pick(picked);
    });
    next.addEventListener('keydown', (e) => {
      const box = e.target.closest ? e.target.closest('.topo-box') : null;
      if (e.key === 'Escape' && picked) {
        pick(picked);
      } else if (box && (e.key === 'Enter' || (e.key === ' ' && box.getAttribute('data-kind') === 'node'))) {
        e.preventDefault();
        activate(box);
      }
    });
    refs = { links, entries, nodes, sites };
    scroll.replaceChildren(next);
    svg = next;
  }

  function paint(graph, layout) {
    for (const l of layout.links) {
      const path = refs.links.get(l.id);
      path.setAttribute('stroke-width', l.width.toFixed(2));
      if (l.standby) path.setAttribute('stroke-dasharray', '6 5');
      else path.removeAttribute('stroke-dasharray');
      path.classList.toggle('busiest', l.busiest);
      path.setAttribute('marker-end', `url(#${l.busiest ? 'topo-arrow-accent' : 'topo-arrow-faint'})`);
    }
    for (const n of graph.nodes) {
      const ref = refs.nodes.get(n.name);
      ref.status.textContent = n.online ? `Healthy · ${fmtRps(n.rps)}` : 'Offline';
      ref.dot.setAttribute('class', 'topo-dot ' + (n.online ? 'ok' : 'bad'));
      ref.g.classList.toggle('offline', !n.online);
      ref.g.setAttribute('aria-label', n.online ? `${n.name}, healthy, ${spoken(n.rps)}` : `${n.name}, offline`);
    }
    for (const site of graph.sites) {
      const ref = refs.sites.get(site.id);
      const [label, tone] = SITE_STATE[site.state] || SITE_STATE.serving;
      ref.rps.textContent = fmtRps(site.rps);
      ref.pillText.textContent = label;
      ref.pillRect.setAttribute('class', 'topo-pill ' + tone);
      ref.g.setAttribute('aria-label', `${site.name}, ${siteKindLabel(site)}, ${label.toLowerCase()}, ${spoken(site.rps)}`);
    }
    for (const e of layout.entries) {
      const site = graph.sites.find((x) => x.id === e.siteId);
      refs.entries.get(e.id).g.setAttribute('aria-label', `${e.host}, ${e.path}, opens ${site ? site.name : e.siteId}`);
    }
  }

  return {
    el,
    update(graph) {
      const layout = layoutTopology(graph);
      const key = shapeKey(graph);
      if (!svg || key !== shape) {
        build(graph, layout);
        shape = key;
      }
      current = { graph, layout };
      paint(graph, layout);
      applyPick();
    },
  };
}

export function topologyView(ctx) {
  ctx.setCrumbs([{ label: 'Topology' }]);
  const stage = h('div', {});
  const notice = h('p', { class: 'notice warn', hidden: true });
  const body = h('div', { class: 'stack' }, notice, stage);
  let poller = null;
  const refresh = button('', { iconName: 'refresh', title: 'Refresh', onClick: () => poller && poller.now() });
  const sitesLink = h('a', { class: 'btn', href: '#/sites' }, icon('globe'), h('span', {}, 'Sites'));
  ctx.root.append(pageHeader({ title: 'Topology', subtitle: 'Hosts, nodes and sites, with live load', actions: [refresh, sitesLink] }), body);
  if (!state.nodes.length) {
    body.replaceChildren(noNodes());
    return undefined;
  }

  const chart = createChart();
  let mode = 'skeleton';
  stage.appendChild(skeletonBlock(320));
  const show = (kind, content) => {
    if (mode === kind && kind === 'chart') return;
    mode = kind;
    stage.replaceChildren(content);
  };

  async function load() {
    let perNode;
    try {
      perNode = await loadNodes();
    } catch (err) {
      if (mode !== 'chart') {
        mode = 'error';
        stage.replaceChildren(errorState(err, () => poller && poller.now()));
      }
      return undefined;
    }
    if (!ctx.root.isConnected) return undefined;
    const graph = buildTopology(perNode);
    const unreachable = perNode.filter((n) => n.sites === null).map((n) => n.name);
    notice.hidden = !unreachable.length;
    notice.replaceChildren(...(unreachable.length ? [icon('alert'), `Could not read ${unreachable.join(', ')}. ${unreachable.length > 1 ? 'They are' : 'It is'} shown as offline.`] : []));
    if (!graph.sites.length) {
      const allDown = unreachable.length === perNode.length;
      show('empty', emptyState({
        iconName: 'layers',
        title: 'No sites to show',
        text: allDown ? 'No node answered, so there is nothing to draw yet.' : 'Create a site to route a host through a node.',
        action: allDown ? null : h('a', { class: 'btn btn-primary', href: '#/sites/new' }, 'Create site'),
      }));
      return graph;
    }
    show('chart', chart.el);
    chart.update(graph);
    return graph;
  }

  // The poller never overlaps two loads and skips its tick while the tab is hidden
  poller = createPoller({ load, delay: () => REFRESH_MS, alive: () => ctx.root.isConnected });
  poller.start();
  return () => poller.stop();
}
