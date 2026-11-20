// Builds the topology graph: entries (host plus path match) -> nodes -> sites, with load on every link.
// Pure data in, plain graph out, so the dashboard draws it with SVG and the tests can check it without a browser.

export const LOAD_WINDOW_SECS = 15 * 60;

// /analytics/facets answers { site: [{key, count}] } for a window; requests per second per site id
export function loadFromFacets(facets, windowSecs = LOAD_WINDOW_SECS) {
  const out = {};
  const list = facets && Array.isArray(facets.site) ? facets.site : [];
  for (const item of list) {
    if (!item || typeof item.key !== 'string') continue;
    const count = Number(item.count);
    if (Number.isFinite(count) && count >= 0) out[item.key] = count / windowSecs;
  }
  return out;
}

// What a request path has to look like to reach a site, in the words the person used
export function pathLabel(site) {
  const prefixes = Array.isArray(site.path_prefixes) ? site.path_prefixes : [];
  const regexes = Array.isArray(site.path_regexes) ? site.path_regexes : [];
  if (!prefixes.length && !regexes.length) return 'any path';
  return [...prefixes, ...regexes.map((r) => `~ ${r}`)].join('  ');
}

function siteState(site) {
  const m = site.maintenance || {};
  if (m.enabled) return 'maintenance';
  if (site.last_deploy_failed || (site.status && String(site.status).toLowerCase().includes('fail'))) return 'failed';
  return 'serving';
}

// nodes: [{ name, online, sites, load }] where sites is null when unreadable and load maps site id to requests per second (or is null).
export function buildTopology(nodes) {
  const entries = new Map();
  const sites = new Map();
  const nodeOut = [];
  const links = [];

  for (const node of nodes) {
    const list = Array.isArray(node.sites) ? node.sites : [];
    const load = node.load || {};
    let nodeRps = 0;
    for (const site of list) {
      const rps = Number(load[site.id]) || 0;
      nodeRps += rps;
      if (!sites.has(site.id)) {
        sites.set(site.id, {
          id: site.id, name: site.name, kind: site.kind || 'site', active: site.active || null, runtime: (site.source && site.source.runtime) || null,
          state: siteState(site), rps: 0, nodes: [],
        });
      }
      const s = sites.get(site.id);
      s.rps += rps;
      s.nodes.push(node.name);
      // A failure or maintenance on any node shows on the site, worst first
      const rank = { serving: 0, failed: 1, maintenance: 2 };
      const state = siteState(site);
      if (rank[state] > rank[s.state]) s.state = state;
      for (const host of site.hosts || []) {
        const key = `${host}|${pathLabel(site)}|${site.id}`;
        if (!entries.has(key)) entries.set(key, { id: key, host, path: pathLabel(site), siteId: site.id });
        const standby = node.online === false || rps === 0;
        links.push({ from: key, via: node.name, to: site.id, rps, standby });
      }
    }
    nodeOut.push({ name: node.name, online: node.online !== false, readable: Array.isArray(node.sites), rps: nodeRps, siteCount: list.length });
  }

  // One link per entry and node, so a host listed on two sites is not counted twice
  const merged = new Map();
  for (const l of links) {
    const key = `${l.from}>${l.via}>${l.to}`;
    if (!merged.has(key)) merged.set(key, l);
  }
  const all = Array.from(merged.values());
  const peak = all.reduce((m, l) => Math.max(m, l.rps), 0);
  return {
    entries: Array.from(entries.values()).sort((a, b) => a.host.localeCompare(b.host) || a.path.localeCompare(b.path)),
    nodes: nodeOut,
    sites: Array.from(sites.values()).sort((a, b) => a.name.localeCompare(b.name)),
    links: all,
    peak,
  };
}

// Line width in pixels for a link: idle links stay visible, the busiest gets the thickest line
export function lineWidth(rps, peak, min = 1.5, max = 8) {
  if (!(peak > 0) || !(rps > 0)) return min;
  return min + (max - min) * Math.sqrt(Math.min(rps / peak, 1));
}

export function fmtRps(rps) {
  if (!(rps > 0)) return '0/s';
  if (rps < 10) return `${rps.toFixed(1)}/s`;
  return `${Math.round(rps)}/s`;
}

// The links that pass through a node, for dimming everything else when a node is picked
export function linksThrough(graph, nodeName) {
  return graph.links.filter((l) => l.via === nodeName);
}

// Shortens text for a fixed-width box; the full text belongs in a tooltip
export function clip(text, max) {
  const s = String(text);
  return s.length <= max ? s : `${s.slice(0, Math.max(1, max - 1))}…`;
}

const capital = (s) => (s ? s.charAt(0).toUpperCase() + s.slice(1) : s);

// What a site is, in the box's second line: the runtime for a built site, "one endpoint" for an API
export function siteKindLabel(site) {
  const runtime = capital(site.runtime || '');
  if (site.kind === 'api') return runtime ? `${runtime}, one endpoint` : 'API';
  return runtime ? `${runtime} site` : 'Site';
}

export const VIEW_WIDTH = 696;
export const COLUMNS = {
  entry: { x: 8, w: 162, h: 46 },
  node: { x: 288, w: 116, h: 58 },
  site: { x: 516, w: 172, h: 74 },
};
const ROW_GAP = 14;
const PAD_Y = 12;
const CURVE = 60;

// Even anchor points down a box edge so several links do not pile onto one spot
const anchor = (box, index, count) => box.y + (box.h * (index + 1)) / (count + 1);

function curve(x1, y1, x2, y2) {
  const r = (n) => Math.round(n * 10) / 10;
  return `M${r(x1)},${r(y1)} C${r(x1 + CURVE)},${r(y1)} ${r(x2 - CURVE)},${r(y2)} ${r(x2)},${r(y2)}`;
}

// Turns the graph into drawable geometry: boxes in three columns and a bezier path per link.
// Pure so the drawing code only has to put elements where this says.
export function layoutTopology(graph) {
  const counts = [graph.entries.length, graph.nodes.length, graph.sites.length];
  const heights = [COLUMNS.entry.h, COLUMNS.node.h, COLUMNS.site.h];
  const colHeight = (i) => (counts[i] ? counts[i] * heights[i] + (counts[i] - 1) * ROW_GAP : 0);
  const inner = Math.max(colHeight(0), colHeight(1), colHeight(2));
  const place = (items, col, i, key) => {
    const top = PAD_Y + (inner - colHeight(i)) / 2;
    return items.map((item, n) => ({ ...key(item), x: col.x, w: col.w, h: col.h, y: top + n * (col.h + ROW_GAP) }));
  };
  const entries = place(graph.entries, COLUMNS.entry, 0, (e) => ({ id: e.id, host: e.host, path: e.path, siteId: e.siteId }));
  const nodes = place(graph.nodes, COLUMNS.node, 1, (n) => ({ id: n.name, name: n.name }));
  const sites = place(graph.sites, COLUMNS.site, 2, (s) => ({ id: s.id }));
  const entryAt = new Map(entries.map((b) => [b.id, b]));
  const nodeAt = new Map(nodes.map((b) => [b.name, b]));
  const siteAt = new Map(sites.map((b) => [b.id, b]));
  const entryRank = new Map(entries.map((b, i) => [b.id, i]));
  const nodeRank = new Map(nodes.map((b, i) => [b.name, i]));
  const siteRank = new Map(sites.map((b, i) => [b.id, i]));

  const inLinks = graph.links.filter((l) => entryAt.has(l.from) && nodeAt.has(l.via));
  const outMap = new Map();
  for (const l of graph.links) {
    const key = `${l.via}>${l.to}`;
    if (!outMap.has(key) && nodeAt.has(l.via) && siteAt.has(l.to)) outMap.set(key, l);
  }
  const outLinks = Array.from(outMap.values());

  // Order the anchors by where the other end sits, so links fan out without crossing at the box
  const slot = (list, boxKey, otherRank) => {
    const groups = new Map();
    for (const l of list) {
      const k = l[boxKey];
      if (!groups.has(k)) groups.set(k, []);
      groups.get(k).push(l);
    }
    const out = new Map();
    for (const members of groups.values()) {
      members.sort((a, b) => otherRank(a) - otherRank(b));
      members.forEach((l, i) => out.set(l, { index: i, count: members.length }));
    }
    return out;
  };
  const inAtNode = slot(inLinks, 'via', (l) => entryRank.get(l.from));
  const outAtNode = slot(outLinks, 'via', (l) => siteRank.get(l.to));
  const inAtSite = slot(outLinks, 'to', (l) => nodeRank.get(l.via));

  const links = [];
  for (const l of inLinks) {
    const from = entryAt.get(l.from);
    const to = nodeAt.get(l.via);
    const s = inAtNode.get(l);
    const x1 = from.x + from.w;
    const y1 = from.y + from.h / 2;
    const x2 = to.x;
    const y2 = anchor(to, s.index, s.count);
    links.push({ id: `in:${l.from}>${l.via}`, stage: 'in', via: l.via, entryId: l.from, siteId: l.to, rps: l.rps, standby: l.standby, d: curve(x1, y1, x2, y2) });
  }
  for (const l of outLinks) {
    const from = nodeAt.get(l.via);
    const to = siteAt.get(l.to);
    const a = outAtNode.get(l);
    const b = inAtSite.get(l);
    links.push({
      id: `out:${l.via}>${l.to}`, stage: 'out', via: l.via, entryId: null, siteId: l.to, rps: l.rps, standby: l.standby,
      d: curve(from.x + from.w, anchor(from, a.index, a.count), to.x, anchor(to, b.index, b.count)),
    });
  }
  for (const l of links) {
    l.width = lineWidth(l.rps, graph.peak);
    l.busiest = graph.peak > 0 && l.rps === graph.peak;
  }
  return { width: VIEW_WIDTH, height: inner + PAD_Y * 2, entries, nodes, sites, links };
}

// Changes only when boxes or links come or go, so a refresh that moves numbers can update in place
export function shapeKey(graph) {
  return JSON.stringify([
    graph.entries.map((e) => e.id),
    graph.nodes.map((n) => [n.name, n.online]),
    graph.sites.map((s) => s.id),
    graph.links.map((l) => `${l.from}>${l.via}>${l.to}`),
  ]);
}
