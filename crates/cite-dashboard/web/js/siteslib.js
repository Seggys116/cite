// Pure helpers for the Sites page: one row per site id across nodes, its state, and the scope filters.
import { failureNote, latestFailure } from './historylib.js';
import { pathLabel } from './topologylib.js';

export const SCOPE_ALL = 'all';
export const SCOPE_ATTENTION = 'attention';
export const nodeScope = (name) => `node:${name}`;

export const STATE_LABEL = {
  serving: 'Serving', attention: 'Needs attention', failed: 'Deploy failed', maintenance: 'Maintenance',
};
export const STATE_TONE = {
  serving: 'ok', attention: 'bad', failed: 'bad', maintenance: 'warn',
};
// Worst first, so a site shows the most serious thing any node reports
const RANK = {
  attention: 0, failed: 1, maintenance: 2, serving: 3,
};

// One site as one node reports it. detail is the per-site call (it carries live target health); without it only the list data is used.
// health is the dot colour: ok, warn (serving but not as intended) or bad (targets failing).
export function nodeStatus(site, detail, { unreadable = false } = {}) {
  const source = detail || site;
  if (source.maintenance && source.maintenance.enabled) {
    return { state: 'maintenance', health: 'warn', reason: 'Maintenance page is being served' };
  }
  if (detail) {
    const targets = failureNote({ active: detail.active, live: detail.live });
    if (targets) return { state: 'attention', health: 'bad', reason: targets };
  }
  if (latestFailure(source.history)) {
    return { state: 'failed', health: 'warn', reason: failureNote({ history: source.history }) };
  }
  if (unreadable) return { state: 'serving', health: 'warn', reason: 'Live health could not be read' };
  return { state: 'serving', health: 'ok', reason: '' };
}

// statuses: [{ node, state, health, reason }], one per node that has the site
export function rowStatus(statuses) {
  let worst = null;
  for (const s of statuses) {
    if (!worst || RANK[s.state] < RANK[worst.state]) worst = s;
  }
  if (!worst) return { state: 'serving', label: STATE_LABEL.serving, tone: STATE_TONE.serving, reason: '' };
  const reason = worst.reason && statuses.length > 1 ? `${worst.node}: ${worst.reason}` : worst.reason;
  return {
    state: worst.state, label: STATE_LABEL[worst.state], tone: STATE_TONE[worst.state], reason,
  };
}

export const needsAttention = (status) => status.state === 'attention' || status.state === 'failed';

// The sentence a node chip shows on hover
export function chipTitle(node, status) {
  if (status.state === 'serving' && status.health === 'ok') return `${node}: healthy`;
  return `${node}: ${status.reason || status.label || status.state}`;
}

// perNode: [{ node, sites }] where sites is null when that node could not be read.
// Returns { rows, nodes, unreachable }: a row per site id with the node entries that carry it, in node order.
export function groupSites(perNode) {
  const rows = new Map();
  const nodes = [];
  const unreachable = [];
  for (const entry of perNode) {
    if (!Array.isArray(entry.sites)) {
      unreachable.push(entry.node);
      continue;
    }
    nodes.push(entry.node);
    for (const site of entry.sites) {
      if (!rows.has(site.id)) {
        rows.set(site.id, {
          id: site.id, name: site.name, kind: site.kind || 'site', hosts: [], paths: [], nodes: [],
        });
      }
      const row = rows.get(site.id);
      row.nodes.push({ node: entry.node, site });
      if (site.kind === 'api') row.kind = 'api';
      for (const host of site.hosts || []) {
        if (!row.hosts.includes(host)) row.hosts.push(host);
      }
      const label = pathLabel(site);
      if (label !== 'any path' && !row.paths.includes(label)) row.paths.push(label);
    }
  }
  const list = Array.from(rows.values()).sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
  return { rows: list, nodes, unreachable };
}

// statusOf: row -> rowStatus(...), so the caller decides which details it already has
export function scopeRows(rows, scope, statusOf) {
  if (scope === SCOPE_ATTENTION) return rows.filter((r) => needsAttention(statusOf(r)));
  if (typeof scope === 'string' && scope.startsWith('node:')) {
    const name = scope.slice(5);
    return rows.filter((r) => r.nodes.some((n) => n.node === name));
  }
  return rows;
}

export function filterRows(rows, query) {
  const q = String(query || '').trim().toLowerCase();
  if (!q) return rows;
  return rows.filter((r) => r.name.toLowerCase().includes(q) || r.id.toLowerCase().includes(q) || r.hosts.some((h) => h.toLowerCase().includes(q)));
}

// The node whose detail page a row opens: the scoped node when one is picked, else the first that has the site
export function homeNode(row, scope) {
  if (typeof scope === 'string' && scope.startsWith('node:')) {
    const name = scope.slice(5);
    if (row.nodes.some((n) => n.node === name)) return name;
  }
  return row.nodes[0].node;
}

// loads: { [node]: { [siteId]: requests per second } | null }. Null when no node reported a figure for the site.
export function rowRps(row, loads) {
  let total = null;
  for (const n of row.nodes) {
    const map = loads && loads[n.node];
    if (!map) continue;
    total = (total || 0) + (Number(map[row.id]) || 0);
  }
  return total;
}

// Adds request series from several nodes point by point, aligned on the newest end
export function mergeSeries(list) {
  const series = list.filter((s) => Array.isArray(s) && s.length);
  const length = series.reduce((m, s) => Math.max(m, s.length), 0);
  const out = new Array(length).fill(0);
  for (const s of series) {
    const offset = length - s.length;
    s.forEach((v, i) => { out[offset + i] += Number(v) || 0; });
  }
  return out;
}

// "4 across 2 nodes"
export function subtitleFor(siteCount, nodeCount) {
  return `${siteCount} across ${nodeCount} node${nodeCount === 1 ? '' : 's'}`;
}
