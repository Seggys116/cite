// Maintenance pages as one library across nodes, and the site by node maintenance matrix.
// Each node still stores its own copy, so a node keeps serving when the console is offline. These helpers only compare the copies and plan the writes.

function variantKey(page) {
  return JSON.stringify([page.name, Number(page.status), page.html]);
}

function pick(page) {
  return { id: page.id, name: page.name, status: Number(page.status), html: page.html };
}

// perNode: [{ node, pages }] where pages is null when the node could not be read.
// A node that could not be read is never reported as missing a page, so an outage cannot trigger writes.
export function unionPages(perNode) {
  const readable = perNode.filter((n) => Array.isArray(n.pages));
  const unreadable = perNode.filter((n) => !Array.isArray(n.pages)).map((n) => n.node);
  const byId = new Map();
  for (const entry of readable) {
    for (const page of entry.pages) {
      if (!byId.has(page.id)) byId.set(page.id, []);
      byId.get(page.id).push({ node: entry.node, page });
    }
  }
  const pages = [];
  for (const [id, holders] of byId) {
    const groups = new Map();
    for (const h of holders) {
      const key = variantKey(h.page);
      if (!groups.has(key)) groups.set(key, { page: h.page, nodes: [] });
      groups.get(key).nodes.push(h.node);
    }
    // The version held by most nodes wins; a tie goes to the node listed first
    const variants = Array.from(groups.values()).sort((a, b) => b.nodes.length - a.nodes.length
      || readable.findIndex((n) => n.node === a.nodes[0]) - readable.findIndex((n) => n.node === b.nodes[0]));
    const canonical = variants[0];
    const present = holders.map((h) => h.node);
    pages.push({
      ...pick(canonical.page),
      id,
      nodes: present,
      missing: readable.map((n) => n.node).filter((n) => !present.includes(n)),
      drift: variants.length > 1,
      variants: variants.map((v) => ({ ...pick(v.page), nodes: v.nodes })),
    });
  }
  pages.sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
  return { pages, unreadable, nodes: readable.map((n) => n.node) };
}

// Pages to create so every readable node has every page: [{ node, page }]
export function missingPlan(union) {
  const plan = [];
  for (const page of union.pages) {
    for (const node of page.missing) plan.push({ node, page: pick(page) });
  }
  return plan;
}

// Nodes that hold a different version of a page than the winning one: [{ node, page }]
export function driftPlan(union) {
  const plan = [];
  for (const page of union.pages) {
    if (!page.drift) continue;
    for (const v of page.variants.slice(1)) {
      for (const node of v.nodes) plan.push({ node, page: pick(page) });
    }
  }
  return plan;
}

// One short line for the page header: in sync, or what is missing where
export function syncSummary(union) {
  const missing = missingPlan(union);
  const drift = driftPlan(union);
  const parts = [];
  if (missing.length) {
    const perNode = new Map();
    for (const m of missing) perNode.set(m.node, (perNode.get(m.node) || 0) + 1);
    for (const [node, n] of perNode) parts.push(`${node} is missing ${n} page${n === 1 ? '' : 's'}`);
  }
  if (drift.length) parts.push(`${drift.length} cop${drift.length === 1 ? 'y differs' : 'ies differ'} between nodes`);
  if (union.unreadable.length) parts.push(`${union.unreadable.join(', ')} could not be read`);
  return { inSync: !missing.length && !drift.length && !union.unreadable.length, text: parts.length ? parts.join('. ') : 'In sync on every node' };
}

// How to write one page to the nodes that can take it: PUT where the node already holds the id, POST where it does not
export function savePlan(union, pageId, nodes) {
  const entry = union.pages.find((p) => p.id === pageId);
  const held = entry ? entry.nodes : [];
  return nodes.map((node) => ({ node, method: held.includes(node) ? 'put' : 'post' }));
}

// One line per node before a save: what the save does there, and a warning where it replaces a copy that differs.
// plan is the result of savePlan; name is the name being saved.
export function saveConfirmLines(union, pageId, plan, name) {
  const entry = union.pages.find((p) => p.id === pageId);
  const differing = new Set(entry ? entry.variants.slice(1).flatMap((v) => v.nodes) : []);
  return plan.map(({ node, method }) => {
    if (method !== 'put') return `${node}: add ${name}`;
    return differing.has(node)
      ? `${node}: update ${name} (its copy differs and will be replaced)`
      : `${node}: update ${name}`;
  });
}

// One line per node for a confirm dialog: "edge-nyc: add Scheduled, Incident; update Sale"
export function planLines(missing, drift) {
  const perNode = new Map();
  const note = (node, key, page) => {
    if (!perNode.has(node)) perNode.set(node, { add: [], update: [] });
    perNode.get(node)[key].push(page.name);
  };
  for (const m of missing) note(m.node, 'add', m.page);
  for (const d of drift) note(d.node, 'update', d.page);
  return Array.from(perNode, ([node, change]) => {
    const parts = [];
    if (change.add.length) parts.push(`add ${change.add.join(', ')}`);
    if (change.update.length) parts.push(`update ${change.update.join(', ')}`);
    return `${node}: ${parts.join('; ')}`;
  });
}

// A toast line for Drain or Restore on one node. results are applyToNodes results whose `node` field holds a site id.
// "Maintenance on for Shop, Docs on edge-nyc. Failed for Blog: <reason>"
export function bulkMessage(state, node, rows, results, describe = (e) => (e && e.message) || String(e)) {
  const name = (id) => (rows.find((r) => r.id === id) || { name: id }).name;
  const parts = [];
  const ok = results.filter((r) => r.ok).map((r) => name(r.node));
  if (ok.length) parts.push(`Maintenance ${state} for ${ok.join(', ')} on ${node}`);
  for (const r of results.filter((x) => !x.ok)) parts.push(`Failed for ${name(r.node)}: ${describe(r.error)}`);
  return parts.join('. ');
}

// perNode: [{ node, online, sites }] where sites is null when unreadable.
// Returns { nodes, rows } with one row per site id and one cell per node.
export function siteMatrix(perNode) {
  const nodes = perNode.map((n) => ({ name: n.node, online: n.online !== false, readable: Array.isArray(n.sites) }));
  const rows = new Map();
  for (const entry of perNode) {
    for (const site of entry.sites || []) {
      if (!rows.has(site.id)) rows.set(site.id, { id: site.id, name: site.name, cells: {} });
      const m = site.maintenance || {};
      rows.get(site.id).cells[entry.node] = { present: true, enabled: Boolean(m.enabled), pageId: m.page_id || null };
    }
  }
  const list = Array.from(rows.values()).sort((a, b) => a.name.localeCompare(b.name));
  for (const row of list) {
    for (const n of nodes) {
      if (!row.cells[n.name]) row.cells[n.name] = { present: false, enabled: false, pageId: null };
    }
  }
  return { nodes, rows: list };
}

// The page a row uses: the one every node that sets a page agrees on, else the first one found
export function rowPage(row) {
  const ids = Object.values(row.cells).map((c) => c.pageId).filter(Boolean);
  return ids.length ? ids[0] : null;
}

// Site ids on a node that are not in maintenance yet
export function drainPlan(matrix, node) {
  return matrix.rows.filter((r) => r.cells[node] && r.cells[node].present && !r.cells[node].enabled).map((r) => r.id);
}

// Site ids on a node that are in maintenance now
export function restorePlan(matrix, node) {
  return matrix.rows.filter((r) => r.cells[node] && r.cells[node].present && r.cells[node].enabled).map((r) => r.id);
}

// A node cannot serve a maintenance page it does not hold: the nodes that need the page created first
export function nodesNeedingPage(union, pageId, nodes) {
  const entry = union.pages.find((p) => p.id === pageId);
  if (!entry) return [];
  return nodes.filter((n) => union.nodes.includes(n) && entry.missing.includes(n));
}
