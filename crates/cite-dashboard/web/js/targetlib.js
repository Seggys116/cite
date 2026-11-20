// Which nodes a write lands on. A write is never sent to a node the person did not pick: "All nodes" selects nothing by itself.

const ALL = 'all';

export function isAllScope(scope) {
  return scope === undefined || scope === null || scope === '' || scope === ALL;
}

function names(nodes) {
  return (nodes || []).map((n) => n.name);
}

// The nodes ticked when a picker first opens. A single selected node is the target; "All nodes" starts with nothing ticked.
export function initialTargets(scope, nodes) {
  if (isAllScope(scope)) return [];
  return names(nodes).includes(scope) ? [scope] : [];
}

export function toggleTarget(selected, name) {
  return selected.includes(name) ? selected.filter((n) => n !== name) : [...selected, name];
}

// Keeps node order and drops names that are not configured, so a stale selection cannot name a node that was removed.
export function normalizeTargets(selected, nodes) {
  const wanted = new Set(selected || []);
  return names(nodes).filter((n) => wanted.has(n));
}

export function canConfirm(selected, nodes) {
  return normalizeTargets(selected, nodes).length > 0;
}

export function offlineTargets(selected, nodes) {
  const picked = new Set(selected || []);
  return (nodes || []).filter((n) => picked.has(n.name) && !n.online).map((n) => n.name);
}

export function notTargeted(selected, nodes) {
  const picked = new Set(selected || []);
  return names(nodes).filter((n) => !picked.has(n));
}

// "edge-nyc", "2 nodes: edge-fra, edge-nyc" or "No node selected"
export function targetSummary(selected, nodes) {
  const list = normalizeTargets(selected, nodes);
  if (!list.length) return 'No node selected';
  if (list.length === 1) return list[0];
  return `${list.length} nodes: ${list.join(', ')}`;
}

// The confirm button names where the change lands: "Turn on for edge-nyc", "Turn on for 2 nodes"
export function confirmLabel(verb, selected, nodes) {
  const list = normalizeTargets(selected, nodes);
  if (!list.length) return verb;
  if (list.length === 1) return `${verb} for ${list[0]}`;
  return `${verb} for ${list.length} nodes`;
}

// Runs fn(node) on every target at once and never throws: each result says which node succeeded or failed and why.
export async function applyToNodes(targets, fn) {
  const settled = await Promise.allSettled(targets.map((node) => Promise.resolve().then(() => fn(node))));
  return settled.map((res, i) => (res.status === 'fulfilled'
    ? { node: targets[i], ok: true, value: res.value }
    : { node: targets[i], ok: false, error: res.reason }));
}

// A toast line for a fan-out: "Added on edge-nyc" or "Added on edge-fra. Failed on edge-nyc: <reason>"
export function resultMessage(done, results, describe = (e) => (e && e.message) || String(e)) {
  const ok = results.filter((r) => r.ok).map((r) => r.node);
  const bad = results.filter((r) => !r.ok);
  const parts = [];
  if (ok.length) parts.push(`${done} on ${ok.join(', ')}`);
  for (const r of bad) parts.push(`Failed on ${r.node}: ${describe(r.error)}`);
  return parts.join('. ');
}

// Toast kinds the console styles are success, info and error; any failure is shown as an error so it is not missed.
export function resultKind(results) {
  return results.every((r) => r.ok) ? 'success' : 'error';
}
