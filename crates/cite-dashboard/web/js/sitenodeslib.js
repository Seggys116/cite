// A site can live on several nodes, and each node stores its own copy. These helpers decide which nodes hold a site and what a shared edit writes to each of them.
import { siteBody } from './sitelib.js';
import { accessForSave } from './accesslib.js';

// Online nodes other than the one a site page belongs to; offline nodes are never asked
export function peerNames(nodes, current) {
  return (nodes || []).filter((n) => n.online !== false && n.name !== current).map((n) => n.name);
}

// peers: [{ node, sites }] where sites is null when the node could not be read.
// The current node always counts because the page was opened from it. The result follows the order of `order`, then any node it does not list.
export function holderNodes(siteId, current, peers, order = []) {
  const held = new Set([current]);
  for (const p of peers || []) {
    if (Array.isArray(p.sites) && p.sites.some((s) => s && s.id === siteId)) held.add(p.node);
  }
  const ordered = order.filter((n) => held.has(n));
  for (const n of held) {
    if (!ordered.includes(n)) ordered.push(n);
  }
  return ordered;
}

const lower = (list) => (Array.isArray(list) ? list : []).map((x) => String(x).toLowerCase());

// Ids default to a slug of the name, so two unrelated sites can share one. Two copies are the same site when their host sets overlap
// or they build from the same repository; otherwise a shared edit would overwrite an unrelated site.
export function siteRelation(current, other) {
  const mine = new Set(lower(current && current.hosts));
  if (lower(other && other.hosts).some((x) => mine.has(x))) return 'same';
  const a = current && current.source && current.source.repo;
  const b = other && other.source && other.source.repo;
  if (a && b && String(a).toLowerCase() === String(b).toLowerCase()) return 'same';
  return 'different';
}

// The holders other than `current` that hold a site with this id but a different one: [{ node, hosts }]
export function differentHolders(currentSite, current, peers, holders) {
  const out = [];
  for (const p of peers || []) {
    if (p.node === current || !holders.includes(p.node) || !Array.isArray(p.sites)) continue;
    const theirs = p.sites.find((s) => s && s.id === currentSite.id);
    if (theirs && siteRelation(currentSite, theirs) === 'different') out.push({ node: p.node, hosts: [...(theirs.hosts || [])] });
  }
  return out;
}

// The body for PUT /sites/{id} on one node. `stored` is that node's own copy, so its upstream targets, live slot and source stay as they are;
// `shared` holds only what a person edits on the settings tab: name, kind, hosts, paths, health and the access object.
export function nodeSaveBody(stored, shared) {
  const { access, ...fields } = shared;
  const body = siteBody(stored, fields);
  delete body.access;
  const value = accessForSave(access, stored.access);
  if (value) body.access = value;
  return body;
}

// One toast line for a maintenance change on several nodes: "Maintenance enabled on edge-fra, edge-nyc. Failed on edge-ams: <reason>"
export function maintenanceMessage(enabled, results, describe = (e) => (e && e.message) || String(e)) {
  const ok = results.filter((r) => r.ok).map((r) => r.node);
  const parts = [];
  if (ok.length) parts.push(`Maintenance ${enabled ? 'enabled' : 'disabled'} on ${ok.join(', ')}`);
  for (const r of results.filter((x) => !x.ok)) parts.push(`Failed on ${r.node}: ${describe(r.error)}`);
  return parts.join('. ');
}
