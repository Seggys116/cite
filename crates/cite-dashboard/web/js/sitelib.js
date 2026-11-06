// Checks for the parts of a site the node validates besides its source, with the node's limits
import { isHostname } from './rulelib.js';
import { pathsProblem } from './conditionlib.js';

export const MAX_TEXT = 128;
export const MAX_HOSTS = 64;
export const KINDS = ['site', 'api'];

const hasControl = (text) => [...text].some((ch) => ch.charCodeAt(0) < 0x20 || ch.charCodeAt(0) === 0x7f);

export function nameProblem(name) {
  const n = String(name ?? '');
  if (!n.trim()) return 'The site needs a name.';
  if ([...n].length > MAX_TEXT || hasControl(n)) return `The name is at most ${MAX_TEXT} characters without control characters.`;
  return null;
}

export function hostProblem(host) {
  const h = String(host ?? '');
  const name = h.startsWith('*.') ? h.slice(2) : h;
  return isHostname(name) ? null : `"${h}" is not a valid host name or *.wildcard.`;
}

export function hostsProblem(hosts) {
  const list = Array.isArray(hosts) ? hosts : [];
  if (!list.length) return 'Keep at least one host.';
  if (list.length > MAX_HOSTS) return `Use at most ${MAX_HOSTS} hosts.`;
  for (const host of list) {
    const bad = hostProblem(host);
    if (bad) return bad;
  }
  return null;
}

export function healthPathProblem(path) {
  const p = String(path ?? '');
  const ok = p.startsWith('/') && p.length <= 512 && [...p].every((ch) => ch.charCodeAt(0) > 0x20 && ch.charCodeAt(0) < 0x7f && !'#"\'\\$'.includes(ch));
  return ok ? null : 'The health check path starts with / and is plain printable characters without # quotes, backslash or $.';
}

const inRange = (v, lo, hi) => Number.isInteger(v) && v >= lo && v <= hi;

// Every health field by name, so the form can mark the one that is wrong
export function healthProblems(health) {
  const h = health || {};
  const out = {};
  const path = healthPathProblem(h.path);
  if (path) out.path = path;
  if (!inRange(h.interval_ms, 100, 60000)) out.interval_ms = 'The interval is 100 to 60000 ms.';
  if (!inRange(h.timeout_ms, 100, 10000)) out.timeout_ms = 'The timeout is 100 to 10000 ms.';
  else if (!out.interval_ms && h.timeout_ms > h.interval_ms) out.timeout_ms = 'The timeout cannot be longer than the interval.';
  if (!inRange(h.rise, 1, 10)) out.rise = 'Rise is 1 to 10.';
  if (!inRange(h.fall, 1, 10)) out.fall = 'Fall is 1 to 10.';
  return out;
}

export function healthFromFields(fields) {
  const num = (v) => (String(v ?? '').trim() === '' ? NaN : Number(v));
  return {
    path: String(fields.path ?? ''),
    interval_ms: num(fields.interval_ms),
    timeout_ms: num(fields.timeout_ms),
    rise: num(fields.rise),
    fall: num(fields.fall),
  };
}

// The body for PUT /sites/{id}: the site as stored with the changed parts laid over it, since the schema requires slots and the active slot.
export function siteBody(site, overrides = {}) {
  const body = {
    id: site.id,
    name: site.name,
    hosts: [...(site.hosts || [])],
    path_prefixes: [...(site.path_prefixes || [])],
    path_regexes: [...(site.path_regexes || []), ...(site.path_regex ? [site.path_regex] : [])],
    kind: site.kind || 'site',
    blue: site.blue,
    green: site.green,
    active: site.active,
    health: { ...site.health },
    source: site.source || null,
  };
  if (site.access) body.access = site.access;
  return { ...body, ...overrides };
}

// The first problem of the routing form in the order it is laid out, as { field, message }
export function routingProblem({ name, hosts, pathRows, health, kind }) {
  const n = nameProblem(name);
  if (n) return { field: 'name', message: n };
  if (!KINDS.includes(kind)) return { field: 'kind', message: 'The kind is site or API.' };
  const h = hostsProblem(hosts);
  if (h) return { field: 'hosts', message: h };
  const p = pathsProblem(pathRows || []);
  if (p) return { field: 'paths', message: p };
  const hp = healthProblems(health);
  const key = ['path', 'interval_ms', 'timeout_ms', 'rise', 'fall'].find((k) => hp[k]);
  return key ? { field: key, message: hp[key] } : null;
}
