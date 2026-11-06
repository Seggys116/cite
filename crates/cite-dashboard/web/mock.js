// Dev aid: an in-memory stand-in for the dashboard API, enabled with ?mock=1 (add &setup=1 for onboarding, &login=1 to start signed out)
import { ApiError } from './js/api.js';
import {
  corsProblem, hasMatcher, headerOpProblem, listsOf, redirectProblem,
} from './js/rulelib.js';

const query = new URLSearchParams(location.search);
const state = {
  loggedIn: query.get('setup') !== '1' && query.get('login') !== '1',
  needsOnboarding: query.get('setup') === '1',
  username: 'admin',
  nodes: [],
};

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const clone = (v) => (v === undefined ? undefined : JSON.parse(JSON.stringify(v)));
const iso = (ms) => new Date(ms).toISOString();

function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function hashString(text) {
  let hash = 2166136261;
  for (let i = 0; i < text.length; i += 1) hash = Math.imul(hash ^ text.charCodeAt(i), 16777619);
  return hash >>> 0;
}

const pick = (rnd, list) => list[Math.floor(rnd() * list.length)];

function weighted(rnd, entries) {
  const total = entries.reduce((t, e) => t + e[1], 0);
  let roll = rnd() * total;
  for (const [value, weight] of entries) {
    roll -= weight;
    if (roll <= 0) return value;
  }
  return entries[entries.length - 1][0];
}

// Two nodes are seeded so the node picker, per-node health and replicated placement can all be tried.

const PAGE_HTML = (title, text, accent) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>${title}</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;font-family:system-ui,sans-serif;background:#0d1117;color:#e6edf3}main{max-width:30rem;padding:2rem;text-align:center}h1{color:${accent}}</style>
</head><body><main><h1>${title}</h1><p>${text}</p></main></body></html>`;

function seedSites(nodeIdx, now) {
  const o = nodeIdx + 0;
  const target = (a, b, c) => ({ addr: `10.${o}.${a}.${b}:${c}`, weight: 100 });
  const hist = (offsets) => offsets.map(([hoursAgo, slot, action, note], i) => ({ id: `d-${nodeIdx}${i}${hoursAgo}`, at: iso(now - hoursAgo * 3600 * 1000), slot, action, note }));
  const health = { path: '/healthz', interval_ms: 2000, rise: 2, fall: 3, timeout_ms: 1500 };
  return [
    {
      id: 'shop', name: 'Storefront', hosts: ['shop.example.com', 'www.example.com'], path_prefixes: [], path_regexes: [], kind: 'site',
      blue: { targets: [target(1, 11, 8080), target(1, 12, 8080)], label: 'v2.14.0' },
      green: { targets: [target(1, 21, 8080), target(1, 22, 8080)], label: 'v2.13.4' },
      active: 'blue', maintenance: { enabled: false, page_id: null }, health, source: null,
      history: hist([[170, 'green', 'promote', 'Release 2.13.4'], [52, 'blue', 'promote', 'Release 2.14.0-rc1'], [51, 'green', 'rollback', 'Checkout regression'], [6, 'blue', 'promote', 'Release 2.14.0']]),
    },
    {
      id: 'api', name: 'Public API', hosts: ['api.example.com'], path_prefixes: ['/v2'], path_regexes: ['^/v1/'], kind: 'api',
      blue: { targets: [target(2, 11, 9000)], label: null },
      green: { targets: [target(2, 21, 9000)], label: null },
      active: 'green', maintenance: { enabled: false, page_id: null }, health: { ...health, path: '/v1/health' }, source: null,
      access: { cloudflare_only: true, tls: 'full', bots: 'block_bad', zone_lock: true },
      history: hist([[300, 'blue', 'promote', 'Initial deploy'], [28, 'green', 'promote', 'Add pagination to orders'], [27, 'blue', 'switch', 'Manual flip while testing'], [26, 'green', 'switch', 'Back to green']]),
    },
    {
      id: 'docs', name: 'Documentation', hosts: ['docs.example.com'], path_prefixes: [], path_regexes: [], kind: 'site',
      blue: { targets: [target(3, 11, 3000)], label: null },
      green: { targets: [target(3, 21, 3000)], label: null },
      active: 'blue', maintenance: { enabled: nodeIdx === 1, page_id: 'scheduled' }, health, source: { repo: 'acme/docs', branch: 'main', runtime: 'static', node_major: 22, poll_interval: '5m' },
      access: { cloudflare_only: true, tls: 'flexible' },
      history: hist([[400, 'blue', 'promote', 'Initial deploy'], [90, 'green', 'failed', 'Health check timed out']]),
    },
    ...(nodeIdx === 0 ? [{
      id: 'legacy', name: 'Legacy portal', hosts: ['legacy.example.com'], path_prefixes: [], path_regexes: [], kind: 'site',
      blue: { targets: [target(4, 11, 8080)], label: null },
      green: { targets: [target(4, 21, 8080)], label: null },
      active: 'blue', maintenance: { enabled: false, page_id: null }, health, source: null,
      access: { cloudflare_only: true, tls: 'full', zone_lock: true },
      history: hist([[500, 'blue', 'promote', 'Initial deploy']]),
    }] : []),
  ];
}

function seedRules() {
  const none = {};
  return [
    { id: 'r-wp-login', name: 'WordPress login probes', enabled: true, action: 'deny', matchers: { path_regexes: ['^/wp-(login|admin)'] }, site: null },
    { id: 'r-env', name: 'Dotfile and VCS leaks', enabled: true, action: 'deny', matchers: { path_regexes: ['/\\.(env|git)(/|$)'] }, site: null },
    { id: 'r-phpmyadmin', name: 'phpMyAdmin scans', enabled: true, action: 'drop', matchers: { path_prefixes: ['/phpmyadmin', '/pma'] }, site: null },
    { id: 'r-scanner-ua', name: 'Known scanner agents', enabled: true, action: 'tarpit', matchers: { user_agent_regexes: ['(sqlmap|nikto|masscan)'] }, site: null },
    { id: 'r-trace', name: 'Odd HTTP methods', enabled: true, action: 'deny', matchers: { methods: ['TRACE', 'CONNECT'] }, site: null },
    { id: 'r-badnet', name: 'Abusive network', enabled: false, action: 'deny', matchers: { cidrs: ['203.0.113.0/24'] }, site: 'shop' },
    {
      id: 'r-sec-headers', name: 'Security headers', enabled: true, matchers: { ...none }, site: 'shop',
      headers: [{ target: 'response', op: 'set', name: 'X-Frame-Options', value: 'DENY' }, { target: 'response', op: 'set', name: 'Referrer-Policy', value: 'strict-origin' }, { target: 'request', op: 'remove', name: 'X-Debug' }],
    },
    {
      id: 'r-cors-api', name: 'CORS for the app', enabled: true, matchers: { ...none }, site: 'api', label: 'cors-app',
      cors: { origins: ['https://app.example.com'], methods: ['GET', 'POST'], allow_headers: ['Content-Type', 'Authorization'], expose_headers: ['X-Request-Id'], credentials: true, max_age_secs: 600 },
    },
    {
      id: 'redirect-1', name: 'Old blog moved', enabled: true, matchers: { path_prefixes: ['/blog'] }, site: 'shop', label: 'redirect-1', redirect: { to: 'https://blog.example.com/', status: 308 },
    },
    {
      id: 'redirect-2', name: 'Old shop pages', enabled: true, matchers: { path_regexes: ['^/shop/[0-9]+$'] }, site: 'shop', label: 'redirect-2', redirect: { to: '/products{query}', status: 301 },
    },
  ];
}

const RULE_HITS = [['r-wp-login', 14], ['r-env', 11], ['r-phpmyadmin', 7], ['r-scanner-ua', 5], ['r-trace', 2], ['r-badnet', 1]];

function seedPresets() {
  const rule = (name, action, matchers) => ({ id: '', name, enabled: true, action, matchers, site: null });
  const redirect = (name, to, matchers) => ({ id: '', name, enabled: true, matchers, site: null, redirect: { to, status: 301 } });
  return [
    { name: 'sensitive-files', title: 'Sensitive files', description: 'Blocks requests for dotfiles, backups, dumps and key material that should never be public.', rules: [rule('Dotfiles', 'deny', { path_regexes: ['/\\.(env|git|svn|htaccess)'] }), rule('Backups and dumps', 'deny', { path_regexes: ['\\.(bak|sql|old|swp)$'] }), rule('Key material', 'deny', { path_regexes: ['\\.(pem|key|p12)$'] })] },
    { name: 'cms-probes', title: 'CMS probes', description: 'Stops WordPress, Joomla and phpMyAdmin probing on sites that do not run them.', rules: [rule('WordPress', 'deny', { path_regexes: ['^/wp-(admin|login|content|includes)'] }), rule('xmlrpc', 'deny', { path_prefixes: ['/xmlrpc.php'] }), rule('phpMyAdmin', 'drop', { path_prefixes: ['/phpmyadmin'] })] },
    { name: 'scanners', title: 'Scanners', description: 'Tarpits well-known vulnerability scanners by their user agent.', rules: [rule('Scanner agents', 'tarpit', { user_agent_regexes: ['(sqlmap|nikto|masscan|nmap|zgrab)'] })] },
    { name: 'odd-methods', title: 'Odd methods', description: 'Rejects TRACE, CONNECT and other methods no real client sends to a website.', rules: [rule('Unusual methods', 'deny', { methods: ['TRACE', 'CONNECT'] })] },
    { name: 'redirect-to-www', title: 'Redirect to www', description: 'Sends the bare domain to its www address with a permanent redirect, keeping the path and query.', rules: [redirect('Redirect to www', '{scheme}://{www_host}{path}{query}', {})] },
    { name: 'redirect-to-apex', title: 'Redirect to apex', description: 'Sends the www address to the bare domain with a permanent redirect, keeping the path and query.', rules: [redirect('Redirect to apex', '{scheme}://{apex_host}{path}{query}', {})] },
    { name: 'force-https', title: 'Force HTTPS', description: 'Sends plain HTTP requests to the HTTPS address. Skipped for sites where Cloudflare handles HTTPS and for nodes without HTTPS.', rules: [redirect('Force HTTPS', 'https://{host}{path}{query}', { scheme: 'http' })] },
  ];
}

const DAY = 86400000;

function fakeSha(seed) {
  const rnd = mulberry32(hashString(seed));
  return Array.from({ length: 64 }, () => Math.floor(rnd() * 16).toString(16)).join('');
}

function archiveStamp(ms) {
  return new Date(ms).toISOString().slice(0, 19).replace(/[-:]/g, '').replace('T', '-');
}

function archiveEntry(kind, name, ms, rows, from, to) {
  return { name, kind, bytes: kind === 'backup' ? 480000 + (rows || 400) * 612 : 9000 + (rows || 0) * 70, created_ms: ms, sha256: fakeSha(name), rows: rows ?? null, from_ms: from ?? null, to_ms: to ?? null };
}

function seedArchives(now, idx) {
  if (idx === 1) return [];
  const day = (ago) => new Date(now - ago * DAY).toISOString().slice(0, 10);
  return [
    archiveEntry('archive', `requests-${day(40)}.ndjson.gz`, now - 38 * DAY, 18200, now - 41 * DAY, now - 40 * DAY),
    archiveEntry('archive', `requests-${day(39)}.ndjson.gz`, now - 38 * DAY, 21400, now - 40 * DAY, now - 39 * DAY),
    archiveEntry('backup', `analytics-${archiveStamp(now - 7 * DAY)}.db`, now - 7 * DAY, null, null, null),
  ];
}

function archiveRoute(node, method, b, c, body) {
  if (b === 'archives') {
    if (method === 'GET' && !c) return { items: clone(node.archives), dir_bytes: node.archives.reduce((t, e) => t + e.bytes, 0) };
    if (method === 'GET' || method === 'DELETE') {
      const found = node.archives.find((e) => e.name === c);
      if (!found) throw new ApiError(404, 'no such archive');
      if (method === 'GET') return `mock contents of ${found.name}\n`;
      node.archives = node.archives.filter((e) => e !== found);
      audit(node, 'analytics.archive.delete', `${found.name} deleted`);
      return '';
    }
  }
  if (method !== 'POST') throw new ApiError(404, 'not found');
  if (b === 'backup') {
    const entry = archiveEntry('backup', `analytics-${archiveStamp(Date.now())}.db`, Date.now(), null, null, null);
    node.archives.push(entry);
    audit(node, 'analytics.backup', `${entry.name} created`);
    return clone(entry);
  }
  if (b === 'cut') return cutRoute(node, body);
  if (b === 'restore') {
    const found = node.archives.find((e) => e.name === body.name);
    if (!found) throw new ApiError(404, 'no such archive');
    audit(node, 'analytics.restore', `${found.name} restored`);
    return { rows: found.rows ?? node.events.length };
  }
  throw new ApiError(404, 'not found');
}

function cutRoute(node, body) {
  const hasMs = body.before_ms !== undefined && body.before_ms !== null;
  const hasDays = body.before_days !== undefined && body.before_days !== null;
  if (hasMs === hasDays) throw new ApiError(422, 'set exactly one of before_ms and before_days');
  const cutoff = hasMs ? Number(body.before_ms) : Date.now() - Number(body.before_days) * DAY;
  if (!Number.isFinite(cutoff) || cutoff < 0) throw new ApiError(422, 'invalid cutoff');
  if (hasDays && !(Number.isInteger(body.before_days) && body.before_days >= 1 && body.before_days <= 3650)) throw new ApiError(422, 'before_days must be between 1 and 3650');
  const archive = body.archive !== false;
  const old = node.events.filter((e) => e.ts_ms < cutoff);
  const oldest = old.length ? Math.min(...old.map((e) => e.ts_ms)) : null;
  const report = { dry_run: body.dry_run === true, cutoff_ms: cutoff, rows: old.length, oldest_ms: oldest, archived_rows: 0, files: [], archive };
  if (report.dry_run || !old.length) return report;
  if (archive) {
    const name = `requests-${new Date(cutoff).toISOString().slice(0, 10)}-${archiveStamp(Date.now()).slice(9)}.ndjson.gz`;
    node.archives.push(archiveEntry('archive', name, Date.now(), old.length, oldest, cutoff));
    report.archived_rows = old.length;
    report.files = [name];
  }
  node.events = node.events.filter((e) => e.ts_ms >= cutoff);
  audit(node, 'analytics.cut', `${old.length} rows cut${archive ? ' and archived' : ' without an archive'}`);
  return report;
}

const CLOUDFLARE_BUILTIN = {
  updated: '2026-11-06',
  ranges: [
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20',
    '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13',
    '131.0.72.0/22', '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
  ],
};

const CERT_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/;
const CERT_BLOCK = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/;
const KEY_BLOCK = /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z]+ )?PRIVATE KEY-----/;
const CIDR_LIKE = /^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]+)\/\d{1,3}$/i;
const PEM_LIMIT = 100 * 1024;
const CERT_ID_RE = /^[0-9A-Z]{26}$/;

// 26 characters of [0-9A-Z], shaped like the ULIDs the connector issues
function fakeUlid(seed) {
  return '01J' + fakeSha(seed).slice(0, 23).toUpperCase();
}

function seedCert(name, subject, sans, issuer, days, keyType) {
  const created = Date.now() - 40 * DAY;
  return { id: fakeUlid('cert-' + name), name, subject, sans, issuer, expires: Date.now() + days * DAY, key_type: keyType, created_at: iso(created), fingerprint: fakeSha('fp-' + name) };
}

function seedCerts(idx) {
  if (idx === 1) return [];
  return [
    seedCert('storefront', 'CN=shop.example.com', ['shop.example.com', 'www.example.com'], "R11 (Let's Encrypt)", 212, 'ECDSA P-256'),
    seedCert('public-api', 'CN=api.example.com', ['api.example.com'], 'Sectigo RSA Domain Validation CA', 9, 'RSA 2048'),
  ];
}

function hostCovered(host, san) {
  const h = host.toLowerCase();
  const s = san.toLowerCase();
  if (!s.startsWith('*.')) return h === s;
  const rest = s.slice(1);
  return h.endsWith(rest) && h.length > rest.length && !h.slice(0, h.length - rest.length).includes('.');
}

function coveredHosts(node, sans) {
  return node.sites.flatMap((s) => s.hosts).filter((host) => sans.some((san) => hostCovered(host, san)));
}

// A file placed in the node's certificate directory by hand: listed read-only, with no item routes
function manualCert() {
  return {
    id: 'file:legacy.pem', name: 'legacy.pem', subject: '', sans: [], issuer: '', not_before: '', not_after: '', days_left: 0,
    fingerprint_sha256: '', key_type: '', created_at: '', covers: [], source: 'manual', warning: 'The file could not be read: no private key block found.',
  };
}

function certView(node, c) {
  const days = Math.floor((c.expires - Date.now()) / DAY);
  return {
    source: 'api', warning: null,
    id: c.id, name: c.name, subject: c.subject, sans: [...c.sans], issuer: c.issuer, not_before: iso(c.expires - 90 * DAY).slice(0, 10), not_after: iso(c.expires).slice(0, 10),
    days_left: days, fingerprint_sha256: c.fingerprint, key_type: c.key_type, created_at: c.created_at, covers: coveredHosts(node, c.sans),
  };
}

// Checks the same things the connector does with an uploaded pair, without parsing the PEM itself
function checkCertBody(node, body, existing) {
  const name = body.name === undefined && existing ? existing.name : body.name;
  if (typeof name !== 'string' || !CERT_NAME_RE.test(name) || name.endsWith(' ') || name.includes('-----')) throw new ApiError(400, 'name must be 1 to 64 letters, digits, spaces, dots, dashes or underscores, start with a letter or digit, not end with a space and not contain -----');
  if (node.certs.some((c) => c !== existing && c.name === name)) throw new ApiError(409, `a certificate named ${name} already exists`);
  if (typeof body.certificate !== 'string' || !CERT_BLOCK.test(body.certificate)) throw new ApiError(400, 'certificate is not valid PEM');
  if (typeof body.private_key !== 'string' || !KEY_BLOCK.test(body.private_key)) throw new ApiError(400, 'private key is not valid PEM');
  if (body.certificate.length + body.private_key.length > PEM_LIMIT) throw new ApiError(413, 'certificate and key are too large');
  return name;
}

function certificateRoute(node, method, id, body) {
  if (node.idx === 1) throw new ApiError(404, 'Not Found');
  if (!id) {
    if (method === 'GET') {
      const hosts = node.sites.flatMap((s) => s.hosts);
      return {
        items: [...node.certs.map((c) => certView(node, c)), manualCert()], https_port: node.settings.https_port ?? null, dir_ready: true,
        uncovered_hosts: hosts.filter((host) => !node.certs.some((c) => c.sans.some((san) => hostCovered(host, san)))),
      };
    }
    if (method === 'POST') {
      const name = checkCertBody(node, body, null);
      const base = /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(name) ? name.toLowerCase() : 'example.com';
      const cert = seedCert(name, 'CN=' + base, [base, '*.' + base], 'Mock issuing CA', 90, 'ECDSA P-256');
      cert.id = fakeUlid(name + Date.now());
      cert.created_at = iso(Date.now());
      node.certs.push(cert);
      audit(node, 'certificate.create', `certificate ${name} uploaded`);
      const view = certView(node, cert);
      return view.covers.length ? view : { ...view, warning: 'This certificate does not cover any site host on this node yet.' };
    }
    throw new ApiError(405, 'method not allowed');
  }
  const cert = CERT_ID_RE.test(id) ? node.certs.find((c) => c.id === id) : null;
  if (!cert) throw new ApiError(404, 'no such certificate');
  if (method === 'GET') return certView(node, cert);
  if (method === 'PUT') {
    cert.name = checkCertBody(node, body, cert);
    cert.expires = Date.now() + 90 * DAY;
    cert.fingerprint = fakeSha(cert.name + Date.now());
    audit(node, 'certificate.replace', `certificate ${cert.name} replaced`);
    return certView(node, cert);
  }
  if (method === 'DELETE') {
    node.certs = node.certs.filter((c) => c !== cert);
    audit(node, 'certificate.delete', `certificate ${cert.name} deleted`);
    return '';
  }
  throw new ApiError(405, 'method not allowed');
}

function cloudflareRoute(node) {
  const custom = node.settings.cloudflare_ranges || [];
  return { source: custom.length ? 'custom' : 'builtin', updated: CLOUDFLARE_BUILTIN.updated, ranges: custom.length ? [...custom] : [...CLOUDFLARE_BUILTIN.ranges] };
}

function seedNode(name, url, idx) {
  const now = Date.now();
  const node = {
    name, url, idx, version: '0.2.0', startedAt: now - (idx ? 9 : 26) * 86400 * 1000 - 3600 * 1000,
    sites: seedSites(idx, now), rules: seedRules(), presets: seedPresets(),
    pages: [
      { id: 'scheduled', name: 'Scheduled maintenance', status: 503, html: PAGE_HTML('Back soon', 'We are upgrading our systems and will be back in a few minutes.', '#ffd23f') },
      { id: 'incident', name: 'Incident notice', status: 503, html: PAGE_HTML('We are on it', 'Something went wrong on our side. Engineers are already working on a fix.', '#ce422b') },
    ],
    settings: {
      // The first node starts with HTTPS off so the certificates tab can show the port control
      http_port: 80, https_port: idx === 0 ? null : 443, max_conn: 20000, client_timeout_ms: 30000, server_timeout_ms: 60000, connect_timeout_ms: 3000,
      per_ip_rate_limit: 600, max_body_bytes: null, cloudflare_ranges: [],
      retention: { recent_events: 5000, minute_buckets_hours: 48, hour_buckets_days: 0, archive_before_delete: true, audit_days: 365, persist_interval_secs: 60, store_user_agents: true, store_client_ips: true },
    },
    archives: seedArchives(now, idx),
    certs: seedCerts(idx),
    zones: { api: { created_at: iso(now - 12 * DAY), fingerprint: fakeSha('zone-api').slice(0, 12) } },
    ruleSecrets: {},
    tokens: [
      { id: 't-1', name: 'ci-deploy', created_at: iso(now - 40 * 86400 * 1000), last_used_at: iso(now - 3 * 3600 * 1000) },
      { id: 't-2', name: 'grafana-readonly', created_at: iso(now - 12 * 86400 * 1000), last_used_at: null },
    ],
    audit: [],
    events: [],
    lastTick: now,
    hap: { configHash: '9f2c41ab77e0', lastReload: now - 6 * 3600 * 1000, ok: true, error: '' },
    down: new Set(idx === 1 ? ['10.1.1.22:8080'] : []),
  };
  const actors = ['admin', 'ci-deploy'];
  const entries = [['site.deploy', 'shop promoted green to blue'], ['firewall.create', 'rule r-env added'], ['settings.update', 'retention changed'], ['site.maintenance', 'docs maintenance toggled'], ['token.create', 'token ci-deploy created'], ['haproxy.reload', 'config reloaded']];
  entries.forEach(([action, detail], i) => node.audit.push({ at: iso(now - (i * 5 + 2) * 3600 * 1000), actor: actors[i % 2], action, detail }));
  const rnd = mulberry32(hashString(name));
  for (let i = 0; i < 400; i += 1) node.events.push(makeEvent(node, now - Math.floor(i * 4500 + rnd() * 3000), rnd));
  return node;
}

// Events come from a generator seeded by the node name, so each node keeps a recognisable traffic mix.

const SITE_SHARE = { shop: 0.55, api: 0.35, docs: 0.1 };
const WINDOWS = { '15m': [15, 60], '1h': [60, 60], '24h': [96, 900], '7d': [168, 3600], '30d': [120, 21600] };
const IPS = ['198.51.100.23', '203.0.113.77', '192.0.2.14', '198.51.100.88', '192.0.2.201', '2001:db8::7a', '203.0.113.5', '198.51.100.140'];
const AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0',
  'curl/8.4.0', 'python-requests/2.31.0', 'Googlebot/2.1 (+http://www.google.com/bot.html)',
];
const PATHS = {
  shop: [['/', 30], ['/products', 18], ['/products/42', 10], ['/cart', 8], ['/checkout', 5], ['/static/app.js', 12], ['/static/main.css', 9], ['/img/hero.webp', 8]],
  api: [['/v1/users', 24], ['/v1/orders', 30], ['/v1/orders/918', 12], ['/v1/health', 20], ['/v1/search', 14]],
  docs: [['/', 25], ['/guide/start', 28], ['/guide/deploy', 18], ['/assets/site.css', 14], ['/search', 15]],
};
const SCANS = [['/wp-login.php', 'r-wp-login'], ['/wp-admin/setup-config.php', 'r-wp-login'], ['/.env', 'r-env'], ['/.git/config', 'r-env'], ['/phpmyadmin/index.php', 'r-phpmyadmin']];
const BLOCK_STATUS = { deny: 403, drop: 444, tarpit: 408 };

function contentTypeFor(path) {
  if (path.endsWith('.js')) return 'application/javascript';
  if (path.endsWith('.css')) return 'text/css';
  if (path.endsWith('.webp')) return 'image/webp';
  if (path.startsWith('/v1/')) return 'application/json';
  return 'text/html';
}

// A rough stand-in for the edge detector: tools and crawlers name themselves, browsers carry the full header set
function botFields(ua, method, rnd) {
  const browser = ua.startsWith('Mozilla/5.0') && !/bot/i.test(ua);
  if (browser) {
    const odd = rnd() < 0.06;
    return {
      http_version: 'HTTP/2', accept: 'text/html,application/xhtml+xml,*/*;q=0.8', accept_language: odd ? '' : 'en-US,en;q=0.9', accept_encoding: 'gzip, deflate, br',
      sec_fetch_site: odd ? '' : 'same-origin', sec_fetch_mode: odd ? '' : 'navigate', sec_fetch_dest: odd ? '' : 'document',
      sec_ch_ua: /Chrome/.test(ua) ? '"Chromium";v="130", "Not?A_Brand";v="99"' : '', tls_version: 'TLSv1.3', resp_ms: Math.round(2 + rnd() * 40),
      bot_score: odd ? 35 + Math.floor(rnd() * 20) : Math.floor(rnd() * 14), bot_class: odd ? 'suspect' : 'human', bot_signals: odd ? 'missing_accept_language,no_sec_fetch' : '',
    };
  }
  const crawler = /bot/i.test(ua);
  const score = crawler ? 55 + Math.floor(rnd() * 15) : 82 + Math.floor(rnd() * 16);
  const signals = crawler ? 'ua_googlebot,no_sec_fetch' : /sqlmap|nikto/i.test(ua) ? 'ua_generic_scraper,missing_accept_language,no_sec_fetch' : 'ua_python_requests,missing_accept_language,accept_wildcard_only,no_sec_fetch';
  return {
    http_version: 'HTTP/1.1', accept: crawler ? 'text/html' : '*/*', accept_language: '', accept_encoding: crawler ? 'gzip' : 'gzip, deflate',
    sec_fetch_site: '', sec_fetch_mode: '', sec_fetch_dest: '', sec_ch_ua: '', tls_version: 'TLSv1.3', resp_ms: Math.round(2 + rnd() * 30),
    bot_score: score, bot_class: crawler ? 'crawler' : method === 'GET' && /curl|python/.test(ua) ? 'tool' : 'bot', bot_signals: signals,
  };
}

function makeEvent(node, ts, rnd) {
  const siteId = weighted(rnd, Object.entries(SITE_SHARE));
  const site = node.sites.find((s) => s.id === siteId) || node.sites[0];
  const scan = rnd() < 0.045;
  const [path, ruleId] = scan ? pick(rnd, SCANS) : [weighted(rnd, PATHS[site.id] || PATHS.shop), null];
  const rule = ruleId ? node.rules.find((r) => r.id === ruleId) : null;
  let method = 'GET';
  if (site.id === 'api') method = weighted(rnd, [['GET', 60], ['POST', 25], ['PUT', 8], ['DELETE', 4], ['OPTIONS', 3]]);
  else if (path === '/checkout' || path === '/cart') method = weighted(rnd, [['GET', 50], ['POST', 50]]);
  const failure = rnd();
  let status = failure < 0.012 ? pick(rnd, [500, 502, 503]) : failure < 0.05 ? pick(rnd, [404, 404, 401, 429, 400]) : failure < 0.11 ? pick(rnd, [301, 302, 304]) : 200;
  if (rule) status = BLOCK_STATUS[rule.action] || 403;
  const client = scan ? pick(rnd, IPS.slice(1, 4)) : pick(rnd, IPS);
  const total = Math.max(2, Math.round(Math.exp(2.9 + rnd() * 2.2) * (site.id === 'api' ? 0.8 : 1)));
  const ua = scan ? pick(rnd, ['sqlmap/1.7.2#stable (https://sqlmap.org)', 'Nikto/2.5.0', AGENTS[3]]) : pick(rnd, AGENTS);
  return {
    ...botFields(ua, method, rnd),
    ts_ms: ts, client_ip: client, host: pick(rnd, site.hosts), method, path, query_len: rnd() < 0.2 ? Math.floor(rnd() * 90) : 0, status,
    bytes_in: 200 + Math.floor(rnd() * 900), bytes_out: rule ? 0 : status === 304 ? 0 : Math.floor(Math.exp(6.5 + rnd() * 5)),
    total_ms: rule ? 0 : total, user_agent: ua,
    referer: rnd() < 0.3 ? 'https://' + pick(rnd, site.hosts) + '/' : '', content_type: contentTypeFor(path),
    backend: 'bk_' + site.id, server: `${site.active}-${1 + Math.floor(rnd() * Math.max(1, site[site.active].targets.length))}`, site: site.id,
    blocked: rule ? rule.id : null,
  };
}

function tickEvents(node) {
  const now = Date.now();
  const gap = Math.min(now - node.lastTick, 20000);
  const count = Math.min(30, Math.floor(gap / 700) + (Math.random() < 0.5 ? 1 : 0));
  const rnd = mulberry32(Math.floor(now / 1000) ^ hashString(node.name));
  const fresh = [];
  for (let i = 0; i < count; i += 1) fresh.push(makeEvent(node, now - Math.floor(rnd() * Math.max(gap, 1000)), rnd));
  fresh.sort((a, b) => b.ts_ms - a.ts_ms);
  node.events = fresh.concat(node.events).slice(0, 2000);
  node.lastTick = now;
}

function noise(i, salt) {
  const x = Math.sin(i * 12.9898 + salt * 78.233) * 43758.5453;
  return x - Math.floor(x);
}

function timeseries(node, win, siteId) {
  const [count, step] = WINDOWS[win] || WINDOWS['24h'];
  const factor = siteId ? SITE_SHARE[siteId] || 0.05 : 1;
  const salt = hashString(node.name + (siteId || ''));
  const base = (node.idx ? 330 : 470) * factor;
  const end = Math.floor(Date.now() / 1000 / step) * step;
  const weights = [];
  const points = [];
  for (let i = 0; i < count; i += 1) {
    const ts = end - (count - 1 - i) * step;
    const hour = ((ts / 3600) % 24 + 24) % 24;
    // Traffic peaks in the afternoon and dips overnight, with a rare error spike, so the charts look plausible.
    const diurnal =0.62 + 0.38 * Math.sin(((hour - 8) / 24) * Math.PI * 2);
    const wobble = 0.85 + 0.3 * noise(ts / step, salt);
    const requests = Math.round((step / 60) * base * diurnal * wobble);
    const spike = noise(ts / step, salt + 7) > 0.93 ? 0.05 : 0;
    const errors = Math.round(requests * (0.012 + spike + 0.006 * noise(ts / step, salt + 3)));
    weights.push(0.3 + noise(ts / step, salt + 11));
    points.push({ ts, requests, bytes_out: requests * Math.round(30000 + 12000 * noise(ts / step, salt + 5)), errors, blocked: 0, avg_ms: Math.round(30 + 25 * noise(ts / step, salt + 9) + spike * 400) });
  }
  const totalBlocked = Math.round(40 * ((count * step) / 86400) * factor);
  const sum = weights.reduce((t, w) => t + w, 0);
  let left = totalBlocked;
  points.forEach((p, i) => {
    p.blocked = Math.floor((totalBlocked * weights[i]) / sum);
    left -= p.blocked;
  });
  // Rounding leaves a remainder; it goes one by one to the heaviest buckets so the total stays exact.
  const order = weights.map((w, i) => [w, i]).sort((a, b) => b[0] - a[0]);
  for (let i = 0; left > 0 && order.length; i = (i + 1) % order.length) {
    points[order[i][1]].blocked += 1;
    left -= 1;
  }
  return { step_secs: step, points };
}

function share(total, entries, scale = 1) {
  const sum = entries.reduce((t, e) => t + e[1], 0);
  return entries.map(([key, weight]) => ({ key, count: Math.round((total * scale * weight) / sum), bytes: 0 }));
}

function summary(node, win, siteId) {
  const series = timeseries(node, win, siteId);
  const total = (field) => series.points.reduce((t, p) => t + p[field], 0);
  const requests = total('requests');
  const errors = total('errors');
  const blocked = total('blocked');
  const e5 = Math.round(errors * 0.22);
  const redirects = Math.round(requests * 0.06);
  const merged = new Map();
  for (const [id, list] of Object.entries(PATHS)) {
    if (siteId && id !== siteId) continue;
    for (const [p, w] of list) merged.set(p, (merged.get(p) || 0) + w * (siteId ? 1 : SITE_SHARE[id] || 0.1));
  }
  const pathPool = [...merged.entries()];
  const withBytes = (items, avg) => items.map((i) => ({ ...i, bytes: i.count * avg }));
  const top = (items) => items.sort((a, b) => b.count - a.count).slice(0, 8);
  const sites = siteId ? node.sites.filter((s) => s.id === siteId) : node.sites;
  const hostEntries = sites.flatMap((s) => s.hosts.map((h) => [h, (SITE_SHARE[s.id] || 0.1) * 100]));
  const blockedWeights = RULE_HITS.filter(([id]) => node.rules.some((r) => r.id === id));
  const topBlocked = share(blocked, blockedWeights).filter((b) => b.count > 0);
  return {
    requests, bytes_in: requests * 1180, bytes_out: total('bytes_out'), blocked, errors_4xx: errors - e5, errors_5xx: e5,
    avg_ms: 38 + (node.idx ? 9 : 0), p50_ms: 24, p95_ms: 148 + (node.idx ? 22 : 0), p99_ms: 412,
    status: { '2xx': requests - errors - redirects - blocked, '3xx': redirects, '4xx': errors - e5 + blocked, '5xx': e5 },
    methods: { GET: Math.round(requests * 0.86), POST: Math.round(requests * 0.1), HEAD: Math.round(requests * 0.02), PUT: Math.round(requests * 0.01), DELETE: Math.round(requests * 0.007), OPTIONS: Math.round(requests * 0.003) },
    content_types: { 'text/html': Math.round(requests * 0.34), 'application/json': Math.round(requests * 0.31), 'application/javascript': Math.round(requests * 0.09), 'image/webp': Math.round(requests * 0.14), 'text/css': Math.round(requests * 0.07), 'image/png': Math.round(requests * 0.03), 'font/woff2': Math.round(requests * 0.02) },
    sizes: cumulativeSizes(requests),
    top_paths: top(withBytes(share(requests, pathPool, 0.8), 21000)),
    top_ips: share(requests, IPS.map((ip, i) => [ip, 30 - i * 3]), 0.7),
    top_user_agents: share(requests, AGENTS.map((ua, i) => [ua, 40 - i * 6]), 0.9),
    top_hosts: top(withBytes(share(requests, hostEntries), 30000)),
    top_blocked: topBlocked,
  };
}

// The API reports response sizes cumulatively: each bucket counts everything up to and including its bound
function cumulativeSizes(requests) {
  let running = 0;
  return [1024, 4096, 16384, 65536, 262144, 1048576, null].map((le, i) => {
    running += Math.round(requests * [0.14, 0.22, 0.24, 0.2, 0.12, 0.06, 0.02][i]);
    return { le, count: running };
  });
}

function filterEvents(node, q) {
  tickEvents(node);
  const status = q.get('status');
  const method = q.get('method');
  const path = (q.get('path') || '').toLowerCase();
  const ip = q.get('ip');
  const site = q.get('site');
  const limit = Number(q.get('limit')) || 100;
  const out = [];
  for (const ev of node.events) {
    if (status) {
      const cls = /^([1-5])xx$/i.exec(status);
      if (cls ? Math.floor(ev.status / 100) !== Number(cls[1]) : /^\d+$/.test(status) && ev.status !== Number(status)) continue;
    }
    if (method && ev.method !== method) continue;
    if (path && !ev.path.toLowerCase().includes(path)) continue;
    if (ip && !ev.client_ip.includes(ip)) continue;
    if (site && ev.site !== site) continue;
    if (q.get('blocked') === 'true' && !ev.blocked) continue;
    out.push(ev);
    if (out.length >= limit) break;
  }
  return out;
}

// Every change is recorded in the node audit log, as the real connector does, so the audit view has content.

function audit(node, action, detail) {
  node.audit.unshift({ at: iso(Date.now()), actor: state.username, action, detail });
}

function findSite(node, id) {
  const site = node.sites.find((s) => s.id === id);
  if (!site) throw new ApiError(404, `site ${id} not found`);
  return site;
}

function withLive(node, site) {
  const status = (t) => ({ addr: t.addr, status: node.down.has(t.addr) ? 'DOWN' : 'UP' });
  return { ...clone(site), live: { blue: site.blue.targets.map(status), green: site.green.targets.map(status) } };
}

function pushHistory(site, slot, action, note) {
  site.history.push({ id: 'd-' + Math.random().toString(36).slice(2, 8), at: iso(Date.now()), slot, action, note });
  return site.history[site.history.length - 1];
}

// Mirrors the node's own validation so form errors can be seen without a real node.
function checkSiteShape(site) {
  if (!site || !/^[a-z0-9][a-z0-9-]{0,62}$/.test(site.id || '')) throw new ApiError(400, 'invalid site id');
  if (!site.name || !Array.isArray(site.hosts) || !site.hosts.length) throw new ApiError(400, 'site needs a name and at least one host');
  for (const source of site.path_regexes || []) {
    try {
      new RegExp(source);
    } catch (err) {
      throw new ApiError(400, 'invalid path regex');
    }
  }
  if ((site.path_prefixes || []).some((p) => typeof p !== 'string' || !p.startsWith('/'))) throw new ApiError(400, 'path prefixes start with /');
  if (site.access && (!['full', 'flexible'].includes(site.access.tls || 'full') || typeof (site.access.cloudflare_only ?? false) !== 'boolean')) throw new ApiError(400, 'invalid access settings');
  if (site.access && !['allow', 'block_bad', 'block_all'].includes(site.access.bots || 'allow')) throw new ApiError(400, 'bots must be allow, block_bad or block_all');
  if (site.access && site.access.zone_lock && !site.access.cloudflare_only) throw new ApiError(400, 'zone_lock needs cloudflare_only');
}

// Not scannable: three finder squares plus seeded noise, enough to preview the onboarding layout.
function fakeQr(seedText) {
  const rnd = mulberry32(hashString(seedText));
  const size = 29;
  let d = '';
  const cell = (x, y) => { d += `M${x} ${y}h1v1h-1z`; };
  const finder = (ox, oy) => {
    for (let y = 0; y < 7; y += 1) {
      for (let x = 0; x < 7; x += 1) {
        if (x === 0 || x === 6 || y === 0 || y === 6 || (x >= 2 && x <= 4 && y >= 2 && y <= 4)) cell(ox + x, oy + y);
      }
    }
  };
  finder(1, 1);
  finder(size - 8, 1);
  finder(1, size - 8);
  for (let y = 1; y < size - 1; y += 1) {
    for (let x = 1; x < size - 1; x += 1) {
      const corner = (x < 9 && y < 9) || (x > size - 10 && y < 9) || (x < 9 && y > size - 10);
      if (!corner && rnd() > 0.52) cell(x, y);
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges"><rect width="${size}" height="${size}" fill="#ffffff"/><path fill="#000000" d="${d}"/></svg>`;
}

function haproxyConfig(node) {
  const lines = ['global', '    maxconn ' + node.settings.max_conn, '    stats socket /run/haproxy/admin.sock mode 660 level admin', '', 'defaults', '    mode http',
    `    timeout client ${node.settings.client_timeout_ms}ms`, `    timeout server ${node.settings.server_timeout_ms}ms`, `    timeout connect ${node.settings.connect_timeout_ms}ms`, '',
    'frontend http_in', '    bind :' + node.settings.http_port];
  for (const s of node.sites) lines.push(`    acl host_${s.id} hdr(host) -i ${s.hosts.join(' ')}`, `    use_backend bk_${s.id} if host_${s.id}`);
  for (const s of node.sites) {
    lines.push('', `backend bk_${s.id}`, '    option httpchk GET ' + s.health.path);
    for (const slot of ['blue', 'green']) {
      s[slot].targets.forEach((t, i) => lines.push(`    server ${slot}-${i + 1} ${t.addr} weight ${t.weight} check${s.active === slot ? '' : ' disabled'}`));
    }
  }
  return lines.join('\n') + '\n';
}

// Paths follow the real API layout: /nodes/<name>/... is stripped to the node part and handed to nodeRoute.

function findNode(name) {
  const node = state.nodes.find((n) => n.name === name);
  if (!node) throw new ApiError(404, `node ${name} is not configured`);
  return node;
}

function nodeInfo(node) {
  return {
    name: node.name, version: node.version, uptime_secs: Math.floor((Date.now() - node.startedAt) / 1000),
    haproxy: { running: true, config_hash: node.hap.configHash, last_reload_at: iso(node.hap.lastReload), last_reload_ok: node.hap.ok, last_error: node.hap.error || null },
    sites: node.sites.length, firewall_rules: node.rules.length,
    // The first node holds a GitHub token of its own, the second does not, so both token flows can be tried
    github: { token_configured: node.idx === 0, source: node.idx === 0 ? 'env' : 'none' },
  };
}

const ZONE_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const TOKEN_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789';

// Secret-looking values come from the platform's random source, even though the mock is only a stand-in
function randomText(length, alphabet) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => alphabet[b % alphabet.length]).join('');
}

// The secret is returned once by a rotate and never by a read, as on the real node
function zoneSecretRoute(node, site, method) {
  const header = 'X-Cite-Origin-Secret';
  const lockOn = Boolean(site.access && site.access.zone_lock);
  if (method === 'GET') {
    // A site named legacy plays a node whose secret store could not be read, so that path can be tried by hand
    if (site.id === 'legacy') return { configured: false, readable: false, header, created_at: null, fingerprint: null };
    const kept = node.zones[site.id];
    return { configured: Boolean(kept), readable: true, header, created_at: kept ? kept.created_at : null, fingerprint: kept ? kept.fingerprint : null };
  }
  if (method !== 'POST') throw new ApiError(405, 'method not allowed');
  if (!lockOn) throw new ApiError(409, `site ${site.id} does not use the zone lock`);
  const secret = randomText(43, ZONE_ALPHABET);
  const kept = { created_at: iso(Date.now()), fingerprint: fakeSha(secret).slice(0, 12) };
  node.zones[site.id] = kept;
  audit(node, 'site.zone-secret', `site ${site.id} zone secret rotated`);
  return { secret, header, ...kept };
}

async function siteRoute(node, method, seg, body) {
  const [id, action] = seg;
  if (!id) {
    if (method === 'GET') return node.sites.map((s) => ({ ...clone(s) }));
    if (method === 'POST') {
      checkSiteShape(body);
      if (node.sites.some((s) => s.id === body.id)) throw new ApiError(409, `site ${body.id} already exists`);
      const created = { ...clone(body), history: [] };
      node.sites.push(created);
      audit(node, 'site.create', `site ${body.id} created`);
      return clone(created);
    }
  }
  const site = findSite(node, id);
  if (!action) {
    if (method === 'GET') return withLive(node, site);
    if (method === 'PUT') {
      checkSiteShape(body);
      const { name, hosts, path_prefixes: pathPrefixes, path_regexes: pathRegexes, kind, health, source, access } = clone(body);
      Object.assign(site, { name, hosts, path_prefixes: pathPrefixes || [], path_regexes: pathRegexes || [], kind, health, source, access: access || { cloudflare_only: false, tls: 'full' } });
      if (!site.access.zone_lock) delete node.zones[id];
      else if (!node.zones[id]) node.zones[id] = { created_at: iso(Date.now()), fingerprint: fakeSha(id + Date.now()).slice(0, 12) };
      audit(node, 'site.update', `site ${id} updated`);
      return clone(site);
    }
    if (method === 'DELETE') {
      node.sites.splice(node.sites.indexOf(site), 1);
      audit(node, 'site.delete', `site ${id} deleted`);
      return { ok: true };
    }
  }
  if (action === 'zone-secret') return zoneSecretRoute(node, site, method);
  if (method !== 'POST') throw new ApiError(405, 'method not allowed');
  const idle = site.active === 'blue' ? 'green' : 'blue';
  if (action === 'deploy') {
    const ref = body && body.git_ref;
    const targets = (body && body.targets) || [];
    if (site.source) {
      if (!ref || !/^[A-Za-z0-9._/-]{1,128}$/.test(ref) || ref.startsWith('-') || ref.includes('..')) throw new ApiError(400, 'a valid git_ref is needed to deploy a site built from GitHub');
    } else if (!targets.length) {
      throw new ApiError(400, 'deploy needs at least one target');
    }
    await sleep(1600);
    if (site.source) {
      if (/bad|down/i.test(ref)) {
        audit(node, 'site.deploy', `site ${id} deploy of ${ref} failed health checks`);
        pushHistory(site, idle, 'failed', (body.note || `Deploy ${ref}`) + ' (health check timed out)');
        throw new ApiError(409, `deploy failed health checks: the ${idle} slot of ${id} never came up, active slot unchanged`);
      }
      site.active = idle;
      audit(node, 'site.deploy', `site ${id} promoted ${idle} at ${ref}`);
      return clone(pushHistory(site, idle, 'promote', body.note || `Deploy ${ref}`));
    }
    // A target address containing bad or down fails the simulated health gate, so the failure path can be tried by hand.
    const broken = targets.some((t) => /bad|down/i.test(t.addr));
    if (broken) {
      audit(node, 'site.deploy', `site ${id} deploy failed health checks`);
      pushHistory(site, idle, 'failed', (body.note || 'Deploy') + ' (health check timed out)');
      throw new ApiError(409, `deploy failed health checks: the ${idle} slot of ${id} never came up, active slot unchanged`);
    }
    site[idle].targets = clone(targets);
    site.active = idle;
    audit(node, 'site.deploy', `site ${id} promoted ${idle}`);
    return clone(pushHistory(site, idle, 'promote', body.note || 'Deploy'));
  }
  if (action === 'switch') {
    if (!body || !['blue', 'green'].includes(body.slot)) throw new ApiError(400, 'slot must be blue or green');
    site.active = body.slot;
    audit(node, 'site.switch', `site ${id} switched to ${body.slot}`);
    return clone(pushHistory(site, body.slot, 'switch', 'Manual switch'));
  }
  if (action === 'rollback') {
    if (!site.history.some((d) => d.action === 'promote' || d.action === 'switch')) throw new ApiError(409, 'nothing to roll back');
    site.active = idle;
    audit(node, 'site.rollback', `site ${id} rolled back to ${idle}`);
    return clone(pushHistory(site, idle, 'rollback', 'Rolled back from the console'));
  }
  if (action === 'maintenance') {
    if (body.page_id && !node.pages.some((p) => p.id === body.page_id)) throw new ApiError(400, 'unknown maintenance page');
    site.maintenance = { enabled: Boolean(body.enabled), page_id: body.page_id || null };
    audit(node, 'site.maintenance', `site ${id} maintenance ${body.enabled ? 'on' : 'off'}`);
    return clone(site);
  }
  throw new ApiError(404, 'not found');
}

function collectionRoute(list, label, method, id, body, node, usedCheck) {
  if (!id) {
    if (method === 'GET') return clone(list);
    if (method === 'POST') {
      if (!body || !body.id) throw new ApiError(400, label + ' needs an id');
      if (list.some((x) => x.id === body.id)) throw new ApiError(409, `${label} ${body.id} already exists`);
      list.push(clone(body));
      audit(node, label + '.create', `${label} ${body.id} created`);
      return clone(body);
    }
  }
  const index = list.findIndex((x) => x.id === id);
  if (index < 0) throw new ApiError(404, `${label} ${id} not found`);
  if (method === 'GET') return clone(list[index]);
  if (method === 'PUT') {
    list[index] = { ...clone(body), id };
    audit(node, label + '.update', `${label} ${id} updated`);
    return clone(list[index]);
  }
  if (method === 'DELETE') {
    const user = usedCheck && usedCheck(id);
    if (user) throw new ApiError(409, `${label} ${id} is in use by ${user}`);
    list.splice(index, 1);
    audit(node, label + '.delete', `${label} ${id} deleted`);
    return { ok: true };
  }
  throw new ApiError(405, 'method not allowed');
}

// Mirrors the node's rule checks, and holds secret header values apart so the API never returns them
function checkRuleShape(rule) {
  const effects = Boolean(rule.redirect) || Boolean(rule.cors) || (rule.headers || []).length > 0;
  if (rule.action && effects) throw new ApiError(400, `rule ${rule.id}: a rule either blocks (action) or has effects (redirect, headers, cors), not both`);
  if (rule.redirect && (rule.cors || (rule.headers || []).length)) throw new ApiError(400, `rule ${rule.id}: a redirect cannot be combined with headers or cors`);
  if (!rule.action && !effects) throw new ApiError(400, `rule ${rule.id}: needs an action or an effect (redirect, headers or cors)`);
  const m = rule.matchers || {};
  if (rule.action && !hasMatcher(m)) throw new ApiError(400, `rule ${rule.id}: needs at least one matcher`);
  const problem = (rule.redirect && redirectProblem(rule.redirect, m))
    || (rule.headers || []).map(headerOpProblem).find(Boolean)
    || (rule.cors && corsProblem(rule.cors));
  if (problem) throw new ApiError(400, `rule ${rule.id}: ${problem}`);
  for (const hm of listsOf(m).headers) {
    if (Boolean(hm.regex) === Boolean(hm.equals) && !(hm.secret && hm.equals === '')) throw new ApiError(400, `rule ${rule.id} header matcher: set exactly one of regex or equals`);
  }
}

// Secret header values are kept apart by position and blanked in the stored rule; a blank value on save keeps the held one
function storeRuleSecrets(node, rule) {
  const list = (rule.matchers && rule.matchers.headers) || [];
  const previous = node.ruleSecrets[rule.id] || [];
  const held = list.map((hm, i) => {
    if (!hm.secret || hm.regex) return null;
    if (hm.equals) return hm.equals;
    if (!previous[i]) throw new ApiError(400, `rule ${rule.id} header matcher: enter the secret value`);
    return previous[i];
  });
  for (const hm of list) {
    if (hm.secret && !hm.regex) hm.equals = '';
  }
  if (held.some(Boolean)) node.ruleSecrets[rule.id] = held;
  else delete node.ruleSecrets[rule.id];
}

function ruleRoute(node, method, id, body) {
  if (method === 'DELETE' && id) delete node.ruleSecrets[id];
  if (method !== 'POST' && method !== 'PUT') return collectionRoute(node.rules, 'rule', method, id, body, node);
  const rule = clone(body);
  checkRuleShape(rule);
  storeRuleSecrets(node, rule);
  return collectionRoute(node.rules, 'rule', method, id, rule, node);
}

// Many rule changes in one step: everything is checked first and a failure leaves the rules as they were
function bulkRoute(node, body) {
  const replace = Array.isArray(body && body.replace) ? body.replace.map(clone) : [];
  const remove = Array.isArray(body && body.delete) ? body.delete : [];
  const ids = replace.map((r) => r.id);
  if (new Set(ids).size !== ids.length) throw new ApiError(400, 'a rule id appears twice in replace');
  replace.forEach(checkRuleShape);
  for (const id of remove) {
    if (!node.rules.some((r) => r.id === id)) throw new ApiError(404, `rule ${id} not found`);
  }
  const rulesBefore = clone(node.rules);
  const secretsBefore = clone(node.ruleSecrets);
  const out = { created: 0, replaced: 0, deleted: 0 };
  try {
    for (const rule of replace) {
      storeRuleSecrets(node, rule);
      const at = node.rules.findIndex((r) => r.id === rule.id);
      if (at >= 0) {
        node.rules[at] = rule;
        out.replaced += 1;
      } else {
        node.rules.push(rule);
        out.created += 1;
      }
    }
    for (const id of remove) {
      node.rules = node.rules.filter((r) => r.id !== id);
      delete node.ruleSecrets[id];
      out.deleted += 1;
    }
  } catch (ex) {
    node.rules = rulesBefore;
    node.ruleSecrets = secretsBefore;
    throw ex;
  }
  audit(node, 'firewall.bulk', `${out.created} created, ${out.replaced} replaced, ${out.deleted} deleted`);
  return out;
}

function eventsIn(node, win, siteId) {
  tickEvents(node);
  const [count, step] = WINDOWS[win] || WINDOWS['24h'];
  const since = Date.now() - count * step * 1000;
  return node.events.filter((e) => e.ts_ms >= since && (!siteId || e.site === siteId));
}

function tally(events, keyOf, limit = 100) {
  const map = new Map();
  for (const e of events) {
    const key = keyOf(e);
    const cur = map.get(key) || { key, count: 0, bytes: 0 };
    cur.count += 1;
    cur.bytes += e.bytes_out || 0;
    map.set(key, cur);
  }
  return [...map.values()].sort((a, b) => b.count - a.count).slice(0, limit);
}

const TOP_FIELDS = {
  paths: (e) => e.path, hosts: (e) => e.host, referers: (e) => e.referer || '', agents: (e) => e.user_agent, content_types: (e) => e.content_type,
  statuses: (e) => String(e.status), ips: (e) => e.client_ip, languages: (e) => (e.accept_language || '').split(',')[0].trim(),
};

function botSummary(events) {
  const flagged = events.filter((e) => e.bot_class && e.bot_class !== 'human');
  const signals = new Map();
  for (const e of events) for (const s of (e.bot_signals || '').split(',').filter(Boolean)) signals.set(s, (signals.get(s) || 0) + 1);
  const labels = ['0-19', '20-39', '40-59', '60-79', '80-100'];
  const buckets = labels.map((key, i) => ({ key, count: events.filter((e) => Math.min(4, Math.floor((e.bot_score || 0) / 20)) === i).length, bytes: 0 }));
  return {
    total_requests: events.length, bot_requests: flagged.length, bot_share_pct: events.length ? (flagged.length / events.length) * 100 : 0,
    classes: tally(events, (e) => e.bot_class || 'human'),
    signals: [...signals].map(([key, count]) => ({ key, count, bytes: 0 })).sort((a, b) => b.count - a.count).slice(0, 10),
    agents: tally(flagged, (e) => e.user_agent, 10), score_buckets: buckets,
  };
}

function csvCell(value) {
  const text = String(value ?? '');
  return /[",\n\r]/.test(text) ? '"' + text.replace(/"/g, '""') + '"' : text;
}

function toRows(rows, format) {
  if (format === 'ndjson') return rows.map((r) => JSON.stringify(r)).join('\n') + '\n';
  const cols = rows.length ? Object.keys(rows[0]) : [];
  return [cols.join(','), ...rows.map((r) => cols.map((c) => csvCell(r[c])).join(','))].join('\n') + '\n';
}

function exportBody(node, q) {
  const kind = q.get('kind');
  const format = q.get('format') || 'csv';
  if (!['requests', 'hourly', 'bots', 'top'].includes(kind)) throw new ApiError(400, 'unknown export kind');
  if (!['csv', 'ndjson'].includes(format)) throw new ApiError(400, 'unknown export format');
  const num = (k) => (q.get(k) ? Number(q.get(k)) : null);
  const from = num('from');
  const to = num('to');
  const limit = num('limit') || 100000;
  tickEvents(node);
  const site = q.get('site');
  const matches = (e) => (!site || e.site === site) && (from === null || e.ts_ms >= from) && (to === null || e.ts_ms <= to)
    && (num('status_min') === null || e.status >= num('status_min')) && (num('status_max') === null || e.status <= num('status_max'))
    && (!q.get('bot_class') || e.bot_class === q.get('bot_class')) && (num('min_bot_score') === null || (e.bot_score || 0) >= num('min_bot_score'))
    && (!q.get('host') || e.host === q.get('host')) && (!q.get('path_prefix') || e.path.startsWith(q.get('path_prefix')))
    && (!q.get('client_ip') || e.client_ip === q.get('client_ip')) && (!q.get('method') || e.method === q.get('method'));
  const events = node.events.filter(matches);
  let rows;
  if (kind === 'requests') rows = events.slice(0, limit).map((e) => ({ ...e, blocked: e.blocked || '' }));
  else if (kind === 'top') {
    const field = TOP_FIELDS[q.get('top')];
    if (!field) throw new ApiError(400, 'unknown top kind');
    rows = tally(events, field, limit);
  } else if (kind === 'bots') {
    const sm = botSummary(events);
    rows = [{ section: 'summary', key: 'bot_share_pct', count: sm.bot_share_pct.toFixed(2) }];
    for (const part of ['classes', 'signals', 'agents', 'score_buckets']) rows.push(...sm[part].map((i) => ({ section: part, key: i.key, count: i.count })));
  } else {
    const hours = new Map();
    for (const e of events) {
      const hour = Math.floor(e.ts_ms / 3600000) * 3600000;
      const cur = hours.get(hour) || { hour_ts_ms: hour, requests: 0, bytes_out: 0, errors: 0 };
      cur.requests += 1;
      cur.bytes_out += e.bytes_out || 0;
      cur.errors += e.status >= 400 ? 1 : 0;
      hours.set(hour, cur);
    }
    rows = [...hours.values()].sort((a, b) => a.hour_ts_ms - b.hour_ts_ms).slice(0, limit);
  }
  return toRows(rows, format);
}

async function nodeRoute(node, method, seg, q, body) {
  const [a, b, c] = seg;
  if (a === 'node') return nodeInfo(node);
  if (a === 'sites') return siteRoute(node, method, seg.slice(1), body);
  if (a === 'pages') {
    const inUse = (id) => (node.sites.find((s) => s.maintenance.page_id === id) || {}).name;
    return collectionRoute(node.pages, 'page', method, b, body, node, inUse);
  }
  if (a === 'firewall' && b === 'bulk') {
    if (method !== 'POST') throw new ApiError(405, 'method not allowed');
    return bulkRoute(node, body);
  }
  if (a === 'firewall' && b === 'rules') return ruleRoute(node, method, c, body);
  if (a === 'firewall' && b === 'presets') {
    if (c && seg[3] === 'apply') {
      const preset = node.presets.find((p) => p.name === c);
      if (!preset) throw new ApiError(404, 'unknown preset');
      const added = preset.rules.map((r) => ({ ...clone(r), id: 'r-' + Math.random().toString(36).slice(2, 8) }));
      node.rules.push(...added);
      audit(node, 'firewall.preset', `preset ${c} applied`);
      return clone(added);
    }
    return clone(node.presets);
  }
  if (a === 'analytics') {
    const win = q.get('window') || '24h';
    if (b === 'summary') return summary(node, win, q.get('site'));
    if (b === 'timeseries') return timeseries(node, win, q.get('site'));
    if (b === 'requests') return clone(filterEvents(node, q));
    if (b === 'bots') return botSummary(eventsIn(node, win, q.get('site')));
    if (b === 'top') {
      const field = TOP_FIELDS[q.get('kind')];
      if (!field) throw new ApiError(400, 'unknown top kind');
      return { items: tally(eventsIn(node, win, q.get('site')), field, Number(q.get('limit')) || 10) };
    }
    if (b === 'stats') {
      const times = node.events.map((e) => e.ts_ms);
      return {
        rows: node.events.length, db_bytes: node.events.length * 612, oldest_ts_ms: times.length ? Math.min(...times) : null,
        newest_ts_ms: times.length ? Math.max(...times) : null, write_batches: 412, write_errors: 0,
      };
    }
    if (b === 'export') return exportBody(node, q);
    if (node.idx === 1 && ['archives', 'backup', 'cut', 'restore'].includes(b)) throw new ApiError(404, 'Not Found');
    if (['archives', 'backup', 'cut', 'restore'].includes(b)) return archiveRoute(node, method, b, seg[2], body);
  }
  if (a === 'certificates') return certificateRoute(node, method, b, body);
  if (a === 'cloudflare' && b === 'ranges' && method === 'GET') return cloudflareRoute(node);
  if (a === 'settings') {
    if (method === 'PUT') {
      if (!body || !body.retention) throw new ApiError(400, 'invalid settings');
      if (body.https_port !== null && body.https_port !== undefined && !(Number.isInteger(body.https_port) && body.https_port >= 1 && body.https_port <= 65535)) throw new ApiError(400, 'https_port must be between 1 and 65535');
      const ranges = body.cloudflare_ranges || [];
      if (!Array.isArray(ranges) || ranges.some((r) => typeof r !== 'string' || !CIDR_LIKE.test(r))) throw new ApiError(400, 'cloudflare_ranges must be CIDR ranges');
      node.settings = clone(body);
      audit(node, 'settings.update', 'settings changed');
    }
    return clone(node.settings);
  }
  if (a === 'audit') return clone(node.audit.slice(0, Number(q.get('limit')) || 100));
  if (a === 'tokens') {
    if (method === 'GET') return clone(node.tokens);
    if (method === 'POST') {
      if (!body || !body.name) throw new ApiError(400, 'token needs a name');
      const token = { id: 't-' + Math.random().toString(36).slice(2, 7), name: body.name, created_at: iso(Date.now()), last_used_at: null };
      node.tokens.push(token);
      audit(node, 'token.create', `token ${body.name} created`);
      return { id: token.id, name: token.name, token: 'cite_' + randomText(40, TOKEN_ALPHABET) };
    }
    if (method === 'DELETE') {
      node.tokens = node.tokens.filter((t) => t.id !== b);
      return { ok: true };
    }
  }
  if (a === 'haproxy') {
    if (b === 'reload') {
      await sleep(500);
      node.hap = { configHash: Math.random().toString(16).slice(2, 14), lastReload: Date.now(), ok: true, error: '' };
      audit(node, 'haproxy.reload', 'config reloaded');
      return { ok: true, config_hash: node.hap.configHash };
    }
    if (b === 'config') return haproxyConfig(node);
    if (b === 'stats') {
      return {
        backends: node.sites.map((s, i) => ({
          name: 'bk_' + s.id, status: 'UP', sessions: 4 + ((i * 7) % 11), bytes_in: 52e6 * (i + 1), bytes_out: 2.1e9 / (i + 1),
          servers: s[s.active].targets.map((t, k) => ({ name: `${s.active}-${k + 1}`, status: node.down.has(t.addr) ? 'DOWN' : 'UP', check: 'L7OK' })),
        })),
      };
    }
  }
  throw new ApiError(404, 'not found');
}

const MOCK_CSRF = 'mock-csrf-token';

async function dashboardRoute(method, seg, q, body) {
  const [a, b] = seg;
  if (a === 'setup') {
    if (method === 'GET' && !b) return { needs_onboarding: state.needsOnboarding, needs_token: true };
    if (method === 'POST' && !b) {
      if (!body.setup_token) throw new ApiError(403, 'the setup token is not valid');
      if (!body.username || !body.password) throw new ApiError(400, 'username and password are required');
      state.username = body.username;
      const secret = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
      return { totp_uri: `otpauth://totp/Cite:${encodeURIComponent(body.username)}?secret=${secret}&issuer=Cite`, totp_secret: secret, qr_svg: fakeQr(secret) };
    }
    if (method === 'POST' && b === 'confirm') {
      if (!/^\d{6}$/.test(String(body.code))) throw new ApiError(400, 'That code is not valid');
      state.needsOnboarding = false;
      return { ok: true };
    }
  }
  if (a === 'session') {
    if (method === 'POST') {
      if (!body.username || !body.password || !/^\d{6}$/.test(String(body.totp))) throw new ApiError(401, 'invalid credentials');
      state.loggedIn = true;
      state.username = body.username;
      return { ok: true, username: body.username, csrf: MOCK_CSRF };
    }
    if (method === 'DELETE') {
      state.loggedIn = false;
      return { ok: true };
    }
    if (!state.loggedIn) throw new ApiError(401, 'not signed in');
    return { username: state.username, csrf: MOCK_CSRF };
  }
  if (!state.loggedIn) throw new ApiError(401, 'not signed in');
  if (a === 'nodes') {
    if (!b) {
      if (method === 'GET') return state.nodes.map((n) => ({ name: n.name, url: n.url, online: true, version: n.version }));
      if (method === 'POST') {
        if (!body.name || !body.url || !body.token) throw new ApiError(400, 'name, url and token are required');
        if (state.nodes.some((n) => n.name === body.name)) throw new ApiError(409, `node ${body.name} already exists`);
        state.nodes.push(seedNode(body.name, body.url, state.nodes.length));
        return { ok: true };
      }
    }
    if (b === 'summary') return state.nodes.map((n) => ({ name: n.name, online: true, node: nodeInfo(n) }));
    if (seg.length === 2 && method === 'DELETE') {
      findNode(b);
      state.nodes = state.nodes.filter((n) => n.name !== b);
      return { ok: true };
    }
    return nodeRoute(findNode(b), method, seg.slice(2), q, body);
  }
  if (a === 'deployments' && method === 'POST') {
    const results = [];
    for (const name of body.nodes || []) {
      const node = state.nodes.find((n) => n.name === name);
      try {
        if (!node) throw new ApiError(404, `node ${name} is not configured`);
        checkSiteShape(body.site);
        if (typeof body.github_token === 'string' && body.github_token.trim() && !body.site.source) throw new ApiError(400, 'github_token needs a site with a source');
        if (node.sites.some((s) => s.id === body.site.id)) throw new ApiError(409, `site ${body.site.id} already exists`);
        node.sites.push({ ...clone(body.site), history: [] });
        audit(node, 'site.create', `site ${body.site.id} created (${body.mode})`);
        results.push({ node: name, ok: true });
      } catch (err) {
        results.push({ node: name, ok: false, error: err.message });
      }
    }
    if (!results.some((r) => r.ok)) throw new ApiError(409, results.map((r) => r.error).join('; ') || 'no nodes selected');
    return { results };
  }
  throw new ApiError(404, 'not found');
}

export async function mockRequest(method, rawPath, body) {
  if (!state.nodes.length) {
    state.nodes.push(seedNode('edge-fra', 'https://fra.edge.example.com:8443', 0), seedNode('edge-nyc', 'https://nyc.edge.example.com:8443', 1));
  }
  await sleep(70 + Math.random() * 190);
  const [pathname, search] = rawPath.split('?');
  const seg = pathname.split('/').filter(Boolean).map(decodeURIComponent);
  const result = await dashboardRoute(method, seg, new URLSearchParams(search || ''), body || {});
  return typeof result === 'string' ? result : clone(result);
}
