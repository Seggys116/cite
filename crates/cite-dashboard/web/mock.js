// Dev aid: an in-memory stand-in for the dashboard API, enabled with ?mock=1 (add &setup=1 for onboarding, &login=1 to start signed out)
import { ApiError } from './js/api.js';

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

// ---- seed data ----

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
      id: 'shop', name: 'Storefront', hosts: ['shop.example.com', 'www.example.com'], path_regex: null, kind: 'site',
      blue: { targets: [target(1, 11, 8080), target(1, 12, 8080)], label: 'v2.14.0' },
      green: { targets: [target(1, 21, 8080), target(1, 22, 8080)], label: 'v2.13.4' },
      active: 'blue', maintenance: { enabled: false, page_id: null }, health, source: null,
      history: hist([[170, 'green', 'promote', 'Release 2.13.4'], [52, 'blue', 'promote', 'Release 2.14.0-rc1'], [51, 'green', 'rollback', 'Checkout regression'], [6, 'blue', 'promote', 'Release 2.14.0']]),
    },
    {
      id: 'api', name: 'Public API', hosts: ['api.example.com'], path_regex: '^/v1/', kind: 'api',
      blue: { targets: [target(2, 11, 9000)], label: null },
      green: { targets: [target(2, 21, 9000)], label: null },
      active: 'green', maintenance: { enabled: false, page_id: null }, health: { ...health, path: '/v1/health' }, source: null,
      history: hist([[300, 'blue', 'promote', 'Initial deploy'], [28, 'green', 'promote', 'Add pagination to orders'], [27, 'blue', 'switch', 'Manual flip while testing'], [26, 'green', 'switch', 'Back to green']]),
    },
    {
      id: 'docs', name: 'Documentation', hosts: ['docs.example.com'], path_regex: null, kind: 'site',
      blue: { targets: [target(3, 11, 3000)], label: null },
      green: { targets: [target(3, 21, 3000)], label: null },
      active: 'blue', maintenance: { enabled: nodeIdx === 1, page_id: 'scheduled' }, health, source: { repo: 'https://git.example.com/docs.git', branch: 'main' },
      history: hist([[400, 'blue', 'promote', 'Initial deploy'], [90, 'green', 'failed', 'Health check timed out']]),
    },
  ];
}

function seedRules() {
  const none = { path_regex: null, path_prefix: null, methods: [], user_agent_regex: null, cidrs: [], host: null };
  return [
    { id: 'r-wp-login', name: 'WordPress login probes', enabled: true, action: 'deny', matchers: { ...none, path_regex: '^/wp-(login|admin)' }, site: null },
    { id: 'r-env', name: 'Dotfile and VCS leaks', enabled: true, action: 'deny', matchers: { ...none, path_regex: '/\\.(env|git)(/|$)' }, site: null },
    { id: 'r-phpmyadmin', name: 'phpMyAdmin scans', enabled: true, action: 'drop', matchers: { ...none, path_prefix: '/phpmyadmin' }, site: null },
    { id: 'r-scanner-ua', name: 'Known scanner agents', enabled: true, action: 'tarpit', matchers: { ...none, user_agent_regex: '(sqlmap|nikto|masscan)' }, site: null },
    { id: 'r-trace', name: 'Odd HTTP methods', enabled: true, action: 'deny', matchers: { ...none, methods: ['TRACE', 'CONNECT'] }, site: null },
    { id: 'r-badnet', name: 'Abusive network', enabled: false, action: 'deny', matchers: { ...none, cidrs: ['203.0.113.0/24'] }, site: 'shop' },
  ];
}

const RULE_HITS = [['r-wp-login', 14], ['r-env', 11], ['r-phpmyadmin', 7], ['r-scanner-ua', 5], ['r-trace', 2], ['r-badnet', 1]];

function seedPresets() {
  const none = { path_regex: null, path_prefix: null, methods: [], user_agent_regex: null, cidrs: [], host: null };
  const rule = (name, action, matchers) => ({ id: '', name, enabled: true, action, matchers: { ...none, ...matchers }, site: null });
  return [
    { name: 'sensitive-files', title: 'Sensitive files', description: 'Blocks requests for dotfiles, backups, dumps and key material that should never be public.', rules: [rule('Dotfiles', 'deny', { path_regex: '/\\.(env|git|svn|htaccess)' }), rule('Backups and dumps', 'deny', { path_regex: '\\.(bak|sql|old|swp)$' }), rule('Key material', 'deny', { path_regex: '\\.(pem|key|p12)$' })] },
    { name: 'cms-probes', title: 'CMS probes', description: 'Stops WordPress, Joomla and phpMyAdmin probing on sites that do not run them.', rules: [rule('WordPress', 'deny', { path_regex: '^/wp-(admin|login|content|includes)' }), rule('xmlrpc', 'deny', { path_prefix: '/xmlrpc.php' }), rule('phpMyAdmin', 'drop', { path_prefix: '/phpmyadmin' })] },
    { name: 'scanners', title: 'Scanners', description: 'Tarpits well-known vulnerability scanners by their user agent.', rules: [rule('Scanner agents', 'tarpit', { user_agent_regex: '(sqlmap|nikto|masscan|nmap|zgrab)' })] },
    { name: 'odd-methods', title: 'Odd methods', description: 'Rejects TRACE, CONNECT and other methods no real client sends to a website.', rules: [rule('Unusual methods', 'deny', { methods: ['TRACE', 'CONNECT'] })] },
  ];
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
      http_port: 80, https_port: 443, max_conn: 20000, client_timeout_ms: 30000, server_timeout_ms: 60000, connect_timeout_ms: 3000,
      per_ip_rate_limit: 600, max_body_bytes: null,
      retention: { recent_events: 5000, minute_buckets_hours: 48, hour_buckets_days: 90, audit_days: 365, persist_interval_secs: 60, store_user_agents: true, store_client_ips: true },
    },
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

// ---- traffic synthesis ----

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
  return {
    ts_ms: ts, client_ip: client, host: pick(rnd, site.hosts), method, path, query_len: rnd() < 0.2 ? Math.floor(rnd() * 90) : 0, status,
    bytes_in: 200 + Math.floor(rnd() * 900), bytes_out: rule ? 0 : status === 304 ? 0 : Math.floor(Math.exp(6.5 + rnd() * 5)),
    total_ms: rule ? 0 : total, user_agent: scan ? pick(rnd, ['sqlmap/1.7.2#stable (https://sqlmap.org)', 'Nikto/2.5.0', AGENTS[3]]) : pick(rnd, AGENTS),
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
    const diurnal = 0.62 + 0.38 * Math.sin(((hour - 8) / 24) * Math.PI * 2);
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

// ---- helpers for state changes ----

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

function checkSiteShape(site) {
  if (!site || !/^[a-z0-9][a-z0-9-]{0,62}$/.test(site.id || '')) throw new ApiError(400, 'invalid site id');
  if (!site.name || !Array.isArray(site.hosts) || !site.hosts.length) throw new ApiError(400, 'site needs a name and at least one host');
  if (site.path_regex) {
    try {
      new RegExp(site.path_regex);
    } catch (err) {
      throw new ApiError(400, 'invalid path regex');
    }
  }
}

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

// ---- routing ----

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
  };
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
      const { name, hosts, path_regex: pathRegex, kind, health, source } = clone(body);
      Object.assign(site, { name, hosts, path_regex: pathRegex, kind, health, source });
      audit(node, 'site.update', `site ${id} updated`);
      return clone(site);
    }
    if (method === 'DELETE') {
      node.sites.splice(node.sites.indexOf(site), 1);
      audit(node, 'site.delete', `site ${id} deleted`);
      return { ok: true };
    }
  }
  if (method !== 'POST') throw new ApiError(405, 'method not allowed');
  const idle = site.active === 'blue' ? 'green' : 'blue';
  if (action === 'deploy') {
    const targets = (body && body.targets) || [];
    if (!targets.length) throw new ApiError(400, 'deploy needs at least one target');
    await sleep(1600);
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

async function nodeRoute(node, method, seg, q, body) {
  const [a, b, c] = seg;
  if (a === 'node') return nodeInfo(node);
  if (a === 'sites') return siteRoute(node, method, seg.slice(1), body);
  if (a === 'pages') {
    const inUse = (id) => (node.sites.find((s) => s.maintenance.page_id === id) || {}).name;
    return collectionRoute(node.pages, 'page', method, b, body, node, inUse);
  }
  if (a === 'firewall' && b === 'rules') return collectionRoute(node.rules, 'rule', method, c, body, node);
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
  }
  if (a === 'settings') {
    if (method === 'PUT') {
      if (!body || !body.retention) throw new ApiError(400, 'invalid settings');
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
      return { id: token.id, name: token.name, token: 'cite_' + Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2) };
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
