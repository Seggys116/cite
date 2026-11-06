// Dev aid: mock certificate and alert routes; install(register) takes register(method, regex, handler), the regex is tested against the node-relative path without a leading slash.
import { ApiError } from './js/api.js';
import {
  ORIGIN_CA_VALIDITY, MAX_SELF_SIGNED_DAYS, nameProblem, parseHosts, tokenProblem, emailProblem,
} from './js/certissue.js';
import {
  ALERT_EVENTS, MAX_RECIPIENTS, MAX_WEBHOOKS, MAX_COOLDOWN_SECS, DEFAULT_COOLDOWN_SECS, maskUrl, urlProblem,
} from './js/alertslib.js';

const DAY = 86400000;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const iso = (ms) => new Date(ms).toISOString();
const jobs = new WeakMap();
const alertStore = new WeakMap();
const EVENT_VALUES = new Set(ALERT_EVENTS.map((e) => e.value));
const KINDS = new Set(['generic', 'discord', 'slack']);

function randomHex(length) {
  const bytes = new Uint8Array(Math.ceil(length / 2));
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('').slice(0, length);
}

function requireSupported(node) {
  if (node.idx === 1) throw new ApiError(404, 'Not Found');
}

function requireBody(body) {
  if (!body || typeof body !== 'object') throw new ApiError(400, 'expected a JSON body');
  return body;
}

function checkHosts(body) {
  const parsed = parseHosts(body.hosts);
  if (parsed.errors.length) throw new ApiError(400, parsed.errors[0]);
  return parsed.hosts;
}

function checkName(node, body, fallback) {
  const name = body.name === undefined ? fallback : body.name;
  const problem = nameProblem(name);
  if (problem || !name) throw new ApiError(400, problem || 'name is required');
  if (node.certs.some((c) => c.name === name)) throw new ApiError(409, `a certificate named ${name} already exists`);
  return name;
}

function addCert(node, { name, hosts, issuer, days, keyType }) {
  const cert = {
    id: ('01J' + randomHex(23)).toUpperCase(),
    name,
    subject: 'CN=' + hosts[0],
    sans: hosts,
    issuer,
    expires: Date.now() + days * DAY,
    key_type: keyType,
    created_at: iso(Date.now()),
    fingerprint: randomHex(64),
  };
  node.certs.push(cert);
  return cert;
}

function saved(node, cert) {
  const covered = node.sites.flatMap((s) => s.hosts).filter((host) => cert.sans.some((san) => (san.startsWith('*.')
    ? host.endsWith(san.slice(1)) && !host.slice(0, host.length - san.length + 1).includes('.') : host === san)));
  return {
    source: 'api',
    id: cert.id,
    name: cert.name,
    subject: cert.subject,
    sans: [...cert.sans],
    issuer: cert.issuer,
    not_before: iso(Date.now()).slice(0, 10),
    not_after: iso(cert.expires).slice(0, 10),
    days_left: Math.floor((cert.expires - Date.now()) / DAY),
    fingerprint_sha256: cert.fingerprint,
    key_type: cert.key_type,
    created_at: cert.created_at,
    covers: covered,
    warning: covered.length ? null : 'This certificate does not cover any site host on this node yet.',
  };
}

async function generate({ node, body }) {
  requireSupported(node);
  requireBody(body);
  const hosts = checkHosts(body);
  const name = checkName(node, body, hosts[0].replace(/^\*\./, 'wildcard-'));
  const days = body.days === undefined ? 365 : body.days;
  if (!Number.isInteger(days) || days < 1 || days > MAX_SELF_SIGNED_DAYS) throw new ApiError(400, `days must be between 1 and ${MAX_SELF_SIGNED_DAYS}`);
  await sleep(600);
  return saved(node, addCert(node, { name, hosts, issuer: 'Cite self-signed', days, keyType: 'ECDSA P-256' }));
}

async function originCa({ node, body }) {
  requireSupported(node);
  requireBody(body);
  const hosts = checkHosts(body);
  const name = checkName(node, body, 'origin-' + hosts[0].replace(/^\*\./, ''));
  const tokenIssue = tokenProblem(body.cloudflare_token);
  if (tokenIssue) throw new ApiError(400, tokenIssue);
  const days = body.validity_days === undefined ? 5475 : body.validity_days;
  if (!ORIGIN_CA_VALIDITY.some((v) => v.days === days)) throw new ApiError(400, 'validity_days is not one Cloudflare offers');
  await sleep(1400);
  if (body.cloudflare_token.startsWith('invalid')) throw new ApiError(403, 'Cloudflare rejected the token: Authentication error (10000)');
  if (hosts.some((h) => h.endsWith('.test'))) throw new ApiError(502, 'Cloudflare refused the request: hostname is not in a zone this token can see');
  return saved(node, addCert(node, { name, hosts, issuer: 'CloudFlare Origin SSL Certificate Authority', days, keyType: 'RSA 2048' }));
}

function jobsOf(node) {
  if (!jobs.has(node)) jobs.set(node, { list: [], managed: [] });
  return jobs.get(node);
}

// A job is pending for a few seconds and then ends; a host named fail.* or a token starting with "fail" makes it fail
function settleJob(node, job) {
  if (job.status !== 'pending') return;
  const age = Date.now() - job.started_ms;
  if (age < (job.willFail ? 6000 : 9000)) return;
  const store = jobsOf(node);
  if (job.willFail) {
    job.status = 'failed';
    job.error = `The DNS challenge for _acme-challenge.${job.hosts[0].replace(/^\*\./, '')} did not validate: the TXT record was not found after 60 seconds.`;
    store.managed.push({ id: job.job_id, hosts: job.hosts, status: 'failed', not_after: null, renew_at: null, staging: job.staging, error: job.error });
    return;
  }
  job.status = 'issued';
  const cert = addCert(node, {
    name: job.certName, hosts: job.hosts, issuer: job.staging ? '(STAGING) Pretend Pear X1' : 'Let\'s Encrypt R11', days: 90, keyType: 'ECDSA P-256',
  });
  store.managed.push({
    id: cert.id, hosts: job.hosts, status: 'issued', not_after: iso(cert.expires), renew_at: iso(cert.expires - 30 * DAY), staging: job.staging,
  });
}

function publicJob(job) {
  const out = {
    job_id: job.job_id, hosts: job.hosts, status: job.status, started_at: iso(job.started_ms),
  };
  if (job.error) out.error = job.error;
  return out;
}

async function acmeStart({ node, body }) {
  requireSupported(node);
  requireBody(body);
  const hosts = checkHosts(body);
  if (body.agree_tos !== true) throw new ApiError(400, 'agree_tos must be true to request a Let\'s Encrypt certificate');
  const mail = emailProblem(body.email);
  if (mail) throw new ApiError(400, mail);
  const tokenIssue = tokenProblem(body.cloudflare_token);
  if (tokenIssue) throw new ApiError(400, tokenIssue);
  const certName = checkName(node, body, 'le-' + hosts[0].replace(/^\*\./, ''));
  const store = jobsOf(node);
  if (store.list.some((j) => j.status === 'pending' && j.hosts.join() === hosts.join())) throw new ApiError(409, 'a request for these hosts is already running');
  await sleep(500);
  const job = {
    job_id: 'job-' + randomHex(12),
    hosts,
    status: 'pending',
    started_ms: Date.now(),
    staging: Boolean(body.staging),
    certName,
    willFail: hosts.some((h) => h.startsWith('fail.')) || body.cloudflare_token.startsWith('fail'),
  };
  store.list.unshift(job);
  return publicJob(job);
}

function acmeList({ node }) {
  requireSupported(node);
  const store = jobsOf(node);
  store.list.forEach((j) => settleJob(node, j));
  return { jobs: store.list.map(publicJob), managed: store.managed.map((m) => ({ ...m })) };
}

function acmeOne({ node, match }) {
  requireSupported(node);
  const store = jobsOf(node);
  const job = store.list.find((j) => j.job_id === match[1]);
  if (!job) throw new ApiError(404, 'no such job');
  settleJob(node, job);
  return publicJob(job);
}

function alertsOf(node) {
  if (!alertStore.has(node)) {
    alertStore.set(node, {
      enabled: false,
      cooldown_secs: DEFAULT_COOLDOWN_SECS,
      webhooks: [{
        id: 'wh-seed', name: 'Ops chat', kind: 'slack', url: 'https://hooks.slack.com/services/T000/B000/seeded-secret', events: ['site_unhealthy', 'site_recovered', 'cert_expiring'],
      }],
      email: null,
    });
  }
  return alertStore.get(node);
}

function alertsView(settings) {
  return {
    enabled: settings.enabled,
    webhooks: settings.webhooks.map((w) => ({ ...w, events: [...w.events], url: maskUrl(w.url) })),
    email: settings.email ? {
      host: settings.email.host,
      port: settings.email.port,
      tls: settings.email.tls,
      username: settings.email.username,
      password_set: Boolean(settings.email.password),
      from: settings.email.from,
      to: [...settings.email.to],
      events: [...settings.email.events],
    } : null,
    cooldown_secs: settings.cooldown_secs,
  };
}

const checkEvents = (events, label) => {
  if (!Array.isArray(events) || !events.length || events.some((e) => !EVENT_VALUES.has(e))) throw new ApiError(400, `${label}: events must be a non-empty list of known events`);
  return [...events];
};

async function alertsPut({ node, body }) {
  requireSupported(node);
  requireBody(body);
  const current = alertsOf(node);
  const incoming = Array.isArray(body.webhooks) ? body.webhooks : [];
  if (incoming.length > MAX_WEBHOOKS) throw new ApiError(400, `at most ${MAX_WEBHOOKS} webhooks are allowed`);
  const webhooks = incoming.map((w, i) => {
    const label = `webhook ${i + 1}`;
    const previous = w.id ? current.webhooks.find((x) => x.id === w.id) : null;
    if (w.id && !previous) throw new ApiError(400, `${label}: unknown id ${w.id}`);
    if (typeof w.name !== 'string' || !w.name.trim() || w.name.length > 64) throw new ApiError(400, `${label}: name must be 1 to 64 characters`);
    if (!KINDS.has(w.kind)) throw new ApiError(400, `${label}: kind must be generic, discord or slack`);
    const url = w.url ? w.url : previous && previous.url;
    const problem = urlProblem(url, { required: true });
    if (problem) throw new ApiError(400, `${label}: ${problem}`);
    return {
      id: previous ? previous.id : 'wh-' + randomHex(8), name: w.name.trim(), kind: w.kind, url, events: checkEvents(w.events, label),
    };
  });
  let email = null;
  if (body.email) {
    const e = body.email;
    const to = Array.isArray(e.to) ? e.to : [];
    if (typeof e.host !== 'string' || !e.host.trim()) throw new ApiError(400, 'email: host is required');
    if (!Number.isInteger(e.port) || e.port < 1 || e.port > 65535) throw new ApiError(400, 'email: port must be between 1 and 65535');
    if (!['starttls', 'tls', 'none'].includes(e.tls)) throw new ApiError(400, 'email: tls must be starttls, tls or none');
    if (emailProblem(e.from)) throw new ApiError(400, 'email: from is not a valid address');
    if (!to.length || to.length > MAX_RECIPIENTS || to.some((r) => emailProblem(r))) throw new ApiError(400, `email: give 1 to ${MAX_RECIPIENTS} valid recipients`);
    email = {
      host: e.host.trim(), port: e.port, tls: e.tls, username: e.username || '', password: e.password ? e.password : (current.email && current.email.password) || '', from: e.from, to, events: checkEvents(e.events, 'email'),
    };
  }
  const cooldown = body.cooldown_secs === undefined ? DEFAULT_COOLDOWN_SECS : body.cooldown_secs;
  if (!Number.isInteger(cooldown) || cooldown < 0 || cooldown > MAX_COOLDOWN_SECS) throw new ApiError(400, `cooldown_secs must be between 0 and ${MAX_COOLDOWN_SECS}`);
  await sleep(400);
  Object.assign(current, {
    enabled: Boolean(body.enabled), webhooks, email, cooldown_secs: cooldown,
  });
  return alertsView(current);
}

async function alertsTest({ node, body }) {
  requireSupported(node);
  requireBody(body);
  const current = alertsOf(node);
  await sleep(700);
  if (body.target === 'email') {
    if (!current.email) throw new ApiError(400, 'email alerts are not configured');
    return current.email.host.includes('fail') ? { ok: false, error: 'could not connect to the mail server: connection refused' } : { ok: true };
  }
  const id = typeof body.target === 'string' && body.target.startsWith('webhook:') ? body.target.slice(8) : '';
  const hook = current.webhooks.find((w) => w.id === id);
  if (!hook) throw new ApiError(400, 'unknown test target');
  return hook.url.includes('fail') ? { ok: false, error: 'the webhook answered HTTP 404' } : { ok: true };
}

export function install(register) {
  register('POST', /^certificates\/generate$/, generate);
  register('POST', /^certificates\/origin-ca$/, originCa);
  register('POST', /^certificates\/acme$/, acmeStart);
  register('GET', /^certificates\/acme$/, acmeList);
  register('GET', /^certificates\/acme\/([^/]+)$/, acmeOne);
  register('GET', /^alerts$/, ({ node }) => {
    requireSupported(node);
    return alertsView(alertsOf(node));
  });
  register('PUT', /^alerts$/, alertsPut);
  register('POST', /^alerts\/test$/, alertsTest);
}
