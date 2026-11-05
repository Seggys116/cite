// Pure helpers for the bot panels and the export dialog; nothing here touches the DOM so node can test it.

export const BOT_CLASSES = [
  { key: 'human', label: 'Human', cls: 'bc-human', help: 'Looks like a real browser: the headers agree with each other and with the user agent.' },
  { key: 'suspect', label: 'Suspect', cls: 'bc-suspect', help: 'Some headers are missing or inconsistent. Could be a privacy tool, an old client or an unlabelled bot.' },
  { key: 'crawler', label: 'Crawler', cls: 'bc-crawler', help: 'A search engine, social preview or monitoring crawler that names itself in the user agent.' },
  { key: 'tool', label: 'Tool', cls: 'bc-tool', help: 'A scripting library or command line client such as curl, python-requests or a headless browser.' },
  { key: 'bot', label: 'Bot', cls: 'bc-bot', help: 'Strong evidence of automation: a high score from several independent signals.' },
];

const UNKNOWN_CLASS = { key: '', label: 'Unknown', cls: 'bc-unknown', help: 'This request was recorded without a bot verdict.' };

export const SCORE_BUCKETS = ['0-19', '20-39', '40-59', '60-79', '80-100'];

export const BOT_METHOD_HELP = 'Detection reads the request headers first (Accept, Accept-Language, Sec-Fetch-*, Sec-CH-UA, protocol and TLS version) and then the user agent. '
  + 'The score from 0 to 100 is a heuristic, not proof: a determined bot can imitate a browser, and an unusual browser can look suspect.';

export const TOP_KINDS = [
  { value: 'paths', label: 'Paths' },
  { value: 'hosts', label: 'Hosts' },
  { value: 'referers', label: 'Referers' },
  { value: 'agents', label: 'User agents' },
  { value: 'content_types', label: 'Content types' },
  { value: 'statuses', label: 'Status codes' },
  { value: 'ips', label: 'Client IPs' },
  { value: 'languages', label: 'Languages' },
];

export const EXPORT_KINDS = [
  { value: 'requests', label: 'Requests', help: 'One row per recorded request, newest first.' },
  { value: 'hourly', label: 'Hourly rollups', help: 'Request, byte and error totals per hour.' },
  { value: 'bots', label: 'Bot summary', help: 'Bot share, classes, signals, agents and score distribution.' },
  { value: 'top', label: 'Top list', help: 'The most frequent values of one field.' },
];

export const EXPORT_FORMATS = [
  { value: 'csv', label: 'CSV' },
  { value: 'ndjson', label: 'NDJSON' },
];

export const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];

// Kinds that read individual requests, so the per-request filters mean something for them
const FILTERED_KINDS = ['requests', 'bots'];

export const WINDOW_MS = { '15m': 15 * 60e3, '1h': 3600e3, '24h': 86400e3, '7d': 7 * 86400e3, '30d': 30 * 86400e3 };

export const MAX_EXPORT_ROWS = 10000000;
export const DEFAULT_EXPORT_ROWS = 100000;

const SIGNAL_HELP = {
  empty_ua: 'The request sent no user agent.',
  missing_accept_language: 'Browsers always send Accept-Language; this request did not.',
  missing_accept: 'No Accept header, which real browsers always send.',
  accept_wildcard_only: 'Accept was only a wildcard, typical of scripts and libraries.',
  missing_accept_encoding: 'No Accept-Encoding, although every modern browser offers compression.',
  no_sec_fetch: 'A browser-style user agent without Sec-Fetch-* headers, which current browsers add themselves.',
  sec_fetch_partial: 'Only some of the Sec-Fetch-* headers were present.',
  sec_fetch_inconsistent: 'The Sec-Fetch-* values contradict each other.',
  no_sec_ch_ua: 'A Chromium user agent without the Sec-CH-UA client hint.',
  sec_ch_ua_mismatch: 'Sec-CH-UA does not match the browser named in the user agent.',
  http_1_0: 'The request used HTTP/1.0, which browsers no longer send.',
  http1_modern_browser: 'A modern browser user agent over plain HTTP/1.x, which is unusual for a real browser.',
  old_tls: 'The connection used an outdated TLS version.',
  post_no_referer: 'A POST with no Referer, as many form-spamming scripts send.',
};

export function botClass(key) {
  const wanted = String(key || '').toLowerCase();
  return BOT_CLASSES.find((c) => c.key === wanted) || UNKNOWN_CLASS;
}

// Always returns the five known classes in a stable order, so colours and positions never shift between windows
export function classBreakdown(items) {
  const counts = new Map((items || []).map((i) => [String(i.key).toLowerCase(), Number(i.count) || 0]));
  const out = BOT_CLASSES.map((c) => ({ ...c, value: counts.get(c.key) || 0 }));
  for (const [key, value] of counts) {
    if (!BOT_CLASSES.some((c) => c.key === key)) out.push({ ...UNKNOWN_CLASS, key, label: key || 'Unknown', value });
  }
  return out;
}

export function bucketClass(label) {
  const i = SCORE_BUCKETS.indexOf(label);
  return 'sb-' + (i < 0 ? 0 : i);
}

export function scoreBuckets(items) {
  const counts = new Map((items || []).map((i) => [String(i.key), Number(i.count) || 0]));
  return SCORE_BUCKETS.map((label) => ({ label, value: counts.get(label) || 0, cls: 'bc-fill ' + bucketClass(label), title: `Score ${label}` }));
}

export function scoreBandClass(score) {
  const n = Number(score);
  if (!Number.isFinite(n)) return 'sb-0';
  return 'sb-' + Math.min(4, Math.max(0, Math.floor(n / 20)));
}

export function parseSignals(text) {
  const out = [];
  for (const part of String(text || '').split(',')) {
    const t = part.trim();
    if (t && !out.includes(t)) out.push(t);
  }
  return out;
}

export function signalLabel(key) {
  const k = String(key || '');
  if (k.startsWith('ua_')) return 'UA ' + k.slice(3).replace(/_/g, ' ');
  return k.replace(/_/g, ' ');
}

export function signalHelp(key) {
  const k = String(key || '');
  if (SIGNAL_HELP[k]) return SIGNAL_HELP[k];
  if (k.startsWith('ua_')) return 'The user agent names this client: ' + k.slice(3).replace(/_/g, ' ') + '.';
  return 'A heuristic signal raised by the detector.';
}

// The API sends the share as a percentage already
export function fmtSharePct(pct) {
  const n = Number(pct);
  if (!Number.isFinite(n)) return '0%';
  return (n >= 10 || n === 0 ? n.toFixed(n === 0 ? 0 : 1) : n.toFixed(2)) + '%';
}

export function shareOf(count, total) {
  const t = Number(total) || 0;
  return t > 0 ? (Number(count) || 0) / t : 0;
}

export function hasBotData(event) {
  if (!event) return false;
  return Boolean(event.bot_class) || (event.bot_score !== undefined && event.bot_score !== null);
}

export function retentionText(settings) {
  const r = settings && settings.retention;
  if (!r) return 'not reported';
  const parts = [];
  if (r.minute_buckets_hours) parts.push(`${r.minute_buckets_hours} h of minute data`);
  if (r.hour_buckets_days === 0) parts.push('hourly data kept forever');
  else if (r.hour_buckets_days) {
    const fate = r.archive_before_delete === true ? ', archived before deletion' : r.archive_before_delete === false ? ', then deleted' : '';
    parts.push(`${r.hour_buckets_days} days of hourly data${fate}`);
  }
  if (r.recent_events) parts.push(`last ${Number(r.recent_events).toLocaleString('en')} requests`);
  return parts.length ? parts.join(', ') : 'not reported';
}

export function windowRange(win, now = Date.now()) {
  const span = WINDOW_MS[win];
  return span ? { from: now - span, to: now } : null;
}

// A datetime-local value has no zone, so it is read in the browser's local time
export function parseLocalDateTime(text) {
  if (!text) return null;
  const ms = new Date(text).getTime();
  return Number.isFinite(ms) ? ms : null;
}

const IPV4_RE = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

export function isIpAddress(text) {
  const t = String(text || '');
  if (IPV4_RE.test(t)) return true;
  return t.includes(':') && /^[0-9a-f:.]+$/i.test(t) && (t.match(/::/g) || []).length <= 1 && t.length <= 45;
}

function intField(text, label, min, max) {
  const t = String(text ?? '').trim();
  if (t === '') return { value: null };
  if (!/^\d+$/.test(t)) return { error: `${label} must be a whole number.` };
  const n = Number(t);
  if (n < min || n > max) return { error: `${label} must be between ${min} and ${max}.` };
  return { value: n };
}

// Turns the dialog state into API parameters, or an error message for the first problem found
export function buildExportParams(form, now = Date.now()) {
  const kind = EXPORT_KINDS.some((k) => k.value === form.kind) ? form.kind : null;
  if (!kind) return { error: 'Choose what to export.' };
  const format = EXPORT_FORMATS.some((f) => f.value === form.format) ? form.format : null;
  if (!format) return { error: 'Choose CSV or NDJSON.' };
  const params = { kind, format };
  if (kind === 'top') {
    if (!TOP_KINDS.some((t) => t.value === form.top)) return { error: 'Choose which top list to export.' };
    params.top = form.top;
  }
  let range = null;
  if (form.rangeMode === 'custom') {
    const from = parseLocalDateTime(form.from);
    const to = parseLocalDateTime(form.to);
    if (from === null || to === null) return { error: 'Enter both a start and an end time.' };
    if (from >= to) return { error: 'The start time must be before the end time.' };
    range = { from, to };
  } else {
    range = windowRange(form.window, now);
    if (!range) return { error: 'Pick a time window.' };
  }
  params.from = range.from;
  params.to = range.to;
  if (form.site) params.site = form.site;

  if (FILTERED_KINDS.includes(kind)) {
    const lo = intField(form.statusMin, 'Minimum status', 100, 599);
    const hi = intField(form.statusMax, 'Maximum status', 100, 599);
    const score = intField(form.minScore, 'Minimum bot score', 0, 100);
    for (const f of [lo, hi, score]) if (f.error) return { error: f.error };
    if (lo.value !== null && hi.value !== null && lo.value > hi.value) return { error: 'Minimum status is above maximum status.' };
    if (lo.value !== null) params.status_min = lo.value;
    if (hi.value !== null) params.status_max = hi.value;
    if (score.value !== null) params.min_bot_score = score.value;
    if (form.botClass) {
      if (!BOT_CLASSES.some((c) => c.key === form.botClass)) return { error: 'Unknown bot class.' };
      params.bot_class = form.botClass;
    }
    const host = String(form.host || '').trim();
    if (host) {
      if (host.length > 253 || /[\s/]/.test(host)) return { error: 'Host must be a plain host name.' };
      params.host = host;
    }
    const prefix = String(form.pathPrefix || '').trim();
    if (prefix) {
      if (!prefix.startsWith('/') || prefix.length > 512) return { error: 'Path prefix must start with a slash.' };
      params.path_prefix = prefix;
    }
    const ip = String(form.clientIp || '').trim();
    if (ip) {
      if (!isIpAddress(ip)) return { error: 'Client IP is not a valid address.' };
      params.client_ip = ip;
    }
    if (form.method) {
      if (!METHODS.includes(form.method)) return { error: 'Unknown method.' };
      params.method = form.method;
    }
  }

  const limit = intField(form.limit, 'Row limit', 1, MAX_EXPORT_ROWS);
  if (limit.error) return { error: limit.error };
  if (limit.value !== null) params.limit = limit.value;
  return { params };
}

export function toQuery(params) {
  const out = new URLSearchParams();
  for (const [key, val] of Object.entries(params || {})) {
    if (val !== undefined && val !== null && val !== '') out.set(key, String(val));
  }
  const text = out.toString();
  return text ? '?' + text : '';
}

export function exportPath(node, params) {
  return '/nodes/' + encodeURIComponent(node) + '/analytics/export' + toQuery(params);
}

export function exportFileName(params, now = Date.now()) {
  const stamp = new Date(now).toISOString().slice(0, 16).replace(/[-:]/g, '').replace('T', '-');
  const what = params.kind === 'top' ? 'top-' + params.top : params.kind;
  return `cite-${what}-${stamp}.${params.format === 'ndjson' ? 'ndjson' : 'csv'}`;
}
