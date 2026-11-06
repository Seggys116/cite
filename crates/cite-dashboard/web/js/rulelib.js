// Pure helpers for firewall rules: they mirror the node's validation so mistakes show before a save, and build the request body.
import { compileProblem } from './regexlib.js';

export const MAX_TEMPLATE_LEN = 512;
export const MAX_PATTERN_LEN = 256;
export const MAX_HEADER_OPS = 16;
export const MAX_CORS_ENTRIES = 32;
export const MAX_HEADER_VALUE = 512;
export const MAX_MATCH_VALUE = 256;
export const MAX_CORS_MAX_AGE = 86400;
export const REDIRECT_STATUSES = [301, 302, 307, 308];
export const PLACEHOLDERS = ['{scheme}', '{host}', '{www_host}', '{apex_host}', '{path}', '{query}'];
export const KEEP_SECRET_NOTE = 'The stored value is kept. Type a new value to replace it.';

export const KINDS = [
  { value: 'block', label: 'Block', text: 'Stop matching requests with a 403, a silent drop or a tarpit.' },
  { value: 'redirect', label: 'Redirect', text: 'Answer matching requests with a redirect to another address.' },
  { value: 'headers', label: 'Headers and CORS', text: 'Let matching requests through, with headers changed or CORS handled.' },
];

const REDIRECT_SHAPE = 'must be an absolute http or https URL or a path starting with /';
const ID_RE = /^[a-z0-9][a-z0-9-]{0,39}$/;
const HEADER_NAME_RE = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/;
const MATCH_VALUE_RE = /^[A-Za-z0-9\-_.~:/@=+,;*&?]+$/;
const RESERVED = ['or', 'and', 'if', 'unless', '{', '}', '||', '&&', '!'];
const FRAMING = ['host', 'content-length', 'transfer-encoding', 'connection', 'keep-alive', 'upgrade', 'te', 'trailer', 'expect'];
const IDENTITY = ['x-forwarded-for', 'x-forwarded-proto', 'x-forwarded-host', 'x-forwarded-port', 'x-real-ip', 'forwarded', 'true-client-ip'];
const HOST_LABEL = /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;
const PLACEHOLDER_NAMES = ['scheme', 'host', 'www_host', 'apex_host', 'path', 'query'];

const isReserved = (text) => RESERVED.includes(String(text).toLowerCase());
const isGraphic = (ch) => ch.charCodeAt(0) >= 0x21 && ch.charCodeAt(0) <= 0x7e;

export function isValidId(text) {
  return typeof text === 'string' && ID_RE.test(text);
}

export function isHostname(text) {
  return typeof text === 'string' && text.length > 0 && text.length <= 253 && text.split('.').every((label) => HOST_LABEL.test(label));
}

export function splitList(text) {
  return String(text || '').split(/[\s,]+/).filter(Boolean);
}

// Splits a redirect template into literal and placeholder pieces, or returns the reason it cannot be read
function templatePieces(to) {
  const pieces = [];
  let rest = to;
  let lit = '';
  for (;;) {
    const at = rest.search(/[{}]/);
    if (at < 0) break;
    lit += rest.slice(0, at);
    if (rest[at] === '}') return { error: 'unmatched }' };
    const end = rest.indexOf('}', at);
    if (end < 0) return { error: 'unclosed {' };
    const name = rest.slice(at + 1, end);
    if (!PLACEHOLDER_NAMES.includes(name)) return { error: `unknown placeholder {${name}}; use ${PLACEHOLDERS.join(' ')}` };
    if (lit) pieces.push({ lit });
    lit = '';
    pieces.push({ ph: name });
    rest = rest.slice(end + 1);
  }
  lit += rest;
  if (lit) pieces.push({ lit });
  return { pieces };
}

const isLit = (piece) => piece && piece.lit !== undefined;
const isPh = (piece, name) => piece && piece.ph === name;
const isHostPh = (piece) => piece && ['host', 'www_host', 'apex_host'].includes(piece.ph);

// Splits "scheme://" off the front and returns whether it was https plus what follows
function stripScheme(pieces) {
  const first = pieces[0];
  const withTail = (tail, more) => (tail ? [{ lit: tail }, ...more] : [...more]);
  if (isLit(first) && first.lit.startsWith('https://')) return { https: true, after: withTail(first.lit.slice(8), pieces.slice(1)) };
  if (isLit(first) && first.lit.startsWith('http://')) return { https: false, after: withTail(first.lit.slice(7), pieces.slice(1)) };
  if (isPh(first, 'scheme') && isLit(pieces[1]) && pieces[1].lit.startsWith('://')) return { https: false, after: withTail(pieces[1].lit.slice(3), pieces.slice(2)) };
  return { error: REDIRECT_SHAPE };
}

// The host part ends at the first literal / or ?, or where {path} or {query} begins
function authority(after) {
  const out = [];
  for (const piece of after) {
    if (isLit(piece)) {
      const cut = piece.lit.search(/[/?]/);
      const host = cut < 0 ? piece.lit : piece.lit.slice(0, cut);
      if (!/^[A-Za-z0-9.:-]*$/.test(host)) return { error: 'the host part may contain only letters, digits, . - and :' };
      if (host) out.push({ lit: host });
      if (cut >= 0) break;
    } else if (isHostPh(piece)) {
      out.push(piece);
    } else if (isPh(piece, 'path') || isPh(piece, 'query')) {
      break;
    } else {
      return { error: '{scheme} can only start the URL' };
    }
  }
  return out.length ? { host: out } : { error: 'the URL has no host' };
}

// Mirrors the node's template parser; returns the facts the loop checks need, or the first problem
export function parseTemplate(to) {
  const text = String(to ?? '');
  if (!text || text.length > MAX_TEMPLATE_LEN) return { error: `must be 1 to ${MAX_TEMPLATE_LEN} characters` };
  const bad = [...text].find((ch) => !isGraphic(ch) || '"\'\\#$`<>'.includes(ch));
  if (bad !== undefined) return { error: 'no spaces, control characters, quotes, backslash, # or $ are allowed' };
  const split = templatePieces(text);
  if (split.error) return split;
  const pieces = split.pieces;
  const first = pieces[0];
  let facts;
  if (isLit(first) && first.lit.startsWith('/')) {
    if (first.lit.startsWith('//') || (first.lit === '/' && isPh(pieces[1], 'path'))) return { error: 'a path target must not start with // or /{path}' };
    facts = { relative: true, https: false, ownHost: false, sameHost: false };
  } else {
    const stripped = stripScheme(pieces);
    if (stripped.error) return stripped;
    const auth = authority(stripped.after);
    if (auth.error) return auth;
    facts = {
      relative: false,
      https: stripped.https,
      ownHost: auth.host.some(isHostPh),
      sameHost: auth.host.length === 1 && isPh(auth.host[0], 'host'),
    };
  }
  const identity = isPh(pieces[0], 'scheme') && isLit(pieces[1]) && pieces[1].lit === '://' && isPh(pieces[2], 'host') && isPh(pieces[3], 'path')
    && (pieces.length === 4 || (pieces.length === 5 && isPh(pieces[4], 'query')));
  if (identity) return { error: 'redirects every request to the URL it asked for' };
  const has = (name) => pieces.some((p) => isPh(p, name));
  if (has('www_host') && has('apex_host')) return { error: 'cannot use {www_host} and {apex_host} together' };
  return { pieces, ...facts, usesWww: has('www_host'), usesApex: has('apex_host') };
}

export function hasMatcher(m) {
  return Boolean(m && (m.path_regex || m.path_prefix || (m.methods && m.methods.length) || m.user_agent_regex
    || (m.cidrs && m.cidrs.length) || m.host || m.header || m.scheme || m.referer_regex));
}

// The same loop checks the node makes, each one because the matchers would still select the request after it was redirected
export function redirectProblem(redirect, matchers) {
  if (!redirect || !REDIRECT_STATUSES.includes(redirect.status)) return 'The redirect status must be 301, 302, 307 or 308.';
  const t = parseTemplate(redirect.to);
  if (t.error) return `The redirect target ${t.error}.`;
  const m = matchers || {};
  const pathMatcher = Boolean(m.path_prefix || m.path_regex);
  const upgrade = !t.relative && t.https && t.sameHost;
  if (upgrade) {
    if (m.scheme !== 'http') return 'An https redirect to the same host needs the scheme matcher set to http, or it loops.';
  } else if (t.relative || t.sameHost) {
    if (!pathMatcher) return 'A redirect that keeps the host needs a path prefix or path regex matcher, or it loops.';
    const only = t.pieces.length === 1 && isLit(t.pieces[0]) ? t.pieces[0].lit : null;
    if (m.path_prefix && only !== null && only.startsWith(m.path_prefix)) return 'The redirect target starts with the matched path prefix and would loop.';
  } else if (!t.usesWww && !t.usesApex && !hasMatcher(m)) {
    return 'Add a matcher, or use {www_host} or {apex_host}, so the redirect cannot loop.';
  }
  return null;
}

export function headerNameProblem(name) {
  return HEADER_NAME_RE.test(String(name ?? '')) ? null : 'A header name is 1 to 64 letters, digits, - or _, starting with a letter.';
}

function headerDenied(target, op, name) {
  const lower = String(name).toLowerCase();
  if (FRAMING.includes(lower)) return 'is managed by the proxy and cannot be changed';
  if (['proxy-', 'sec-', 'x-cite-'].some((p) => lower.startsWith(p))) return 'is reserved and cannot be changed';
  const identity = IDENTITY.includes(lower) || lower.startsWith('cf-');
  if (target === 'request' && op !== 'remove' && identity) return 'carries the client identity; a request rule can only remove it';
  return null;
}

export function headerValueProblem(value) {
  const text = String(value ?? '');
  const ok = text.length > 0 && text.length <= MAX_HEADER_VALUE && [...text].every((ch) => ch.charCodeAt(0) >= 0x20 && ch.charCodeAt(0) <= 0x7e && !'"\\$'.includes(ch));
  return ok ? null : `A value is 1 to ${MAX_HEADER_VALUE} printable ASCII characters without " \\ or $.`;
}

export function headerOpProblem(op) {
  const named = headerNameProblem(op.name);
  if (named) return named;
  const denied = headerDenied(op.target, op.op, op.name);
  if (denied) return `${op.name} ${denied}.`;
  if (op.op === 'remove') return op.value ? 'Remove takes no value.' : null;
  return headerValueProblem(op.value);
}

function validOrigin(origin) {
  const m = /^https?:\/\/([^/:]+)(?::(\d+))?$/.exec(origin);
  if (!m || !isHostname(m[1])) return false;
  return m[2] === undefined || (Number(m[2]) > 0 && Number(m[2]) <= 65535);
}

const METHOD_RE = /^[A-Z-]{1,24}$/;

// cors holds already split lists; the form splits the text boxes first
export function corsProblem(cors) {
  const origins = cors.origins || [];
  if (!origins.length || origins.length > MAX_CORS_ENTRIES) return `CORS needs 1 to ${MAX_CORS_ENTRIES} origins.`;
  const wildcard = origins.includes('*');
  if (wildcard && origins.length !== 1) return 'The origin * must be the only origin.';
  if (wildcard && cors.credentials) return 'Credentials cannot be combined with the origin *. List the exact origins instead.';
  const badOrigin = origins.find((o) => o !== '*' && !validOrigin(o));
  if (badOrigin !== undefined) return `Origin ${badOrigin} must look like https://app.example.com, with no path.`;
  for (const [label, list] of [['methods', cors.methods], ['allow headers', cors.allow_headers], ['expose headers', cors.expose_headers]]) {
    if ((list || []).length > MAX_CORS_ENTRIES) return `Use at most ${MAX_CORS_ENTRIES} ${label}.`;
  }
  const badMethod = (cors.methods || []).find((m) => !METHOD_RE.test(m));
  if (badMethod !== undefined) return `Method ${badMethod} must be uppercase letters.`;
  const badHeader = [...(cors.allow_headers || []), ...(cors.expose_headers || [])].find((n) => headerNameProblem(n));
  if (badHeader !== undefined) return `Header name ${badHeader} must be 1 to 64 letters, digits, - or _.`;
  const age = cors.max_age_secs;
  if (!Number.isInteger(age) || age < 0 || age > MAX_CORS_MAX_AGE) return `Max age must be a whole number from 0 to ${MAX_CORS_MAX_AGE} seconds.`;
  return null;
}

// Printable ASCII with no # or quotes, as the node requires of every pattern that ends up in the config
export function patternProblem(text, label) {
  const s = String(text ?? '');
  if (!s || s.length > MAX_PATTERN_LEN) return `${label} must be 1 to ${MAX_PATTERN_LEN} characters.`;
  const bad = [...s].find((ch) => !isGraphic(ch) || '#"\''.includes(ch));
  if (bad !== undefined) return `${label} cannot contain spaces, # or quotes. Use \\s for a space.`;
  if (s.startsWith('-') || isReserved(s)) return `${label} cannot be used as written.`;
  if (s.includes('\\\\') || s.endsWith('\\')) return `${label} has a doubled or trailing backslash.`;
  if (s.includes('\\x')) return `${label} cannot use \\x escapes. Write the character or a class.`;
  if (/\$[A-Za-z0-9_{]/.test(s)) return `${label} cannot have $ followed by a name.`;
  return compileProblem(s) ? `${label} is not a valid regular expression.` : null;
}

// A secret equals value may be left blank on an edit, which tells the node to keep the stored one
export function headerMatcherProblem(h, { stored = Boolean(h && h.stored) } = {}) {
  if (!h || !String(h.name || '').trim()) return null;
  const named = headerNameProblem(String(h.name).trim());
  if (named) return named;
  if (h.mode === 'regex') {
    if (h.secret) return 'Only an exact value can be marked secret.';
    return patternProblem(h.value, 'The header regex');
  }
  const value = String(h.value ?? '');
  if (!value) return h.secret && stored ? null : 'Enter the value the header must equal.';
  if (value.length > MAX_MATCH_VALUE || !MATCH_VALUE_RE.test(value) || isReserved(value)) {
    return `The exact value is 1 to ${MAX_MATCH_VALUE} characters from letters, digits and - _ . ~ : / @ = + , ; * & ?`;
  }
  return null;
}

export function matcherProblem(m) {
  if (m.scheme && m.scheme !== 'http' && m.scheme !== 'https') return 'The scheme must be http or https.';
  if (m.referer_regex) {
    const problem = patternProblem(m.referer_regex, 'The referer regex');
    if (problem) return problem;
  }
  return null;
}

const emptyHeader = () => ({ name: '', mode: 'equals', value: '', negate: false, secret: false, stored: false });

export function emptyForm() {
  return {
    id: '', name: '', enabled: true, site: '', label: '', kind: 'block', action: 'deny',
    matchers: {
      path_prefix: '', path_regex: '', methods: [], user_agent_regex: '', cidrs: [], host: '', scheme: '', referer_regex: '', header: emptyHeader(),
    },
    redirect: { to: '', status: 301 },
    headers: [],
    cors: { enabled: false, origins: '', methods: '', allow_headers: '', expose_headers: '', credentials: false, max_age: '0' },
  };
}

export function ruleKind(rule) {
  if (rule.redirect) return 'redirect';
  if ((rule.headers && rule.headers.length) || rule.cors) return 'headers';
  return 'block';
}

// A secret value is never returned by the node, so a stored secret matcher opens with a blank value and the stored flag
export function ruleToForm(rule) {
  const form = emptyForm();
  const m = rule.matchers || {};
  const hm = m.header;
  form.id = rule.id;
  form.name = rule.name;
  form.enabled = rule.enabled;
  form.site = rule.site || '';
  form.label = rule.label || '';
  form.kind = ruleKind(rule);
  form.action = rule.action || 'deny';
  form.matchers = {
    path_prefix: m.path_prefix || '', path_regex: m.path_regex || '', methods: [...(m.methods || [])], user_agent_regex: m.user_agent_regex || '',
    cidrs: [...(m.cidrs || [])], host: m.host || '', scheme: m.scheme || '', referer_regex: m.referer_regex || '',
    header: hm ? {
      name: hm.name,
      mode: hm.regex ? 'regex' : 'equals',
      value: hm.secret ? '' : (hm.regex || hm.equals || ''),
      negate: Boolean(hm.negate),
      secret: Boolean(hm.secret),
      stored: Boolean(hm.secret),
    } : emptyHeader(),
  };
  if (rule.redirect) form.redirect = { to: rule.redirect.to, status: rule.redirect.status };
  form.headers = (rule.headers || []).map((op) => ({ target: op.target, op: op.op, name: op.name, value: op.value || '' }));
  const c = rule.cors;
  if (c) {
    form.cors = {
      enabled: true, origins: (c.origins || []).join('\n'), methods: (c.methods || []).join(' '), allow_headers: (c.allow_headers || []).join(' '),
      expose_headers: (c.expose_headers || []).join(' '), credentials: Boolean(c.credentials), max_age: String(c.max_age_secs || 0),
    };
  }
  return form;
}

function headerMatcherBody(h) {
  const body = { name: h.name.trim(), regex: null, equals: null, negate: Boolean(h.negate), secret: Boolean(h.secret) };
  if (h.mode === 'regex') body.regex = h.value;
  else body.equals = h.value;
  return body;
}

export function corsFromForm(c) {
  const age = String(c.max_age ?? '').trim();
  return {
    origins: splitList(c.origins),
    methods: splitList(c.methods).map((m) => m.toUpperCase()),
    allow_headers: splitList(c.allow_headers),
    expose_headers: splitList(c.expose_headers),
    credentials: Boolean(c.credentials),
    max_age_secs: age === '' ? 0 : Number(age),
  };
}

// Returns the request body for the node, or the first problem found; matchers the form did not use are left out of the JSON
export function buildRule(form) {
  const name = String(form.name || '').trim();
  if (!name) return { error: 'Give the rule a name.' };
  const label = String(form.label || '').trim();
  if (label && !isValidId(label)) return { error: 'The label is lowercase letters, digits and dashes, up to 40 characters.' };
  const m = form.matchers;
  const matchers = {
    path_regex: m.path_regex.trim() || null,
    path_prefix: m.path_prefix.trim() || null,
    methods: [...m.methods],
    user_agent_regex: m.user_agent_regex.trim() || null,
    cidrs: [...m.cidrs],
    host: m.host.trim() || null,
  };
  if (m.scheme) matchers.scheme = m.scheme;
  const referer = m.referer_regex.trim();
  if (referer) matchers.referer_regex = referer;
  const found = matcherProblem({ scheme: m.scheme, referer_regex: referer });
  if (found) return { error: found };
  const hm = m.header;
  if (String(hm.name || '').trim()) {
    const bad = headerMatcherProblem(hm, { stored: hm.stored });
    if (bad) return { error: bad };
    matchers.header = headerMatcherBody(hm);
  }
  const rule = { id: form.id, name, enabled: form.enabled, matchers, site: form.site || null };
  if (label) rule.label = label;
  if (form.kind === 'redirect') {
    const redirect = { to: form.redirect.to.trim(), status: Number(form.redirect.status) };
    const bad = redirectProblem(redirect, matchers);
    if (bad) return { error: bad };
    rule.redirect = redirect;
    return { rule };
  }
  if (form.kind === 'headers') {
    const ops = form.headers.map((op) => {
      const body = { target: op.target, op: op.op, name: op.name.trim() };
      if (op.op !== 'remove') body.value = op.value;
      return body;
    });
    if (ops.length > MAX_HEADER_OPS) return { error: `Use at most ${MAX_HEADER_OPS} header changes.` };
    for (const op of ops) {
      const bad = headerOpProblem(op);
      if (bad) return { error: bad };
    }
    const cors = form.cors.enabled ? corsFromForm(form.cors) : null;
    if (cors) {
      const bad = corsProblem(cors);
      if (bad) return { error: bad };
    }
    if (!ops.length && !cors) return { error: 'Add at least one header change or turn on CORS.' };
    if (ops.length) rule.headers = ops;
    if (cors) rule.cors = cors;
    return { rule };
  }
  if (!hasMatcher(matchers)) return { error: 'A rule needs at least one matcher, otherwise it would block everything.' };
  rule.action = form.action;
  return { rule };
}

// A listed rule saved back as it is (the on/off switch) must keep a secret value: the node returns it blank, and a blank value with secret set means keep
export function resaveBody(rule, patch = {}) {
  const body = { ...rule, ...patch };
  const hm = rule.matchers && rule.matchers.header;
  if (hm && hm.secret && !hm.regex) body.matchers = { ...rule.matchers, header: { ...hm, equals: '' } };
  return body;
}

// Short chips for the rule list; a secret value is never shown
export function matcherSummary(m) {
  const out = [];
  if (m.path_prefix) out.push('prefix ' + m.path_prefix);
  if (m.path_regex) out.push('path ~ ' + m.path_regex);
  if (m.methods && m.methods.length) out.push(m.methods.join(' '));
  if (m.user_agent_regex) out.push('ua ~ ' + m.user_agent_regex);
  if (m.cidrs && m.cidrs.length) out.push(m.cidrs.length > 2 ? `${m.cidrs.slice(0, 2).join(', ')} +${m.cidrs.length - 2}` : m.cidrs.join(', '));
  if (m.host) out.push('host ' + m.host);
  if (m.scheme) out.push('scheme ' + m.scheme);
  if (m.referer_regex) out.push('referer ~ ' + m.referer_regex);
  if (m.header) {
    const h = m.header;
    const test = h.regex ? `~ ${h.regex}` : h.secret ? '= (secret)' : `= ${h.equals}`;
    out.push(`header ${h.name} ${h.negate ? 'not ' : ''}${test}`);
  }
  return out;
}

const ACTION_LABELS = { deny: ['Deny', 'bad'], drop: ['Drop silently', 'warn'], tarpit: ['Tarpit', 'info'] };

// What the rule does, as a pill kind, a pill label and a line of detail for the list
export function effectView(rule) {
  const kind = ruleKind(rule);
  if (kind === 'redirect') return { kind, pill: 'info', label: `Redirect ${rule.redirect.status}`, detail: rule.redirect.to };
  if (kind === 'headers') {
    const parts = [];
    const n = (rule.headers || []).length;
    if (n) parts.push(`${n} header ${n === 1 ? 'change' : 'changes'}`);
    if (rule.cors) parts.push(`CORS for ${rule.cors.origins.length === 1 ? rule.cors.origins[0] : rule.cors.origins.length + ' origins'}`);
    return { kind, pill: 'ok', label: rule.cors && !n ? 'CORS' : 'Headers', detail: parts.join(', ') };
  }
  const [label, pill] = ACTION_LABELS[rule.action] || [String(rule.action || 'Block'), 'muted'];
  return { kind, pill, label, detail: '' };
}

// Redirect presets carry no site, so applying one acts on every site on the node
export function presetNeedsScopeWarning(preset) {
  return (preset.rules || []).some((r) => Boolean(r.redirect) && !r.site);
}
