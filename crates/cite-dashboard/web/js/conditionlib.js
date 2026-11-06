// Condition rows are the builder's view of a rule's matchers: values of one type are OR'd, different types are AND'd
import {
  headerMatcherProblem, isHostname, listsOf, patternProblem,
} from './rulelib.js';

export const MAX_LIST_ITEMS = 32;
export const MAX_CIDRS = 256;

export const CONDITION_TYPES = [
  { id: 'path_prefix', label: 'Path starts with', field: 'path_prefixes', placeholder: '/old' },
  { id: 'path_regex', label: 'Path matches regex', field: 'path_regexes', placeholder: '^/blog/[0-9]+$' },
  { id: 'user_agent', label: 'User agent matches', field: 'user_agent_regexes', placeholder: '(?i)scraper' },
  { id: 'referer', label: 'Referer matches', field: 'referer_regexes', placeholder: '^https://spam' },
  { id: 'method', label: 'Method is', field: 'methods', placeholder: 'GET' },
  { id: 'host', label: 'Host is', field: 'hosts', placeholder: 'shop.example.com' },
  { id: 'cidr', label: 'IP is in range', field: 'cidrs', placeholder: '203.0.113.0/24' },
  { id: 'scheme', label: 'Scheme is', field: 'scheme', placeholder: 'http' },
  { id: 'header', label: 'Header', field: 'headers', placeholder: '' },
];

export const PATH_TYPES = ['path_prefix', 'path_regex'];

const CIDR_LOOSE = /^[0-9a-fA-F:.]+(\/\d{1,3})?$/;
const METHOD_RE = /^[A-Z-]{1,24}$/;

export function typeOf(id) {
  return CONDITION_TYPES.find((t) => t.id === id) || CONDITION_TYPES[0];
}

export const emptyHeader = () => ({ name: '', mode: 'equals', value: '', negate: false, secret: false, stored: false });

export function newRow(type = 'path_prefix') {
  return { type, value: '', header: emptyHeader() };
}

const trimmed = (row) => String(row.value ?? '').trim();
const isBlank = (row) => (row.type === 'header' ? !String(row.header.name || '').trim() : !trimmed(row));

// A scheme row is a pick, so it is blank only when nothing is chosen
function normalised(row) {
  if (row.type === 'method') return trimmed(row).toUpperCase();
  return trimmed(row);
}

function headerBody(h) {
  const body = { name: h.name.trim(), regex: null, equals: null, negate: Boolean(h.negate), secret: Boolean(h.secret) };
  if (h.mode === 'regex') body.regex = h.value;
  else body.equals = h.value;
  return body;
}

// Blank rows are ignored; a field is left out when it has no values, so only the list fields reach the node
export function rowsToMatchers(rows) {
  const out = {};
  for (const type of CONDITION_TYPES) {
    const mine = rows.filter((r) => r.type === type.id && !isBlank(r));
    if (!mine.length) continue;
    if (type.id === 'scheme') out.scheme = normalised(mine[0]);
    else if (type.id === 'header') out.headers = mine.map((r) => headerBody(r.header));
    else out[type.field] = [...new Set(mine.map(normalised))];
  }
  return out;
}

function headerRow(h) {
  return {
    type: 'header',
    value: '',
    header: {
      name: h.name, mode: h.regex ? 'regex' : 'equals', value: h.secret ? '' : (h.regex || h.equals || ''), negate: Boolean(h.negate), secret: Boolean(h.secret), stored: Boolean(h.secret),
    },
  };
}

// A secret value is never returned by the node, so a stored secret opens with a blank value and the stored flag
export function matchersToRows(matchers) {
  const l = listsOf(matchers);
  const rows = [];
  for (const type of CONDITION_TYPES) {
    if (type.id === 'scheme') {
      if (l.scheme) rows.push({ ...newRow('scheme'), value: l.scheme });
    } else if (type.id === 'header') {
      for (const h of l.headers) rows.push(headerRow(h));
    } else {
      for (const value of l[type.field]) rows.push({ ...newRow(type.id), value });
    }
  }
  return rows;
}

export function rowProblem(row) {
  if (isBlank(row)) return null;
  const v = normalised(row);
  switch (row.type) {
    case 'path_prefix':
      if (!v.startsWith('/') || v.includes('\\')) return 'A path prefix starts with / and has no backslash.';
      return patternProblem(v, 'The path prefix');
    case 'path_regex': return patternProblem(v, 'The path regex');
    case 'user_agent': return patternProblem(v, 'The user agent regex');
    case 'referer': return patternProblem(v, 'The referer regex');
    case 'method': return METHOD_RE.test(v) ? null : `${v} is not a method name; use capital letters such as GET.`;
    case 'host': return isHostname(v.startsWith('*.') ? v.slice(2) : v) ? null : `${v} is not a host name; use shop.example.com or *.example.com.`;
    case 'cidr': return CIDR_LOOSE.test(v) ? null : `${v} is not an address or range such as 203.0.113.0/24.`;
    case 'scheme': return v === 'http' || v === 'https' ? null : 'The scheme is http or https.';
    case 'header': return headerMatcherProblem(row.header);
    default: return 'Pick a condition type.';
  }
}

// The first problem in the list, or null; two different schemes can never both hold
export function rowsProblem(rows) {
  for (let i = 0; i < rows.length; i += 1) {
    const bad = rowProblem(rows[i]);
    if (bad) return `Condition ${i + 1}: ${bad}`;
  }
  const schemes = new Set(rows.filter((r) => r.type === 'scheme' && !isBlank(r)).map(normalised));
  if (schemes.size > 1) return 'A request is either http or https, so only one scheme condition can be used.';
  const m = rowsToMatchers(rows);
  for (const [field, values] of Object.entries(m)) {
    const limit = field === 'cidrs' ? MAX_CIDRS : MAX_LIST_ITEMS;
    if (Array.isArray(values) && values.length > limit) return `Use at most ${limit} values for one kind of condition.`;
  }
  return null;
}

const orList = (values) => values.join(' or ');

function headerPhrase(h) {
  const secret = h.secret && !h.regex;
  const value = secret ? 'a secret value' : (h.regex || h.equals || '');
  if (h.regex) return `the header ${h.name} ${h.negate ? 'does not match' : 'matches'} ${value}`;
  return `the header ${h.name} ${h.negate ? 'does not equal' : 'equals'} ${value}`;
}

const PHRASES = {
  path_prefixes: (v) => `the path starts with ${orList(v)}`,
  path_regexes: (v) => `the path matches ${orList(v)}`,
  user_agent_regexes: (v) => `the user agent matches ${orList(v)}`,
  referer_regexes: (v) => `the referer matches ${orList(v)}`,
  methods: (v) => `the method is ${orList(v)}`,
  hosts: (v) => `the host is ${orList(v)}`,
  cidrs: (v) => `the visitor address is in ${orList(v)}`,
};

// Plain English for the live sentence under the builder; secret values are never written out
export function describeMatchers(matchers) {
  const l = listsOf(matchers);
  const parts = [];
  for (const [field, phrase] of Object.entries(PHRASES)) {
    if (l[field].length) parts.push(phrase(l[field]));
  }
  if (l.scheme) parts.push(`the connection is ${l.scheme}`);
  if (l.headers.length) parts.push(orList(l.headers.map(headerPhrase)));
  return parts.length ? `When ${parts.join(', and ')}.` : 'Every request.';
}

export function describeRows(rows) {
  return describeMatchers(rowsToMatchers(rows));
}

// Short chips for the rule list; a secret value is never shown
export function matcherSummary(matchers) {
  const l = listsOf(matchers);
  const out = [];
  const each = (prefix, values) => values.forEach((v) => out.push(`${prefix} ${v}`));
  each('prefix', l.path_prefixes);
  each('path ~', l.path_regexes);
  if (l.methods.length) out.push(l.methods.join(' '));
  each('ua ~', l.user_agent_regexes);
  if (l.cidrs.length) out.push(l.cidrs.length > 2 ? `${l.cidrs.slice(0, 2).join(', ')} +${l.cidrs.length - 2}` : l.cidrs.join(', '));
  each('host', l.hosts);
  if (l.scheme) out.push('scheme ' + l.scheme);
  each('referer ~', l.referer_regexes);
  for (const h of l.headers) {
    const test = h.regex ? `~ ${h.regex}` : h.secret ? '= (secret)' : `= ${h.equals}`;
    out.push(`header ${h.name} ${h.negate ? 'not ' : ''}${test}`);
  }
  return out;
}

// Site routing paths use the same two row types, stored as OR lists on the site
export function pathRowsFromSite(site) {
  const s = site || {};
  const prefixes = [...(s.path_prefixes || [])];
  const regexes = [...(s.path_regexes || []), ...(s.path_regex ? [s.path_regex] : [])];
  return [
    ...prefixes.map((value) => ({ ...newRow('path_prefix'), value })),
    ...regexes.map((value) => ({ ...newRow('path_regex'), value })),
  ];
}

export function pathFieldsFromRows(rows) {
  const m = rowsToMatchers(rows.filter((r) => PATH_TYPES.includes(r.type)));
  return { path_prefixes: m.path_prefixes || [], path_regexes: m.path_regexes || [] };
}

export function pathsProblem(rows) {
  return rowsProblem(rows.filter((r) => PATH_TYPES.includes(r.type)));
}
