// The Redirects page works on rows; each row is one redirect rule, and one bulk request carries every change
import { listsOf, patternProblem, redirectProblem } from './rulelib.js';
import { describeMatchers } from './conditionlib.js';

export const STATUS_CHOICES = [301, 302, 307, 308];
export const WWW_TARGET = '{scheme}://{www_host}{path}{query}';
export const HTTPS_TARGET = 'https://{host}{path}{query}';
export const MAX_ROWS = 200;

let counter = 0;
const nextKey = () => {
  counter += 1;
  return `row-${counter}`;
};

// A rule is a simple row when its only condition is one path prefix or one path regex
function simpleFrom(matchers) {
  const l = listsOf(matchers);
  const others = [l.user_agent_regexes, l.referer_regexes, l.hosts, l.methods, l.cidrs, l.headers].some((list) => list.length > 0) || l.scheme;
  if (others) return null;
  if (l.path_prefixes.length === 1 && l.path_regexes.length === 0) return { mode: 'prefix', value: l.path_prefixes[0] };
  if (l.path_regexes.length === 1 && l.path_prefixes.length === 0) return { mode: 'regex', value: l.path_regexes[0] };
  return null;
}

const snapshotOf = (row) => JSON.stringify([row.enabled, row.mode, row.value, row.to, Number(row.status)]);

export function rulesToRows(rules) {
  return (rules || []).filter((r) => r.redirect).map((rule) => {
    const from = simpleFrom(rule.matchers);
    const row = {
      key: nextKey(),
      id: rule.id,
      enabled: Boolean(rule.enabled),
      simple: Boolean(from),
      mode: from ? from.mode : 'prefix',
      value: from ? from.value : '',
      to: rule.redirect.to,
      status: rule.redirect.status,
      site: rule.site || null,
      matchers: rule.matchers || {},
      name: rule.name,
    };
    row.snapshot = snapshotOf(row);
    return row;
  });
}

export function blankRow() {
  return {
    key: nextKey(), id: '', enabled: true, simple: true, mode: 'prefix', value: '', to: '', status: 301, site: null, matchers: {}, name: '', snapshot: '',
  };
}

// Quick actions that mirror the presets: they are not tied to a path, so the row shows what it matches instead of a From box
export function presetRow(kind) {
  const row = blankRow();
  row.simple = false;
  if (kind === 'www') {
    row.to = WWW_TARGET;
    row.name = 'Redirect to www';
  } else {
    row.to = HTTPS_TARGET;
    row.matchers = { scheme: 'http' };
    row.name = 'Force HTTPS';
  }
  return row;
}

export function fromMatchers(row) {
  return row.simple ? (row.mode === 'regex' ? { path_regexes: [row.value.trim()] } : { path_prefixes: [row.value.trim()] }) : row.matchers;
}

export function describeFrom(row) {
  if (row.simple) return row.mode === 'regex' ? `Path matches ${row.value.trim() || '...'}` : `Path starts with ${row.value.trim() || '...'}`;
  return describeMatchers(row.matchers).replace(/^Every request\.$/, 'Every request');
}

// One row's problem as a message, or null
export function rowProblem(row) {
  if (row.simple) {
    const v = row.value.trim();
    if (!v) return 'Enter the path to redirect from.';
    if (row.mode === 'prefix') {
      if (!v.startsWith('/') || v.includes('\\')) return 'A path prefix starts with / and has no backslash.';
      const bad = patternProblem(v, 'The path prefix');
      if (bad) return bad;
    } else {
      const bad = patternProblem(v, 'The path regex');
      if (bad) return bad;
    }
  }
  if (!String(row.to).trim()) return 'Enter the address to redirect to.';
  return redirectProblem({ to: String(row.to).trim(), status: Number(row.status) }, fromMatchers(row));
}

// Problems keyed by row, including two rows that start from the same place
export function rowsProblems(rows) {
  const out = new Map();
  const seen = new Map();
  for (const row of rows) {
    const bad = rowProblem(row);
    if (bad) out.set(row.key, bad);
    if (row.simple && row.value.trim()) {
      const id = `${row.mode}:${row.value.trim()}`;
      if (seen.has(id) && !out.has(row.key)) out.set(row.key, 'Another row already redirects from this path.');
      seen.set(id, row.key);
    }
  }
  if (rows.length > MAX_ROWS) out.set('*', `Use at most ${MAX_ROWS} redirects.`);
  return out;
}

// The smallest redirect-<n> that no rule or earlier row uses
export function freeId(taken) {
  let n = 1;
  while (taken.has(`redirect-${n}`)) n += 1;
  return `redirect-${n}`;
}

export function rowToRule(row, id) {
  const rule = {
    id,
    name: row.name || `Redirect ${row.simple ? row.value.trim() : 'rule'}`.slice(0, 60),
    enabled: row.enabled,
    matchers: fromMatchers(row),
    site: row.site || null,
    label: id,
    redirect: { to: String(row.to).trim(), status: Number(row.status) },
  };
  return rule;
}

// What to send: rules for new and edited rows, ids for rows that were removed, and nothing for rows left alone
export function diffRows(rows, originalRules) {
  const originals = (originalRules || []).filter((r) => r.redirect);
  // every rule id counts, so a new redirect can never reuse the id of a block, header or CORS rule
  const taken = new Set([...(originalRules || []).map((r) => r.id), ...rows.map((r) => r.id).filter(Boolean)]);
  const replace = [];
  const owners = new Map();
  for (const row of rows) {
    const changed = !row.id || row.snapshot !== snapshotOf(row);
    if (!changed) continue;
    let id = row.id;
    if (!id) {
      id = freeId(taken);
      taken.add(id);
    }
    owners.set(id, row.key);
    replace.push(rowToRule(row, id));
  }
  const kept = new Set(rows.map((r) => r.id).filter(Boolean));
  const remove = originals.map((r) => r.id).filter((id) => !kept.has(id));
  return { replace, delete: remove, owners };
}

// The node's error names the rule it refused; this finds the row so the message can sit beside it
export function rowForError(message, owners) {
  const text = String(message || '');
  for (const [id, key] of owners) {
    if (new RegExp(`rule ${id}(?![A-Za-z0-9-])`).test(text) || text.includes(`"${id}"`)) return key;
  }
  return null;
}
