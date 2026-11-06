// The rule builder's form model: four steps from what should happen to a request body for the node
import {
  MAX_HEADER_OPS, corsFromForm, corsProblem, hasMatcher, headerOpProblem, isValidId, redirectProblem, ruleKind,
} from './rulelib.js';
import {
  describeRows, matchersToRows, rowsProblem, rowsToMatchers,
} from './conditionlib.js';

export const KINDS = [
  { value: 'block', label: 'Block', text: 'Stop matching requests with a 403, a silent drop or a tarpit.' },
  { value: 'redirect', label: 'Redirect', text: 'Answer matching requests with a redirect to another address.' },
  { value: 'headers', label: 'Change headers', text: 'Let matching requests through, with request or response headers changed.' },
  { value: 'cors', label: 'CORS', text: 'Let matching requests through, with cross-origin access rules added.' },
];

export const STEPS = [
  { id: 'what', title: 'What should happen?' },
  { id: 'when', title: 'When?' },
  { id: 'details', title: 'Details' },
  { id: 'name', title: 'Name and scope' },
];

export function emptyForm() {
  return {
    id: '', name: '', enabled: true, site: '', label: '', kind: '', action: 'deny',
    conditions: [],
    redirect: { to: '', status: 301 },
    headers: [],
    cors: { origins: '', methods: '', allow_headers: '', expose_headers: '', credentials: false, max_age: '0' },
  };
}

// Header changes and CORS are separate choices in the builder, but one rule can hold both, so an existing rule opens as headers when it has any
export function formKindOf(rule) {
  const kind = ruleKind(rule);
  if (kind === 'headers') return (rule.headers && rule.headers.length) ? 'headers' : 'cors';
  return kind;
}

export function ruleToForm(rule) {
  const form = emptyForm();
  form.id = rule.id;
  form.name = rule.name;
  form.enabled = rule.enabled;
  form.site = rule.site || '';
  form.label = rule.label || '';
  form.kind = formKindOf(rule);
  form.action = rule.action || 'deny';
  form.conditions = matchersToRows(rule.matchers);
  if (rule.redirect) form.redirect = { to: rule.redirect.to, status: rule.redirect.status };
  form.headers = (rule.headers || []).map((op) => ({ target: op.target, op: op.op, name: op.name, value: op.value || '' }));
  const c = rule.cors;
  if (c) {
    form.cors = {
      origins: (c.origins || []).join('\n'), methods: (c.methods || []).join(' '), allow_headers: (c.allow_headers || []).join(' '),
      expose_headers: (c.expose_headers || []).join(' '), credentials: Boolean(c.credentials), max_age: String(c.max_age_secs || 0),
    };
  }
  // A rule that holds both effects keeps both when it is saved again
  form.alsoCors = Boolean(c) && form.kind === 'headers';
  form.alsoHeaders = form.headers.length > 0 && form.kind === 'cors';
  return form;
}

function headerOps(form) {
  return form.headers.map((op) => {
    const body = { target: op.target, op: op.op, name: op.name.trim() };
    if (op.op !== 'remove') body.value = op.value;
    return body;
  });
}

// The first problem on one step (0 to 3), or null; Next stays off until it is null
export function stepProblem(form, step) {
  const matchers = rowsToMatchers(form.conditions);
  if (step === 0) return form.kind ? null : 'Choose what should happen to matching requests.';
  if (step === 1) {
    const bad = rowsProblem(form.conditions);
    if (bad) return bad;
    if (form.kind === 'block' && !hasMatcher(matchers)) return 'A blocking rule needs at least one condition, otherwise it would block everything.';
    return null;
  }
  if (step === 2) {
    if (form.kind === 'block') return null;
    if (form.kind === 'redirect') return redirectProblem({ to: form.redirect.to.trim(), status: Number(form.redirect.status) }, matchers);
    const opsProblem = () => {
      const ops = headerOps(form);
      if (!ops.length) return 'Add at least one header change.';
      if (ops.length > MAX_HEADER_OPS) return `Use at most ${MAX_HEADER_OPS} header changes.`;
      return ops.map(headerOpProblem).find(Boolean) || null;
    };
    if (form.kind === 'headers') return opsProblem() || (form.alsoCors ? corsProblem(corsFromForm(form.cors)) : null);
    return corsProblem(corsFromForm(form.cors)) || (form.alsoHeaders ? opsProblem() : null);
  }
  const name = String(form.name || '').trim();
  if (!name) return 'Give the rule a name.';
  const label = String(form.label || '').trim();
  if (label && !isValidId(label)) return 'The label is lowercase letters, digits and dashes, up to 40 characters.';
  return null;
}

// Returns the request body for the node, or the first problem with its step number; matchers hold list fields only
export function buildRule(form) {
  for (let step = 0; step < STEPS.length; step += 1) {
    const bad = stepProblem(form, step);
    if (bad) return { error: bad, step };
  }
  const label = String(form.label || '').trim();
  const rule = {
    id: form.id, name: String(form.name).trim(), enabled: form.enabled, matchers: rowsToMatchers(form.conditions), site: form.site || null,
  };
  if (label) rule.label = label;
  if (form.kind === 'redirect') {
    rule.redirect = { to: form.redirect.to.trim(), status: Number(form.redirect.status) };
  } else if (form.kind === 'headers') {
    rule.headers = headerOps(form);
    if (form.alsoCors) rule.cors = corsFromForm(form.cors);
  } else if (form.kind === 'cors') {
    rule.cors = corsFromForm(form.cors);
    if (form.alsoHeaders && form.headers.length) rule.headers = headerOps(form);
  } else {
    rule.action = form.action;
  }
  return { rule };
}

// Lines for the review on the last step
export function reviewLines(form, siteName) {
  const kind = KINDS.find((k) => k.value === form.kind);
  const lines = [['Does', kind ? kind.label : '-'], ['When', describeRows(form.conditions)]];
  if (form.kind === 'block') lines.push(['Action', form.action]);
  if (form.kind === 'redirect') lines.push(['Redirects to', `${form.redirect.to.trim()} (${form.redirect.status})`]);
  if (form.kind === 'headers') lines.push(['Header changes', String(form.headers.length)]);
  if (form.kind === 'cors') lines.push(['Allowed origins', corsFromForm(form.cors).origins.join(', ')]);
  lines.push(['Applies to', form.site ? siteName(form.site) : 'All sites on this node']);
  return lines;
}
