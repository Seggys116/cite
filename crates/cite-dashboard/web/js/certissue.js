// Pure helpers for the certificate issuing forms: host lists, token shape checks, request bodies and the ACME job state machine

export const MAX_HOSTS = 50;
export const JOB_POLL_MS = 3000;
export const JOB_MAX_POLL_ERRORS = 5;
export const JOB_GIVE_UP_MS = 15 * 60 * 1000;
export const ORIGIN_CA_VALIDITY = [
  { days: 7, label: '7 days' },
  { days: 30, label: '30 days' },
  { days: 90, label: '90 days' },
  { days: 365, label: '1 year' },
  { days: 730, label: '2 years' },
  { days: 1095, label: '3 years' },
  { days: 5475, label: '15 years' },
];
export const DEFAULT_ORIGIN_CA_DAYS = 5475;
export const DEFAULT_SELF_SIGNED_DAYS = 365;
export const MAX_SELF_SIGNED_DAYS = 3650;
export const ORIGIN_CA_PERMISSIONS = [
  'Zone - SSL and Certificates - Edit',
  'Zone - Zone - Read',
];
export const ACME_PERMISSIONS = [
  'Zone - DNS - Edit',
  'Zone - Zone - Read',
];
export const NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/;

const LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const TOKEN_SHAPE = /^[A-Za-z0-9_-]{20,128}$/;

export function hostProblem(host) {
  const text = String(host);
  if (text.length > 253) return `${text.slice(0, 30)}... is too long.`;
  const body = text.startsWith('*.') ? text.slice(2) : text;
  const labels = body.split('.');
  if (labels.length < 2 || !labels.every((l) => LABEL.test(l))) {
    return `${text} is not a valid host name. Use a name like www.example.com or *.example.com.`;
  }
  if (/^[0-9.]+$/.test(body)) return `${text} is an IP address; certificates here are for host names.`;
  return '';
}

// Splits on commas, spaces and new lines, lowercases and removes duplicates while keeping order
export function parseHosts(input) {
  const raw = Array.isArray(input) ? input : String(input || '').split(/[\s,;]+/);
  const seen = new Set();
  const hosts = [];
  const errors = [];
  for (const item of raw) {
    const host = String(item).trim().toLowerCase().replace(/\.$/, '');
    if (!host || seen.has(host)) continue;
    seen.add(host);
    const problem = hostProblem(host);
    if (problem) errors.push(problem);
    else hosts.push(host);
  }
  if (!hosts.length && !errors.length) errors.push('Choose or enter at least one host name.');
  if (hosts.length > MAX_HOSTS) errors.push(`A certificate can cover at most ${MAX_HOSTS} host names.`);
  return { hosts, errors };
}

// Uncovered hosts come first because they are the ones that need a certificate
export function hostChoices(sites, uncovered) {
  const missing = new Set((Array.isArray(uncovered) ? uncovered : []).map((x) => String(x).toLowerCase()));
  const all = [];
  const seen = new Set();
  const add = (host) => {
    const key = String(host).toLowerCase();
    if (!key || seen.has(key)) return;
    seen.add(key);
    all.push({ host: key, uncovered: missing.has(key) });
  };
  for (const host of missing) add(host);
  for (const site of Array.isArray(sites) ? sites : []) for (const host of site.hosts || []) add(host);
  return all;
}

export function tokenProblem(token) {
  const text = String(token || '');
  if (!text) return 'Paste the Cloudflare API token.';
  if (text !== text.trim() || /\s/.test(text)) return 'The token contains spaces or line breaks. Paste only the token text.';
  if (text.length < 20 || text.length > 128) return 'That does not look like a Cloudflare API token (they are about 40 characters).';
  if (!TOKEN_SHAPE.test(text)) return 'The token has characters a Cloudflare API token never contains.';
  return '';
}

export function emailProblem(email) {
  const text = String(email || '').trim();
  if (!text) return 'Enter an email address for Let\'s Encrypt expiry notices.';
  if (text.length > 254 || !EMAIL.test(text)) return 'That is not a valid email address.';
  return '';
}

export function nameProblem(name) {
  const text = String(name || '').trim();
  if (!text) return '';
  if (!NAME_PATTERN.test(text) || text.endsWith(' ')) return 'The name can use letters, digits, spaces, dots, dashes and underscores, and must start with a letter or digit (up to 64 characters).';
  return '';
}

export function daysProblem(days, max) {
  const n = Number(days);
  if (!Number.isInteger(n) || n < 1 || n > max) return `Enter a whole number of days from 1 to ${max}.`;
  return '';
}

function withName(body, name) {
  const clean = String(name || '').trim();
  if (clean) body.name = clean;
  return body;
}

export function generateProblem({ hostsText, name, days }) {
  const parsed = parseHosts(hostsText);
  return parsed.errors[0] || nameProblem(name) || daysProblem(days, MAX_SELF_SIGNED_DAYS);
}

export function generateBody({ hostsText, name, days }) {
  return withName({ hosts: parseHosts(hostsText).hosts, days: Number(days) }, name);
}

export function originCaProblem({ hostsText, name, token, days }) {
  const parsed = parseHosts(hostsText);
  const valid = ORIGIN_CA_VALIDITY.some((v) => v.days === Number(days));
  return parsed.errors[0] || nameProblem(name) || tokenProblem(token) || (valid ? '' : 'Choose how long the certificate is valid.');
}

export function originCaBody({ hostsText, name, token, days, remember }) {
  return withName({
    hosts: parseHosts(hostsText).hosts, cloudflare_token: String(token), validity_days: Number(days), remember_token: Boolean(remember),
  }, name);
}

export function acmeProblem({ hostsText, name, token, email, agree }) {
  const parsed = parseHosts(hostsText);
  if (parsed.errors.length) return parsed.errors[0];
  return nameProblem(name) || emailProblem(email) || tokenProblem(token)
    || (agree ? '' : 'Agree to the Let\'s Encrypt terms and the token storage notice to continue.');
}

export function acmeBody({ hostsText, name, token, email, agree, staging }) {
  return withName({
    hosts: parseHosts(hostsText).hosts, email: String(email).trim(), cloudflare_token: String(token), agree_tos: Boolean(agree), staging: Boolean(staging),
  }, name);
}

// Job polling: a pure reducer so the dialog only has to feed it events and render the state
export function jobStart(now) {
  return { phase: 'submitting', jobId: '', error: '', startedAt: now, pollErrors: 0 };
}

export function jobReduce(state, event, now = 0) {
  if (isJobDone(state)) return state;
  switch (event.type) {
    case 'accepted':
      return { ...state, phase: 'running', jobId: String(event.jobId || ''), error: '' };
    case 'rejected':
      return { ...state, phase: 'failed', error: String(event.message || 'The request was rejected.') };
    case 'poll': {
      const status = event.job && event.job.status;
      if (status === 'issued') return { ...state, phase: 'issued', error: '', pollErrors: 0 };
      if (status === 'failed') return { ...state, phase: 'failed', error: String((event.job && event.job.error) || 'Issuing failed without a reason.'), pollErrors: 0 };
      if (status === 'pending') {
        if (now - state.startedAt > JOB_GIVE_UP_MS) {
          return { ...state, phase: 'lost', error: 'Still waiting after 15 minutes. Check the certificate list later; the node keeps working on it.' };
        }
        return { ...state, phase: 'running', pollErrors: 0 };
      }
      return { ...state, pollErrors: state.pollErrors + 1, phase: state.pollErrors + 1 >= JOB_MAX_POLL_ERRORS ? 'lost' : state.phase, error: 'The node sent a status this page does not know.' };
    }
    case 'pollError': {
      const pollErrors = state.pollErrors + 1;
      if (pollErrors >= JOB_MAX_POLL_ERRORS) {
        return { ...state, phase: 'lost', pollErrors, error: `Lost contact with the node: ${event.message || 'no answer'}. The job may still be running; check the certificate list.` };
      }
      return { ...state, pollErrors };
    }
    default:
      return state;
  }
}

export function isJobDone(state) {
  return state.phase === 'issued' || state.phase === 'failed' || state.phase === 'lost';
}

export function shouldPoll(state) {
  return state.phase === 'running' && Boolean(state.jobId);
}

export function jobStatusText(state) {
  switch (state.phase) {
    case 'submitting': return 'Sending the request to the node...';
    case 'running': return state.pollErrors
      ? `Waiting for the certificate authority. The last status check failed (${state.pollErrors} of ${JOB_MAX_POLL_ERRORS}); trying again.`
      : 'Waiting for the certificate authority. This usually takes under a minute; DNS checks can take a few.';
    case 'issued': return 'The certificate was issued and is now on the node.';
    case 'failed': return 'Issuing failed.';
    default: return 'Stopped waiting for the result.';
  }
}
