// Pure helpers for the alert settings form: conversion to and from the node JSON, validation and secret masking

export const MAX_WEBHOOKS = 10;
export const MAX_RECIPIENTS = 5;
export const MAX_COOLDOWN_SECS = 86400;
export const DEFAULT_COOLDOWN_SECS = 900;
export const WEBHOOK_KINDS = [
  { value: 'generic', label: 'Generic JSON webhook' },
  { value: 'discord', label: 'Discord' },
  { value: 'slack', label: 'Slack' },
];
export const TLS_MODES = [
  { value: 'starttls', label: 'STARTTLS (usually port 587)' },
  { value: 'tls', label: 'TLS from the start (usually port 465)' },
  { value: 'none', label: 'No encryption (not recommended)' },
];
export const ALERT_EVENTS = [
  { value: 'site_unhealthy', label: 'A site becomes unhealthy' },
  { value: 'site_recovered', label: 'A site recovers' },
  { value: 'build_failed', label: 'A build fails' },
  { value: 'deploy_succeeded', label: 'A deploy succeeds' },
  { value: 'cert_expiring', label: 'A certificate is about to expire' },
  { value: 'node_error', label: 'The node reports an error' },
];

const EVENT_VALUES = new Set(ALERT_EVENTS.map((e) => e.value));
const KIND_VALUES = new Set(WEBHOOK_KINDS.map((k) => k.value));
const TLS_VALUES = new Set(TLS_MODES.map((t) => t.value));
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const HOST = /^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$/;

let counter = 0;
const localKey = () => {
  counter += 1;
  return 'new-' + counter;
};

export function eventLabel(value) {
  const found = ALERT_EVENTS.find((e) => e.value === value);
  return found ? found.label : String(value);
}

export function emptyWebhook() {
  return { key: localKey(), id: '', name: '', kind: 'generic', url: '', storedUrl: '', events: ['site_unhealthy', 'site_recovered'] };
}

export function emptyEmail() {
  return {
    enabled: true, host: '', port: '587', tls: 'starttls', username: '', password: '', passwordSet: false, from: '', to: '', events: ['site_unhealthy', 'cert_expiring'],
  };
}

const cleanEvents = (list) => (Array.isArray(list) ? list.filter((e) => EVENT_VALUES.has(e)) : []);

// Stored URLs arrive masked; the field starts blank and the masked text is only shown beside it
export function formFromSettings(settings) {
  const s = settings && typeof settings === 'object' ? settings : {};
  const email = s.email && typeof s.email === 'object' ? s.email : null;
  return {
    enabled: Boolean(s.enabled),
    cooldown: String(Number.isInteger(s.cooldown_secs) ? s.cooldown_secs : DEFAULT_COOLDOWN_SECS),
    webhooks: (Array.isArray(s.webhooks) ? s.webhooks : []).map((w) => ({
      key: String(w.id || localKey()),
      id: String(w.id || ''),
      name: String(w.name || ''),
      kind: KIND_VALUES.has(w.kind) ? w.kind : 'generic',
      url: '',
      storedUrl: String(w.url || ''),
      events: cleanEvents(w.events),
    })),
    email: email ? {
      enabled: true,
      host: String(email.host || ''),
      port: String(email.port ?? 587),
      tls: TLS_VALUES.has(email.tls) ? email.tls : 'starttls',
      username: String(email.username || ''),
      password: '',
      passwordSet: Boolean(email.password_set),
      from: String(email.from || ''),
      to: (Array.isArray(email.to) ? email.to : []).join('\n'),
      events: cleanEvents(email.events),
    } : { ...emptyEmail(), enabled: false },
  };
}

export function parseRecipients(text) {
  const seen = new Set();
  const out = [];
  for (const part of String(text || '').split(/[\s,;]+/)) {
    const item = part.trim();
    if (!item || seen.has(item.toLowerCase())) continue;
    seen.add(item.toLowerCase());
    out.push(item);
  }
  return out;
}

export function urlProblem(text, { required }) {
  const value = String(text || '').trim();
  if (!value) return required ? 'Enter the webhook URL.' : '';
  let url;
  try {
    url = new URL(value);
  } catch (ex) {
    return 'That is not a valid URL.';
  }
  if (url.protocol !== 'https:') return 'Webhook URLs must start with https://.';
  if (!url.hostname) return 'The URL needs a host name.';
  if (url.username || url.password) return 'Do not put a user name or password in the URL.';
  return '';
}

function webhookProblem(w, index) {
  const label = `Webhook ${index + 1}`;
  if (!w.name.trim()) return `${label}: enter a name.`;
  if (w.name.trim().length > 64) return `${label}: the name is longer than 64 characters.`;
  const url = urlProblem(w.url, { required: !(w.id && w.storedUrl) });
  if (url) return `${label}: ${url}`;
  if (!w.events.length) return `${label}: choose at least one event.`;
  return '';
}

function emailProblems(e) {
  const out = [];
  if (!HOST.test(e.host.trim())) out.push('Email: enter the mail server host name.');
  const port = Number(e.port);
  if (!/^\d+$/.test(String(e.port).trim()) || port < 1 || port > 65535) out.push('Email: the port must be between 1 and 65535.');
  if (!TLS_VALUES.has(e.tls)) out.push('Email: choose an encryption mode.');
  if (!EMAIL.test(e.from.trim())) out.push('Email: enter a valid From address.');
  const to = parseRecipients(e.to);
  if (!to.length) out.push('Email: add at least one recipient.');
  else if (to.length > MAX_RECIPIENTS) out.push(`Email: at most ${MAX_RECIPIENTS} recipients are allowed.`);
  else if (to.some((r) => !EMAIL.test(r))) out.push('Email: one of the recipients is not a valid address.');
  if (e.password && !e.username.trim()) out.push('Email: a password needs a user name.');
  if (!e.events.length) out.push('Email: choose at least one event.');
  return out;
}

export function validateForm(form) {
  const errors = [];
  const cooldown = String(form.cooldown).trim();
  if (!/^\d+$/.test(cooldown) || Number(cooldown) > MAX_COOLDOWN_SECS) errors.push(`Cooldown must be a whole number of seconds from 0 to ${MAX_COOLDOWN_SECS}.`);
  if (form.webhooks.length > MAX_WEBHOOKS) errors.push(`At most ${MAX_WEBHOOKS} webhooks are allowed.`);
  form.webhooks.forEach((w, i) => {
    const problem = webhookProblem(w, i);
    if (problem) errors.push(problem);
  });
  if (form.email.enabled) errors.push(...emailProblems(form.email));
  return errors;
}

// A blank URL or password goes out as an empty string, which the node reads as keep what is stored for that id
export function settingsFromForm(form) {
  const errors = validateForm(form);
  if (errors.length) return { errors, settings: null };
  const e = form.email;
  const settings = {
    enabled: form.enabled,
    webhooks: form.webhooks.map((w) => {
      const out = { name: w.name.trim(), kind: w.kind, url: w.url.trim(), events: [...w.events] };
      if (w.id) out.id = w.id;
      return out;
    }),
    email: e.enabled ? {
      host: e.host.trim(),
      port: Number(e.port),
      tls: e.tls,
      username: e.username.trim(),
      password: e.password,
      from: e.from.trim(),
      to: parseRecipients(e.to),
      events: [...e.events],
    } : null,
    cooldown_secs: Number(String(form.cooldown).trim()),
  };
  return { errors: [], settings };
}

// Secrets are left out so an unsaved-changes check never holds them and typing a new secret still counts as a change
export function formSignature(form) {
  const e = form.email;
  return JSON.stringify([
    form.enabled, form.cooldown, form.webhooks.map((w) => [w.id, w.name, w.kind, w.url !== '', [...w.events].sort()]),
    e.enabled, e.host, e.port, e.tls, e.username, e.password !== '', e.from, parseRecipients(e.to), [...e.events].sort(),
  ]);
}

export function isDirty(form, baseline) {
  return formSignature(form) !== baseline;
}

// Shows only the scheme and host of a URL, since webhook paths carry the secret
export function maskUrl(url) {
  const text = String(url || '');
  if (!text) return '';
  if (/\*/.test(text) || text.includes('•')) return text;
  try {
    const parsed = new URL(text);
    return `${parsed.protocol}//${parsed.host}/********`;
  } catch (ex) {
    return '********';
  }
}

export function secretBadge(isSet) {
  return isSet ? 'saved' : 'not set';
}

export function toggleEvent(events, value, on) {
  const set = new Set(events);
  if (on) set.add(value);
  else set.delete(value);
  return ALERT_EVENTS.map((e) => e.value).filter((v) => set.has(v));
}

export function testTarget(kind, id) {
  return kind === 'email' ? 'email' : `webhook:${id}`;
}

export function testResultText(result) {
  if (result && result.ok) return 'Test sent. Check the destination.';
  const reason = result && result.error ? String(result.error) : 'The node did not say why.';
  return `Test failed: ${reason}`;
}
