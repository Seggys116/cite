import test from 'node:test';
import assert from 'node:assert/strict';
import {
  MAX_RECIPIENTS, MAX_WEBHOOKS, emptyEmail, emptyWebhook, formFromSettings, formSignature, isDirty, maskUrl, parseRecipients, secretBadge,
  settingsFromForm, testResultText, testTarget, toggleEvent, urlProblem, validateForm,
} from '../../web/js/alertslib.js';

const stored = {
  enabled: true,
  webhooks: [{ id: 'w1', name: 'Ops chat', kind: 'slack', url: 'https://hooks.slack.com/********', events: ['site_unhealthy', 'bogus'] }],
  email: {
    host: 'smtp.example.com', port: 587, tls: 'starttls', username: 'mailer', password_set: true, from: 'cite@example.com', to: ['a@example.com', 'b@example.com'], events: ['cert_expiring'],
  },
  cooldown_secs: 600,
};

test('a stored webhook loads with a blank url field and unknown events dropped', () => {
  const form = formFromSettings(stored);
  assert.equal(form.webhooks[0].url, '');
  assert.equal(form.webhooks[0].storedUrl, 'https://hooks.slack.com/********');
  assert.deepEqual(form.webhooks[0].events, ['site_unhealthy']);
  assert.equal(form.email.password, '');
  assert.equal(form.email.passwordSet, true);
  assert.equal(form.email.to, 'a@example.com\nb@example.com');
  assert.equal(form.cooldown, '600');
});

test('missing settings give a disabled form with defaults', () => {
  const form = formFromSettings(null);
  assert.equal(form.enabled, false);
  assert.equal(form.email.enabled, false);
  assert.equal(form.cooldown, '900');
  assert.deepEqual(form.webhooks, []);
});

test('saving an untouched form keeps stored secrets by sending blanks with the item id', () => {
  const { settings, errors } = settingsFromForm(formFromSettings(stored));
  assert.deepEqual(errors, []);
  assert.equal(settings.webhooks[0].url, '');
  assert.equal(settings.webhooks[0].id, 'w1');
  assert.equal(settings.email.password, '');
  assert.deepEqual(settings.email.to, ['a@example.com', 'b@example.com']);
  assert.equal(settings.email.port, 587);
  assert.equal(settings.cooldown_secs, 600);
});

test('a new secret is sent in full and a new webhook has no id', () => {
  const form = formFromSettings(stored);
  form.webhooks[0].url = ' https://hooks.slack.com/services/T/B/X ';
  form.email.password = 'hunter2';
  const fresh = emptyWebhook();
  fresh.name = 'Second';
  fresh.url = 'https://discord.com/api/webhooks/1/abc';
  form.webhooks.push(fresh);
  const { settings } = settingsFromForm(form);
  assert.equal(settings.webhooks[0].url, 'https://hooks.slack.com/services/T/B/X');
  assert.equal(settings.email.password, 'hunter2');
  assert.equal('id' in settings.webhooks[1], false);
});

test('a new webhook must have a url but a stored one need not', () => {
  const form = formFromSettings(stored);
  const fresh = emptyWebhook();
  fresh.name = 'No url';
  form.webhooks.push(fresh);
  const errors = validateForm(form);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /Webhook 2: Enter the webhook URL/);
});

test('urls must be https without credentials', () => {
  assert.equal(urlProblem('', { required: false }), '');
  assert.match(urlProblem('http://example.com/x', { required: true }), /https/);
  assert.match(urlProblem('not a url', { required: true }), /valid URL/);
  assert.match(urlProblem('https://user:pw@example.com/', { required: true }), /user name/);
  assert.equal(urlProblem('https://example.com/hook', { required: true }), '');
});

test('limits on webhooks and recipients mirror the node', () => {
  const form = formFromSettings(stored);
  form.webhooks = Array.from({ length: MAX_WEBHOOKS + 1 }, (_, i) => ({ ...emptyWebhook(), name: 'w' + i, url: 'https://example.com/' + i }));
  assert.ok(validateForm(form).some((e) => e.includes(`At most ${MAX_WEBHOOKS}`)));
  const mail = formFromSettings(stored);
  mail.email.to = Array.from({ length: MAX_RECIPIENTS + 1 }, (_, i) => `u${i}@example.com`).join(',');
  assert.ok(validateForm(mail).some((e) => e.includes(`at most ${MAX_RECIPIENTS}`)));
});

test('email checks cover host, port, from, recipients and events', () => {
  const form = formFromSettings(null);
  form.email = { ...emptyEmail(), host: '', port: '70000', from: 'nope', to: 'x', events: [] };
  const errors = validateForm(form);
  assert.equal(errors.length, 5);
  form.email.enabled = false;
  assert.deepEqual(validateForm(form), []);
});

test('a disabled email block is sent as null and the cooldown is checked', () => {
  const form = formFromSettings(stored);
  form.email.enabled = false;
  assert.equal(settingsFromForm(form).settings.email, null);
  form.cooldown = '-1';
  assert.match(settingsFromForm(form).errors[0], /Cooldown/);
  form.cooldown = '86401';
  assert.match(settingsFromForm(form).errors[0], /Cooldown/);
  form.cooldown = '0';
  assert.deepEqual(settingsFromForm(form).errors, []);
});

test('recipients are split, trimmed and deduplicated', () => {
  assert.deepEqual(parseRecipients('A@x.com, a@x.com\n b@x.com;'), ['A@x.com', 'b@x.com']);
});

test('dirty tracking notices edits and typed secrets but not reverts', () => {
  const form = formFromSettings(stored);
  const base = formSignature(form);
  assert.equal(isDirty(form, base), false);
  form.email.password = 'x';
  assert.equal(isDirty(form, base), true);
  form.email.password = '';
  assert.equal(isDirty(form, base), false);
  form.webhooks[0].name = 'Renamed';
  assert.equal(isDirty(form, base), true);
});

test('the signature never contains secret text', () => {
  const form = formFromSettings(stored);
  form.webhooks[0].url = 'https://secret.example.com/token123';
  form.email.password = 'hunter2';
  const sig = formSignature(form);
  assert.equal(sig.includes('token123'), false);
  assert.equal(sig.includes('hunter2'), false);
});

test('masking keeps only the host and tolerates already masked text', () => {
  assert.equal(maskUrl('https://hooks.slack.com/services/T0/B0/secret'), 'https://hooks.slack.com/********');
  assert.equal(maskUrl('https://hooks.slack.com/********'), 'https://hooks.slack.com/********');
  assert.equal(maskUrl(''), '');
  assert.equal(maskUrl('garbage'), '********');
  assert.equal(secretBadge(true), 'saved');
  assert.equal(secretBadge(false), 'not set');
});

test('event toggling keeps a stable order', () => {
  assert.deepEqual(toggleEvent(['build_failed'], 'site_unhealthy', true), ['site_unhealthy', 'build_failed']);
  assert.deepEqual(toggleEvent(['build_failed', 'site_unhealthy'], 'build_failed', false), ['site_unhealthy']);
});

test('test targets and results are described plainly', () => {
  assert.equal(testTarget('email'), 'email');
  assert.equal(testTarget('webhook', 'w1'), 'webhook:w1');
  assert.match(testResultText({ ok: true }), /sent/);
  assert.equal(testResultText({ ok: false, error: 'timeout' }), 'Test failed: timeout');
  assert.match(testResultText(null), /did not say why/);
});
