import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildRule, emptyForm, formKindOf, reviewLines, ruleToForm, stepProblem,
} from '../../web/js/rulebuilder.js';
import { newRow } from '../../web/js/conditionlib.js';

const cond = (type, value) => ({ ...newRow(type), value });
const form = (over = {}) => ({ ...emptyForm(), name: 'Rule', id: 'r1', ...over });

test('each step explains what is missing before Next is allowed', () => {
  const f = form();
  assert.match(stepProblem(f, 0), /Choose what should happen/);
  f.kind = 'block';
  assert.equal(stepProblem(f, 0), null);
  assert.match(stepProblem(f, 1), /at least one condition/);
  f.conditions = [cond('path_prefix', '/admin')];
  assert.equal(stepProblem(f, 1), null);
  f.conditions = [cond('path_prefix', 'admin')];
  assert.match(stepProblem(f, 1), /^Condition 1:/);
  assert.equal(stepProblem(f, 2), null);
  f.name = '  ';
  assert.match(stepProblem(f, 3), /name/);
  f.name = 'Ok';
  f.label = 'Bad Label';
  assert.match(stepProblem(f, 3), /label/);
  f.label = 'good-label';
  assert.equal(stepProblem(f, 3), null);
});

test('a block rule sends list matchers and the chosen action', () => {
  const f = form({ kind: 'block', action: 'tarpit', conditions: [cond('path_prefix', '/a'), cond('path_prefix', '/b'), cond('method', 'post')] });
  assert.deepEqual(buildRule(f), {
    rule: {
      id: 'r1', name: 'Rule', enabled: true, action: 'tarpit', site: null, matchers: { path_prefixes: ['/a', '/b'], methods: ['POST'] },
    },
  });
  const scoped = buildRule({ ...f, site: 'shop', label: 'my-label' }).rule;
  assert.equal(scoped.site, 'shop');
  assert.equal(scoped.label, 'my-label');
  const empty = buildRule(form({ kind: 'block' }));
  assert.equal(empty.step, 1);
  assert.match(empty.error, /at least one condition/);
});

test('a redirect rule carries redirect and no action, with the loop checks', () => {
  const f = form({ kind: 'redirect', redirect: { to: '{scheme}://{www_host}{path}{query}', status: '302' } });
  const { rule } = buildRule(f);
  assert.deepEqual(rule.redirect, { to: '{scheme}://{www_host}{path}{query}', status: 302 });
  assert.equal('action' in rule, false);
  assert.deepEqual(rule.matchers, {});
  const loops = buildRule(form({ kind: 'redirect', redirect: { to: '/new', status: 301 } }));
  assert.equal(loops.step, 2);
  assert.match(loops.error, /path condition/);
  const ok = buildRule(form({ kind: 'redirect', redirect: { to: '/new', status: 301 }, conditions: [cond('path_prefix', '/old')] }));
  assert.equal(ok.rule.matchers.path_prefixes[0], '/old');
  assert.match(stepProblem(form({ kind: 'redirect', redirect: { to: '', status: 301 }, conditions: [cond('host', 'a.com')] }), 2), /redirect target/);
});

test('header changes follow the node rules and need at least one', () => {
  assert.match(stepProblem(form({ kind: 'headers' }), 2), /at least one header change/);
  const ops = [{ target: 'response', op: 'set', name: 'X-Frame-Options', value: 'DENY' }, { target: 'request', op: 'remove', name: 'X-Debug', value: 'ignored' }];
  const { rule } = buildRule(form({ kind: 'headers', headers: ops }));
  assert.deepEqual(rule.headers, [
    { target: 'response', op: 'set', name: 'X-Frame-Options', value: 'DENY' },
    { target: 'request', op: 'remove', name: 'X-Debug' },
  ]);
  assert.equal('cors' in rule, false);
  assert.equal('action' in rule, false);
  assert.match(stepProblem(form({ kind: 'headers', headers: [{ target: 'request', op: 'set', name: 'Host', value: 'x' }] }), 2), /Host/);
  const many = Array.from({ length: 17 }, () => ({ target: 'response', op: 'set', name: 'X-A', value: 'v' }));
  assert.match(stepProblem(form({ kind: 'headers', headers: many }), 2), /at most 16/);
});

test('a CORS rule is checked like the node does', () => {
  const cors = { origins: 'https://app.example.com', methods: 'GET POST', allow_headers: '', expose_headers: '', credentials: true, max_age: '600' };
  const { rule } = buildRule(form({ kind: 'cors', cors }));
  assert.equal(rule.cors.max_age_secs, 600);
  assert.deepEqual(rule.cors.methods, ['GET', 'POST']);
  assert.equal('headers' in rule, false);
  assert.match(stepProblem(form({ kind: 'cors', cors: { ...cors, origins: '*' } }), 2), /Credentials/);
  assert.match(stepProblem(form({ kind: 'cors', cors: { ...cors, origins: '' } }), 2), /1 to 32 origins/);
});

test('an existing rule opens in the same steps and saves back whole', () => {
  const stored = {
    id: 'c', name: 'Cors', enabled: false, site: 'api', label: 'cors-app', matchers: { hosts: ['api.example.com'] },
    cors: { origins: ['https://a.example.com', 'https://b.example.com'], methods: ['GET'], allow_headers: ['X-A'], expose_headers: [], credentials: true, max_age_secs: 600 },
  };
  const f = ruleToForm(stored);
  assert.equal(f.kind, 'cors');
  assert.equal(f.cors.origins, 'https://a.example.com\nhttps://b.example.com');
  assert.equal(f.cors.max_age, '600');
  assert.equal(f.enabled, false);
  assert.equal(f.label, 'cors-app');
  assert.equal(f.conditions.length, 1);
  assert.deepEqual(buildRule(f).rule, stored);
});

test('a rule with headers and CORS keeps both when saved again', () => {
  const stored = {
    id: 'both', name: 'Both', enabled: true, site: null, matchers: {},
    headers: [{ target: 'response', op: 'set', name: 'X-A', value: 'v' }],
    cors: { origins: ['*'], methods: [], allow_headers: [], expose_headers: [], credentials: false, max_age_secs: 0 },
  };
  assert.equal(formKindOf(stored), 'headers');
  const f = ruleToForm(stored);
  assert.equal(f.alsoCors, true);
  const { rule } = buildRule(f);
  assert.deepEqual(rule.headers, stored.headers);
  assert.deepEqual(rule.cors, stored.cors);
  const reverse = ruleToForm({ ...stored, headers: [] });
  assert.equal(reverse.kind, 'cors');
  assert.equal('headers' in buildRule(reverse).rule, false);
});

test('a stored secret condition is kept by sending a blank value', () => {
  const stored = { id: 'k', name: 'Key', enabled: true, action: 'deny', site: null, matchers: { headers: [{ name: 'X-Key', regex: null, equals: '', negate: true, secret: true }] } };
  const f = ruleToForm(stored);
  assert.equal(f.conditions[0].header.value, '');
  assert.deepEqual(buildRule(f).rule.matchers.headers[0], stored.matchers.headers[0]);
  f.conditions[0].header.value = 'newvalue';
  assert.equal(buildRule(f).rule.matchers.headers[0].equals, 'newvalue');
});

test('the review lists the effect, the sentence and the scope', () => {
  const f = form({ kind: 'block', action: 'drop', conditions: [cond('path_prefix', '/a')], site: 'shop' });
  const lines = new Map(reviewLines(f, (id) => `Site ${id}`));
  assert.equal(lines.get('When'), 'When the path starts with /a.');
  assert.equal(lines.get('Action'), 'drop');
  assert.equal(lines.get('Applies to'), 'Site shop');
  assert.equal(new Map(reviewLines({ ...f, site: '' }, () => '')).get('Applies to'), 'All sites on this node');
});
