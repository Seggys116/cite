import test from 'node:test';
import assert from 'node:assert/strict';
import {
  healthFromFields, healthPathProblem, healthProblems, hostProblem, hostsProblem, nameProblem, routingProblem, siteBody,
} from '../../web/js/sitelib.js';
import { dirtyGroup, dirtyText, makeDirty } from '../../web/js/dirtylib.js';

const health = (over = {}) => ({ path: '/healthz', interval_ms: 2000, timeout_ms: 1500, rise: 2, fall: 3, ...over });

test('the name follows the node text rule', () => {
  assert.equal(nameProblem('Storefront'), null);
  assert.ok(nameProblem(''));
  assert.ok(nameProblem('   '));
  assert.ok(nameProblem('a\nb'));
  assert.equal(nameProblem('x'.repeat(128)), null);
  assert.ok(nameProblem('x'.repeat(129)));
});

test('hosts are names or wildcards and at least one is kept', () => {
  assert.equal(hostProblem('shop.example.com'), null);
  assert.equal(hostProblem('*.example.com'), null);
  assert.ok(hostProblem('bad host'));
  assert.ok(hostProblem('*.'));
  assert.ok(hostProblem('http://x.com'));
  assert.equal(hostsProblem(['a.example.com', '*.b.example.com']), null);
  assert.match(hostsProblem([]), /at least one/);
  assert.match(hostsProblem(Array.from({ length: 65 }, (_, i) => `h${i}.example.com`)), /at most 64/);
  assert.match(hostsProblem(['ok.example.com', 'no spaces']), /no spaces/);
});

test('the health path is plain printable text', () => {
  for (const ok of ['/', '/healthz', '/v1/health?x=1']) assert.equal(healthPathProblem(ok), null, ok);
  for (const bad of ['', 'health', '/a b', '/a#b', '/a"b', "/a'b", '/a\\b', '/a$b', `/${'x'.repeat(512)}`]) assert.ok(healthPathProblem(bad), bad);
});

test('health numbers follow the node ranges', () => {
  assert.deepEqual(healthProblems(health()), {});
  assert.ok(healthProblems(health({ interval_ms: 99 })).interval_ms);
  assert.deepEqual(Object.keys(healthProblems(health({ interval_ms: 60000, timeout_ms: 10000 }))), []);
  assert.ok(healthProblems(health({ interval_ms: 60001 })).interval_ms);
  assert.ok(healthProblems(health({ timeout_ms: 99 })).timeout_ms);
  assert.ok(healthProblems(health({ timeout_ms: 10001, interval_ms: 60000 })).timeout_ms);
  assert.match(healthProblems(health({ interval_ms: 1000, timeout_ms: 1500 })).timeout_ms, /longer than the interval/);
  assert.ok(healthProblems(health({ rise: 0 })).rise);
  assert.ok(healthProblems(health({ rise: 11 })).rise);
  assert.ok(healthProblems(health({ fall: 0 })).fall);
  assert.ok(healthProblems(health({ fall: 1.5 })).fall);
  assert.ok(healthProblems(health({ path: 'x' })).path);
  assert.ok(healthProblems(null).path);
});

test('form fields become numbers and blanks stay invalid', () => {
  const h = healthFromFields({ path: '/x', interval_ms: '2000', timeout_ms: ' 1500 ', rise: '2', fall: '' });
  assert.deepEqual([h.interval_ms, h.timeout_ms, h.rise], [2000, 1500, 2]);
  assert.ok(Number.isNaN(h.fall));
  assert.ok(healthProblems(h).fall);
});

test('the routing form reports its first problem in layout order', () => {
  const good = { name: 'Shop', kind: 'site', hosts: ['a.example.com'], pathRows: [], health: health() };
  assert.equal(routingProblem(good), null);
  assert.equal(routingProblem({ ...good, name: '' }).field, 'name');
  assert.equal(routingProblem({ ...good, kind: 'x' }).field, 'kind');
  assert.equal(routingProblem({ ...good, hosts: [] }).field, 'hosts');
  assert.equal(routingProblem({ ...good, pathRows: [{ type: 'path_regex', value: '(', header: {} }] }).field, 'paths');
  assert.equal(routingProblem({ ...good, health: health({ path: 'x', rise: 0 }) }).field, 'path');
  assert.equal(routingProblem({ ...good, health: health({ fall: 0 }) }).field, 'fall');
});

test('the save body takes the stored site and lays the changes over it', () => {
  const site = {
    id: 'shop', name: 'Shop', hosts: ['a.example.com'], path_regex: '^/v1/', kind: 'api', blue: { targets: [] }, green: { targets: [] }, active: 'blue',
    health: health(), source: { repo: 'acme/shop' }, access: { cloudflare_only: true, tls: 'full' }, history: [{ id: 'x' }], live: {},
  };
  const body = siteBody(site, { name: 'Shop 2', source: { repo: 'acme/shop2' } });
  assert.equal(body.name, 'Shop 2');
  assert.deepEqual(body.source, { repo: 'acme/shop2' });
  assert.deepEqual(body.path_regexes, ['^/v1/']);
  assert.deepEqual(body.path_prefixes, []);
  assert.equal('path_regex' in body, false);
  assert.equal('history' in body, false);
  assert.equal('live' in body, false);
  assert.deepEqual(body.access, { cloudflare_only: true, tls: 'full' });
  body.hosts.push('b');
  body.health.path = '/z';
  assert.deepEqual(site.hosts, ['a.example.com']);
  assert.equal(site.health.path, '/healthz');
  assert.equal('access' in siteBody({ ...site, access: undefined }), false);
  assert.equal(siteBody({ ...site, source: undefined }).source, null);
});

test('a form is dirty only while it differs from the saved value', () => {
  const state = { name: 'Shop', hosts: ['a'] };
  const d = makeDirty(() => state);
  assert.equal(d.dirty(), false);
  state.name = 'Shop 2';
  assert.equal(d.dirty(), true);
  state.name = 'Shop';
  assert.equal(d.dirty(), false);
  state.hosts.push('b');
  assert.equal(d.dirty(), true);
  d.reset();
  assert.equal(d.dirty(), false);
});

test('a page reports which forms have unsaved changes', () => {
  const a = { v: 1 };
  const b = { v: 1 };
  const g = dirtyGroup({ Routing: makeDirty(() => a), 'Build settings': makeDirty(() => b) });
  assert.equal(g.dirty(), false);
  assert.equal(dirtyText(g.names()), '');
  a.v = 2;
  assert.deepEqual(g.names(), ['Routing']);
  assert.equal(dirtyText(g.names()), 'Unsaved changes in Routing');
  b.v = 2;
  assert.equal(dirtyText(g.names()), 'Unsaved changes in Routing and Build settings');
  assert.equal(dirtyText(['A', 'B', 'C']), 'Unsaved changes in A, B and C');
  g.reset();
  assert.equal(g.dirty(), false);
});
