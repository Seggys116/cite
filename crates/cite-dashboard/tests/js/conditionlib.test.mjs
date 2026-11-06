import test from 'node:test';
import assert from 'node:assert/strict';
import {
  describeMatchers, describeRows, matchersToRows, newRow, pathFieldsFromRows, pathRowsFromSite, pathsProblem, rowProblem, rowsProblem, rowsToMatchers,
} from '../../web/js/conditionlib.js';

const row = (type, value = '', header) => ({ ...newRow(type), value, ...(header ? { header: { ...newRow('header').header, ...header } } : {}) });

test('rows of one type become one list and blank rows are ignored', () => {
  const m = rowsToMatchers([row('path_prefix', '/a'), row('path_prefix', ' /b '), row('path_prefix', '/a'), row('method', 'get'), row('host', ''), row('scheme', 'http')]);
  assert.deepEqual(m, { path_prefixes: ['/a', '/b'], methods: ['GET'], scheme: 'http' });
  assert.deepEqual(rowsToMatchers([]), {});
  assert.deepEqual(rowsToMatchers([row('header', '', { name: '  ' })]), {});
});

test('matchers survive rows and back unchanged', () => {
  const cases = [
    { path_prefixes: ['/a', '/b'], path_regexes: ['^/x/[0-9]+$'], user_agent_regexes: ['(?i)bot'], referer_regexes: ['^https://spam'], methods: ['GET', 'POST'], hosts: ['a.example.com', '*.b.example.com'], cidrs: ['203.0.113.0/24'], scheme: 'https' },
    { headers: [{ name: 'X-Env', regex: null, equals: 'staging', negate: false, secret: false }, { name: 'X-A', regex: '^a', equals: null, negate: true, secret: false }] },
    { headers: [{ name: 'X-Key', regex: null, equals: '', negate: false, secret: true }] },
    {},
  ];
  for (const m of cases) assert.deepEqual(rowsToMatchers(matchersToRows(m)), m);
});

test('old single-value matchers open as one-item lists', () => {
  const rows = matchersToRows({ path_prefix: '/old', host: 'a.com', header: { name: 'X-A', equals: '1', negate: false, secret: false } });
  assert.deepEqual(rowsToMatchers(rows), {
    path_prefixes: ['/old'], hosts: ['a.com'], headers: [{ name: 'X-A', regex: null, equals: '1', negate: false, secret: false }],
  });
});

test('a stored secret opens blank and flagged, and is never put into a row', () => {
  const [r] = matchersToRows({ headers: [{ name: 'X-Key', regex: null, equals: '', negate: false, secret: true }] });
  assert.equal(r.header.value, '');
  assert.equal(r.header.stored, true);
  assert.equal(rowProblem(r), null);
  r.header.value = 'a-new-value';
  assert.equal(rowsToMatchers([r]).headers[0].equals, 'a-new-value');
});

test('each row type is checked', () => {
  assert.equal(rowProblem(row('path_prefix', '/ok')), null);
  assert.ok(rowProblem(row('path_prefix', 'nope')));
  assert.ok(rowProblem(row('path_prefix', '/a b')));
  assert.equal(rowProblem(row('path_regex', '^/a/')), null);
  assert.ok(rowProblem(row('path_regex', '(')));
  assert.equal(rowProblem(row('user_agent', '(?i)scraper')), null);
  assert.ok(rowProblem(row('referer', 'a b')));
  assert.equal(rowProblem(row('method', 'get')), null);
  assert.ok(rowProblem(row('method', 'G T')));
  assert.equal(rowProblem(row('host', 'shop.example.com')), null);
  assert.equal(rowProblem(row('host', '*.example.com')), null);
  assert.ok(rowProblem(row('host', 'bad host')));
  assert.equal(rowProblem(row('cidr', '203.0.113.0/24')), null);
  assert.equal(rowProblem(row('cidr', '2001:db8::/32')), null);
  assert.ok(rowProblem(row('cidr', 'nope')));
  assert.equal(rowProblem(row('scheme', 'https')), null);
  assert.ok(rowProblem(row('scheme', 'ftp')));
  assert.ok(rowProblem(row('header', '', { name: '1x', value: 'v' })));
  assert.ok(rowProblem(row('header', '', { name: 'X-A', value: '' })));
  assert.equal(rowProblem(row('header', '', { name: 'X-A', value: 'v' })), null);
  assert.equal(rowProblem(row('path_prefix', '')), null);
});

test('the list is checked as a whole', () => {
  assert.equal(rowsProblem([row('path_prefix', '/a'), row('method', 'GET')]), null);
  assert.match(rowsProblem([row('path_prefix', '/a'), row('path_prefix', 'bad')]), /^Condition 2:/);
  assert.match(rowsProblem([row('scheme', 'http'), row('scheme', 'https')]), /only one scheme/);
  assert.equal(rowsProblem([row('scheme', 'http'), row('scheme', 'http')]), null);
  const many = (n, make) => Array.from({ length: n }, (_, i) => make(i));
  assert.equal(rowsProblem(many(32, (i) => row('path_prefix', `/p${i}`))), null);
  assert.match(rowsProblem(many(33, (i) => row('path_prefix', `/p${i}`))), /at most 32/);
  assert.equal(rowsProblem(many(256, (i) => row('cidr', `10.${i}.0.0/16`))), null);
  assert.match(rowsProblem(many(257, (i) => row('cidr', `10.${i}.0.0/16`))), /at most 256/);
});

test('the sentence reads alternatives as or and different kinds as and', () => {
  assert.equal(describeMatchers({}), 'Every request.');
  assert.equal(describeMatchers({ path_prefixes: ['/a', '/b'], methods: ['POST'] }), 'When the path starts with /a or /b, and the method is POST.');
  assert.equal(describeMatchers({ hosts: ['a.com'], scheme: 'http' }), 'When the host is a.com, and the connection is http.');
  assert.equal(
    describeMatchers({ headers: [{ name: 'X-A', equals: '1', negate: false }, { name: 'X-B', regex: '^b', negate: true }] }),
    'When the header X-A equals 1 or the header X-B does not match ^b.',
  );
  assert.equal(describeRows([row('cidr', '203.0.113.0/24'), row('cidr', '198.51.100.0/24')]), 'When the visitor address is in 203.0.113.0/24 or 198.51.100.0/24.');
});

test('the sentence never writes out a secret value', () => {
  const hidden = ['sec', 'ret'].join('') + '-token-value';
  const text = describeMatchers({ headers: [{ name: 'X-Key', equals: hidden, secret: true, negate: false }] });
  assert.equal(text, 'When the header X-Key equals a secret value.');
  assert.ok(!text.includes(hidden));
});

test('site paths use the same rows and read the old single regex', () => {
  const rows = pathRowsFromSite({ path_prefixes: ['/a'], path_regexes: ['^/b'], path_regex: '^/c' });
  assert.deepEqual(rows.map((r) => [r.type, r.value]), [['path_prefix', '/a'], ['path_regex', '^/b'], ['path_regex', '^/c']]);
  assert.deepEqual(pathFieldsFromRows(rows), { path_prefixes: ['/a'], path_regexes: ['^/b', '^/c'] });
  assert.deepEqual(pathFieldsFromRows([]), { path_prefixes: [], path_regexes: [] });
  assert.deepEqual(pathFieldsFromRows([row('host', 'a.com'), row('path_prefix', '/x')]), { path_prefixes: ['/x'], path_regexes: [] });
  assert.deepEqual(pathRowsFromSite(null), []);
  assert.equal(pathsProblem([row('path_prefix', '/ok'), row('path_regex', '(')]).startsWith('Condition 2:'), true);
  assert.equal(pathsProblem([row('host', 'bad host')]), null);
});
