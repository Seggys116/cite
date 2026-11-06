import test from 'node:test';
import assert from 'node:assert/strict';
import {
  corsFromForm, corsProblem, effectView, hasMatcher, headerMatcherProblem, headerOpProblem, listsOf, parseTemplate,
  patternProblem, presetNeedsScopeWarning, redirectProblem, resaveBody, ruleKind, splitList,
} from '../../web/js/rulelib.js';
import { matcherSummary } from '../../web/js/conditionlib.js';

test('good redirect templates parse and bad ones are explained', () => {
  for (const ok of ['https://example.com/', 'http://example.com', 'https://example.com:8443/x?y=1', '{scheme}://{www_host}{path}{query}',
    '{scheme}://{apex_host}{path}{query}', 'https://{host}{path}{query}', 'https://www.{host}/home', '/new', '/new/{path}', '/a%20b']) {
    assert.equal(parseTemplate(ok).error, undefined, ok);
  }
  for (const bad of ['', 'javascript:alert(1)', 'data:text/html,x', '//evil.example.com/x', '/{path}', 'relative/path', 'ftp://example.com/',
    'HTTP://example.com/', 'https://exam ple.com/', 'https://example.com/a\r\nSet-Cookie: x=1', 'https://example.com/"', "https://example.com/'",
    'https://example.com/\\x', 'https://example.com/#frag', 'https://example.com/$HOME', 'https://example.com/`id`', 'https://user@example.com/',
    'https:///x', 'https://{path}', 'https://{host}x{scheme}/', '{host}', '{scheme}://{host}{path}', '{scheme}://{host}{path}{query}',
    'https://{www_host}{apex_host}/', 'https://example.com/{nope}', 'https://example.com/{HOST}', 'https://example.com/{host',
    'https://example.com/host}', 'https://example.com/{}']) {
    assert.ok(parseTemplate(bad).error, JSON.stringify(bad));
  }
  assert.match(parseTemplate('https://example.com/{nope}').error, /\{nope\}/);
  assert.ok(parseTemplate('/' + 'a'.repeat(512)).error);
  assert.equal(parseTemplate('/' + 'a'.repeat(511)).error, undefined);
});

test('template facts drive the loop checks', () => {
  assert.deepEqual(
    (({ relative, https, ownHost, sameHost }) => ({ relative, https, ownHost, sameHost }))(parseTemplate('https://{host}{path}')),
    { relative: false, https: true, ownHost: true, sameHost: true },
  );
  assert.equal(parseTemplate('/x').relative, true);
  assert.equal(parseTemplate('{scheme}://{www_host}{path}').usesWww, true);
  assert.equal(parseTemplate('{scheme}://{apex_host}{path}').usesApex, true);
  assert.equal(parseTemplate('https://other.example.org/x').ownHost, false);
});

test('redirects that would loop are refused like the node does', () => {
  const to = (target, status = 301) => ({ to: target, status });
  assert.equal(redirectProblem(to('{scheme}://{www_host}{path}{query}'), {}), null);
  assert.equal(redirectProblem(to('{scheme}://{apex_host}{path}{query}'), {}), null);
  assert.equal(redirectProblem(to('https://{host}{path}{query}'), { scheme: 'http' }), null);
  assert.match(redirectProblem(to('https://{host}{path}{query}'), {}), /scheme condition set to http/);
  assert.match(redirectProblem(to('/new'), {}), /path condition/);
  assert.equal(redirectProblem(to('/new'), { path_prefixes: ['/old'] }), null);
  assert.equal(redirectProblem(to('/new'), { path_prefix: '/old' }), null);
  assert.match(redirectProblem(to('/old/new'), { path_prefixes: ['/old'] }), /would loop/);
  assert.match(redirectProblem(to('/old/new'), { path_prefixes: ['/x', '/old'] }), /would loop/);
  assert.match(redirectProblem(to('https://other.example.org/'), {}), /Add a condition/);
  assert.equal(redirectProblem(to('https://other.example.org/'), { hosts: ['a.example.com'] }), null);
  assert.match(redirectProblem(to('/x', 303), { path_prefixes: ['/a'] }), /301, 302, 307 or 308/);
  for (const status of [301, 302, 307, 308]) assert.equal(redirectProblem(to('/new', status), { path_regexes: ['^/old'] }), null);
  assert.match(redirectProblem(to('javascript:alert(1)'), { hosts: ['a.com'] }), /redirect target/);
});

test('matchers read as lists whether they are new lists or old single values', () => {
  const l = listsOf({ path_prefix: '/a', path_prefixes: ['/b'], host: 'x.com', header: { name: 'X-A', equals: '1' }, scheme: 'http' });
  assert.deepEqual(l.path_prefixes, ['/b', '/a']);
  assert.deepEqual(l.hosts, ['x.com']);
  assert.equal(l.headers.length, 1);
  assert.equal(l.scheme, 'http');
  assert.deepEqual(listsOf(null).methods, []);
  assert.equal(hasMatcher({}), false);
  assert.equal(hasMatcher({ path_prefixes: [], methods: [] }), false);
  assert.equal(hasMatcher({ referer_regexes: ['^$'] }), true);
  assert.equal(hasMatcher({ scheme: 'https' }), true);
  assert.equal(hasMatcher({ headers: [{ name: 'X-A', equals: '1' }] }), true);
});

test('header changes follow the node rules', () => {
  const ok = (target, op, name, value) => headerOpProblem({ target, op, name, value });
  assert.equal(ok('response', 'set', 'X-Frame-Options', 'DENY'), null);
  assert.equal(ok('response', 'add', 'Link', '<x>'.replace(/[<>]/g, '')), null);
  assert.equal(ok('request', 'remove', 'X-Debug'), null);
  assert.equal(ok('request', 'remove', 'X-Forwarded-For'), null);
  assert.match(ok('request', 'set', 'X-Forwarded-For', '1.2.3.4'), /client identity/);
  assert.match(ok('request', 'add', 'CF-Connecting-IP', '1.2.3.4'), /client identity/);
  assert.equal(ok('response', 'set', 'X-Forwarded-For', 'x'), null);
  for (const name of ['Host', 'Content-Length', 'Transfer-Encoding', 'Connection', 'Upgrade', 'TE', 'Trailer', 'Expect', 'Proxy-Authorization', 'Sec-Fetch-Mode', 'X-Cite-Origin-Secret']) {
    assert.ok(ok('response', 'set', name, 'x'), name);
    assert.ok(ok('request', 'remove', name), name);
  }
  assert.ok(ok('response', 'set', '1bad', 'x'));
  assert.ok(ok('response', 'set', 'Bad Name', 'x'));
  assert.ok(ok('response', 'set', 'X-A', ''));
  assert.ok(ok('response', 'set', 'X-A', 'say "hi"'));
  assert.ok(ok('response', 'set', 'X-A', 'cost $5'));
  assert.ok(ok('response', 'set', 'X-A', 'back\\slash'));
  assert.ok(ok('response', 'set', 'X-A', 'a'.repeat(513)));
  assert.equal(ok('response', 'set', 'X-A', 'a'.repeat(512)), null);
  assert.match(ok('request', 'remove', 'X-Debug', 'v'), /no value/);
});

test('CORS is checked like the node does', () => {
  const base = { origins: ['https://app.example.com'], methods: ['GET'], allow_headers: ['Content-Type'], expose_headers: [], credentials: true, max_age_secs: 600 };
  assert.equal(corsProblem(base), null);
  assert.equal(corsProblem({ ...base, origins: ['*'], credentials: false }), null);
  assert.match(corsProblem({ ...base, origins: ['*'] }), /Credentials cannot be combined/);
  assert.match(corsProblem({ ...base, origins: ['*', 'https://a.example.com'], credentials: false }), /only origin/);
  assert.match(corsProblem({ ...base, origins: [] }), /1 to 32 origins/);
  assert.match(corsProblem({ ...base, origins: Array.from({ length: 33 }, (_, i) => `https://a${i}.example.com`) }), /1 to 32 origins/);
  for (const bad of ['app.example.com', 'https://app.example.com/path', 'ftp://a.example.com', 'https://*.example.com', 'https://a.example.com:0', 'https://a.example.com:99999', 'https://']) {
    assert.match(corsProblem({ ...base, origins: [bad] }), /Origin/, bad);
  }
  assert.equal(corsProblem({ ...base, origins: ['http://localhost:3000'] }), null);
  assert.match(corsProblem({ ...base, methods: ['get'] }), /uppercase/);
  assert.match(corsProblem({ ...base, allow_headers: ['bad name'] }), /Header name/);
  assert.match(corsProblem({ ...base, expose_headers: ['1x'] }), /Header name/);
  assert.match(corsProblem({ ...base, methods: Array.from({ length: 33 }, () => 'GET') }), /at most 32/);
  assert.equal(corsProblem({ ...base, max_age_secs: 86400 }), null);
  assert.match(corsProblem({ ...base, max_age_secs: 86401 }), /0 to 86400/);
  assert.match(corsProblem({ ...base, max_age_secs: -1 }), /0 to 86400/);
  assert.match(corsProblem({ ...base, max_age_secs: 1.5 }), /whole number/);
});

test('CORS text boxes split on whitespace and commas, with methods upper-cased', () => {
  const out = corsFromForm({ origins: 'https://a.example.com\nhttps://b.example.com', methods: 'get, post', allow_headers: 'X-A  X-B', expose_headers: '', credentials: true, max_age: ' 600 ' });
  assert.deepEqual(out, {
    origins: ['https://a.example.com', 'https://b.example.com'], methods: ['GET', 'POST'], allow_headers: ['X-A', 'X-B'], expose_headers: [], credentials: true, max_age_secs: 600,
  });
  assert.equal(corsFromForm({ ...out, origins: '', methods: '', allow_headers: '', expose_headers: '', max_age: '' }).max_age_secs, 0);
  assert.deepEqual(splitList(' a,b  c\n'), ['a', 'b', 'c']);
});

test('patterns follow the node limits', () => {
  assert.equal(patternProblem('^/api/', 'Pattern'), null);
  assert.equal(patternProblem('(?i)bot', 'Pattern'), null);
  for (const bad of ['', 'a b', 'a#b', 'a"b', "a'b", '-x', 'if', 'a\\\\b', 'a\\', 'a\\x41', 'a$HOME', '(', 'a'.repeat(257)]) {
    assert.ok(patternProblem(bad, 'Pattern'), JSON.stringify(bad));
  }
});

test('header matchers need exactly one test and keep secrets out of sight', () => {
  const eq = (over) => ({ name: 'X-Env', mode: 'equals', value: 'staging', negate: false, secret: false, stored: false, ...over });
  assert.equal(headerMatcherProblem(eq({})), null);
  assert.equal(headerMatcherProblem(eq({ name: '' })), null);
  assert.ok(headerMatcherProblem(eq({ name: '1x' })));
  assert.ok(headerMatcherProblem(eq({ value: '' })));
  assert.ok(headerMatcherProblem(eq({ value: 'has space' })));
  assert.ok(headerMatcherProblem(eq({ value: 'if' })));
  assert.ok(headerMatcherProblem(eq({ value: 'a'.repeat(257) })));
  assert.equal(headerMatcherProblem(eq({ secret: true, value: '', stored: true })), null);
  assert.ok(headerMatcherProblem(eq({ secret: true, value: '', stored: false })));
  assert.ok(headerMatcherProblem(eq({ secret: false, value: '', stored: true })));
  assert.equal(headerMatcherProblem(eq({ mode: 'regex', value: '^stag' })), null);
  assert.ok(headerMatcherProblem(eq({ mode: 'regex', value: '^stag', secret: true })));
  assert.ok(headerMatcherProblem(eq({ mode: 'regex', value: 'a b' })));
});

test('rule kinds follow the rule fields', () => {
  assert.equal(ruleKind({ action: 'deny' }), 'block');
  assert.equal(ruleKind({ redirect: { to: '/x', status: 301 } }), 'redirect');
  assert.equal(ruleKind({ headers: [{ target: 'response', op: 'set', name: 'X-A', value: 'v' }] }), 'headers');
  assert.equal(ruleKind({ cors: { origins: ['*'] } }), 'headers');
  assert.equal(ruleKind({ headers: [], action: 'deny' }), 'block');
});

test('the list shows the effect and never a secret value', () => {
  assert.deepEqual(effectView({ action: 'deny' }), { kind: 'block', pill: 'bad', label: 'Deny', detail: '' });
  assert.equal(effectView({ action: 'drop' }).label, 'Drop silently');
  assert.deepEqual(effectView({ redirect: { to: '/new', status: 308 } }), { kind: 'redirect', pill: 'info', label: 'Redirect 308', detail: '/new' });
  assert.equal(effectView({ headers: [{}, {}] }).detail, '2 header changes');
  assert.equal(effectView({ headers: [{}] }).detail, '1 header change');
  const both = effectView({ headers: [{}], cors: { origins: ['https://a.example.com'] } });
  assert.equal(both.detail, '1 header change, CORS for https://a.example.com');
  assert.equal(effectView({ cors: { origins: ['a', 'b'] } }).label, 'CORS');
  assert.equal(effectView({ cors: { origins: ['a', 'b'] } }).detail, 'CORS for 2 origins');
  const hidden = ['top', 'value'].join('-') + '-1'.repeat(3);
  const chips = matcherSummary({ scheme: 'http', referer_regexes: ['^$'], headers: [{ name: 'X-Key', equals: hidden, secret: true, negate: false }] });
  assert.deepEqual(chips, ['scheme http', 'referer ~ ^$', 'header X-Key = (secret)']);
  assert.ok(!chips.join(' ').includes(hidden));
  assert.deepEqual(matcherSummary({ headers: [{ name: 'X-Env', equals: 'staging', negate: true }] }), ['header X-Env not = staging']);
  assert.deepEqual(matcherSummary({ header: { name: 'X-A', regex: '^a', negate: false } }), ['header X-A ~ ^a']);
  assert.deepEqual(matcherSummary({ path_prefixes: ['/a', '/b'], cidrs: ['1.2.3.0/24', '1.2.4.0/24', '1.2.5.0/24'] }), ['prefix /a', 'prefix /b', '1.2.3.0/24, 1.2.4.0/24 +1']);
});

test('switching a rule on or off keeps a stored secret by sending it blank', () => {
  const rule = { id: 'r', name: 'n', enabled: true, action: 'deny', matchers: { header: { name: 'X-Key', equals: null, secret: true, negate: false } } };
  const body = resaveBody(rule, { enabled: false });
  assert.equal(body.enabled, false);
  assert.equal(body.matchers.header.equals, '');
  assert.equal(body.matchers.header.secret, true);
  assert.equal(rule.matchers.header.equals, null);
  const list = { ...rule, matchers: { headers: [{ name: 'X-Key', equals: null, secret: true }, { name: 'X-Env', equals: 'staging', secret: false }] } };
  const kept = resaveBody(list, { enabled: false }).matchers.headers;
  assert.equal(kept[0].equals, '');
  assert.equal(kept[1].equals, 'staging');
  const plain = { ...rule, matchers: { header: { name: 'X-Env', equals: 'staging', secret: false } } };
  assert.equal(resaveBody(plain, { enabled: false }).matchers.header.equals, 'staging');
  const viaRegex = { ...rule, matchers: { header: { name: 'X-Env', regex: '^a', equals: null, secret: false } } };
  assert.equal(resaveBody(viaRegex).matchers.header.equals, null);
  assert.equal(resaveBody({ ...rule, matchers: {} }).enabled, true);
});

test('redirect presets without a site warn about their reach', () => {
  assert.equal(presetNeedsScopeWarning({ rules: [{ redirect: { to: '/x', status: 301 }, site: null }] }), true);
  assert.equal(presetNeedsScopeWarning({ rules: [{ redirect: { to: '/x', status: 301 }, site: 'shop' }] }), false);
  assert.equal(presetNeedsScopeWarning({ rules: [{ action: 'deny' }] }), false);
  assert.equal(presetNeedsScopeWarning({}), false);
});
