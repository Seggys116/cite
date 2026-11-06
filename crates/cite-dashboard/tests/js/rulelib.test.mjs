import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildRule, corsFromForm, corsProblem, effectView, emptyForm, headerMatcherProblem, headerOpProblem, matcherSummary, parseTemplate,
  patternProblem, presetNeedsScopeWarning, redirectProblem, resaveBody, ruleKind, ruleToForm, splitList,
} from '../../web/js/rulelib.js';

const form = (over = {}) => ({ ...emptyForm(), name: 'Rule', id: 'r1', ...over });
const withMatchers = (over) => ({ ...emptyForm().matchers, ...over });

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
  assert.match(redirectProblem(to('https://{host}{path}{query}'), {}), /scheme matcher set to http/);
  assert.match(redirectProblem(to('/new'), {}), /path prefix or path regex/);
  assert.equal(redirectProblem(to('/new'), { path_prefix: '/old' }), null);
  assert.match(redirectProblem(to('/old/new'), { path_prefix: '/old' }), /would loop/);
  assert.match(redirectProblem(to('https://other.example.org/'), {}), /Add a matcher/);
  assert.equal(redirectProblem(to('https://other.example.org/'), { host: 'a.example.com' }), null);
  assert.match(redirectProblem(to('/x', 303), { path_prefix: '/a' }), /301, 302, 307 or 308/);
  for (const status of [301, 302, 307, 308]) assert.equal(redirectProblem(to('/new', status), { path_regex: '^/old' }), null);
  assert.match(redirectProblem(to('javascript:alert(1)'), { host: 'a.com' }), /redirect target/);
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

test('a block rule keeps the old body shape and needs a matcher', () => {
  const built = buildRule(form({ matchers: withMatchers({ path_prefix: '/admin' }) }));
  assert.deepEqual(built.rule, {
    id: 'r1', name: 'Rule', enabled: true, action: 'deny', site: null,
    matchers: { path_regex: null, path_prefix: '/admin', methods: [], user_agent_regex: null, cidrs: [], host: null },
  });
  assert.match(buildRule(form()).error, /at least one matcher/);
  assert.match(buildRule(form({ name: '  ' })).error, /name/);
  assert.match(buildRule(form({ label: 'Bad Label', matchers: withMatchers({ host: 'a.com' }) })).error, /label/);
  const labelled = buildRule(form({ label: 'my-label', site: 'shop', action: 'tarpit', matchers: withMatchers({ host: 'a.com' }) })).rule;
  assert.equal(labelled.label, 'my-label');
  assert.equal(labelled.site, 'shop');
  assert.equal(labelled.action, 'tarpit');
});

test('new matchers appear only when set', () => {
  const rule = buildRule(form({ matchers: withMatchers({ scheme: 'http', referer_regex: '^$' }) })).rule;
  assert.equal(rule.matchers.scheme, 'http');
  assert.equal(rule.matchers.referer_regex, '^$');
  assert.equal('header' in rule.matchers, false);
  assert.match(buildRule(form({ matchers: withMatchers({ scheme: 'ftp' }) })).error, /http or https/);
  assert.match(buildRule(form({ matchers: withMatchers({ referer_regex: 'a b' }) })).error, /referer/);
  const header = { name: ' X-Key ', mode: 'equals', value: 'abc123', negate: true, secret: true, stored: false };
  const built = buildRule(form({ matchers: withMatchers({ header }) })).rule;
  assert.deepEqual(built.matchers.header, { name: 'X-Key', regex: null, equals: 'abc123', negate: true, secret: true });
});

test('a stored secret is kept by sending a blank value and is never loaded into the form', () => {
  const stored = {
    id: 'r2', name: 'Key', enabled: true, action: 'deny', site: null,
    matchers: { header: { name: 'X-Key', regex: null, equals: '', negate: true, secret: true } },
  };
  const f = ruleToForm(stored);
  assert.equal(f.matchers.header.value, '');
  assert.equal(f.matchers.header.secret, true);
  assert.equal(f.matchers.header.stored, true);
  const again = buildRule(f).rule;
  assert.deepEqual(again.matchers.header, { name: 'X-Key', regex: null, equals: '', negate: true, secret: true });
  f.matchers.header.value = 'newvalue';
  assert.equal(buildRule(f).rule.matchers.header.equals, 'newvalue');
  const plain = ruleToForm({ ...stored, matchers: { header: { name: 'X-Env', equals: 'staging', negate: false, secret: false } } });
  assert.equal(plain.matchers.header.value, 'staging');
  assert.equal(plain.matchers.header.stored, false);
});

test('a redirect rule carries redirect and no action', () => {
  const f = form({ kind: 'redirect', redirect: { to: '{scheme}://{www_host}{path}{query}', status: '302' } });
  const { rule } = buildRule(f);
  assert.deepEqual(rule.redirect, { to: '{scheme}://{www_host}{path}{query}', status: 302 });
  assert.equal('action' in rule, false);
  assert.match(buildRule(form({ kind: 'redirect', redirect: { to: '/new', status: 301 } })).error, /path prefix/);
  assert.match(buildRule(form({ kind: 'redirect', redirect: { to: '', status: 301 }, matchers: withMatchers({ host: 'a.com' }) })).error, /redirect target/);
});

test('a header rule carries headers and cors and needs at least one', () => {
  assert.match(buildRule(form({ kind: 'headers' })).error, /at least one header change/);
  const ops = [{ target: 'response', op: 'set', name: 'X-Frame-Options', value: 'DENY' }, { target: 'request', op: 'remove', name: 'X-Debug', value: 'ignored' }];
  const { rule } = buildRule(form({ kind: 'headers', headers: ops }));
  assert.deepEqual(rule.headers, [
    { target: 'response', op: 'set', name: 'X-Frame-Options', value: 'DENY' },
    { target: 'request', op: 'remove', name: 'X-Debug' },
  ]);
  assert.equal('cors' in rule, false);
  assert.equal('action' in rule, false);
  const cors = { enabled: true, origins: 'https://app.example.com', methods: 'GET POST', allow_headers: '', expose_headers: '', credentials: true, max_age: '600' };
  const onlyCors = buildRule(form({ kind: 'headers', cors })).rule;
  assert.equal(onlyCors.cors.max_age_secs, 600);
  assert.equal('headers' in onlyCors, false);
  assert.match(buildRule(form({ kind: 'headers', cors: { ...cors, origins: '*' } })).error, /Credentials/);
  assert.match(buildRule(form({ kind: 'headers', headers: [{ target: 'request', op: 'set', name: 'Host', value: 'x' }] })).error, /Host/);
  const many = Array.from({ length: 17 }, () => ({ target: 'response', op: 'set', name: 'X-A', value: 'v' }));
  assert.match(buildRule(form({ kind: 'headers', headers: many })).error, /at most 16/);
});

test('rules load back into the form by kind', () => {
  assert.equal(ruleKind({ action: 'deny' }), 'block');
  assert.equal(ruleKind({ redirect: { to: '/x', status: 301 } }), 'redirect');
  assert.equal(ruleKind({ headers: [{ target: 'response', op: 'set', name: 'X-A', value: 'v' }] }), 'headers');
  assert.equal(ruleKind({ cors: { origins: ['*'] } }), 'headers');
  assert.equal(ruleKind({ headers: [] , action: 'deny' }), 'block');
  const f = ruleToForm({
    id: 'c', name: 'Cors', enabled: false, site: 'api', label: 'cors-app', matchers: {},
    cors: { origins: ['https://a.example.com', 'https://b.example.com'], methods: ['GET'], allow_headers: ['X-A'], expose_headers: [], credentials: true, max_age_secs: 600 },
  });
  assert.equal(f.kind, 'headers');
  assert.equal(f.cors.enabled, true);
  assert.equal(f.cors.origins, 'https://a.example.com\nhttps://b.example.com');
  assert.equal(f.cors.max_age, '600');
  assert.equal(f.enabled, false);
  assert.equal(f.label, 'cors-app');
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
  const chips = matcherSummary({ scheme: 'http', referer_regex: '^$', header: { name: 'X-Key', equals: hidden, secret: true, negate: false } });
  assert.deepEqual(chips, ['scheme http', 'referer ~ ^$', 'header X-Key = (secret)']);
  assert.ok(!chips.join(' ').includes(hidden));
  assert.deepEqual(matcherSummary({ header: { name: 'X-Env', equals: 'staging', negate: true } }), ['header X-Env not = staging']);
  assert.deepEqual(matcherSummary({ header: { name: 'X-A', regex: '^a', negate: false } }), ['header X-A ~ ^a']);
});

test('switching a rule on or off keeps a stored secret by sending it blank', () => {
  const rule = { id: 'r', name: 'n', enabled: true, action: 'deny', matchers: { header: { name: 'X-Key', equals: null, secret: true, negate: false } } };
  const body = resaveBody(rule, { enabled: false });
  assert.equal(body.enabled, false);
  assert.equal(body.matchers.header.equals, '');
  assert.equal(body.matchers.header.secret, true);
  assert.equal(rule.matchers.header.equals, null);
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
