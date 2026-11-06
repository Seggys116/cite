import test from 'node:test';
import assert from 'node:assert/strict';
import {
  addProblem, buildPatch, emptyPending, envNameProblem, envValueProblem, pendingCount, pendingSummary,
} from '../../web/js/envlib.js';
import {
  canUseNodeToken, nodeTokenNote, tokenHealth, tokenInputProblem, tokenSourceText,
} from '../../web/js/tokenlib.js';

const pending = (set = [], unset = []) => ({ set: new Map(set), unset: new Set(unset) });

test('variable names follow the node rule', () => {
  for (const ok of ['API_URL', '_X', 'A', 'VITE_PUBLIC_KEY_2', 'A'.repeat(64)]) assert.equal(envNameProblem(ok), null, ok);
  for (const bad of ['', 'api_url', '1X', 'A-B', 'A B', 'A'.repeat(65), 'Ä']) assert.ok(envNameProblem(bad), bad);
});

test('names the node keeps for itself are refused', () => {
  for (const name of ['PATH', 'HOME', 'NODE_OPTIONS', 'LD_PRELOAD', 'GIT_DIR', 'CITE_TOKEN', 'NPM_CONFIG_REGISTRY', 'XDG_CACHE_HOME', 'HTTPS_PROXY']) {
    assert.match(envNameProblem(name), /reserved/, name);
  }
  assert.equal(envNameProblem('PATHS'), null);
  assert.equal(envNameProblem('MY_GIT_URL'), null);
});

test('build and runtime variables refuse different names', () => {
  for (const name of ['SHELL', 'BASH_ENV', 'NODE_PATH', 'TMP', 'CARGO_HOME', 'LD_X', 'DYLD_X', 'COREPACK_HOME', 'YARN_CACHE_FOLDER', 'REQUESTS_CA_BUNDLE', 'HOSTNAME']) {
    assert.match(envNameProblem(name, 'build'), /reserved/, name);
    assert.match(envNameProblem(name), /reserved/, name);
  }
  for (const name of ['SHELL', 'BASH_ENV', 'NODE_PATH', 'TMP', 'CARGO_HOME', 'LD_X', 'DYLD_X']) assert.equal(envNameProblem(name, 'runtime'), null, name);
  for (const name of ['PORT', 'NODE_ENV', 'HOST', 'HOSTNAME', 'NITRO_HOST']) assert.match(envNameProblem(name, 'runtime'), /reserved/, name);
  for (const name of ['PORT', 'NODE_ENV', 'HOST', 'NITRO_HOST']) assert.equal(envNameProblem(name, 'build'), null, name);
  for (const name of ['PATH', 'LD_PRELOAD', 'CITE_X', 'GIT_DIR', 'NPM_CONFIG_REGISTRY']) assert.match(envNameProblem(name, 'runtime'), /reserved/, name);
  assert.match(buildPatch(pending([['NODE_ENV', 'x']]), [], 'runtime').problem, /reserved/);
  assert.equal(buildPatch(pending([['NODE_ENV', 'x']]), [], 'build').problem, undefined);
  assert.match(addProblem('PORT', 'x', [], [], 'runtime'), /reserved/);
  assert.equal(addProblem('SHELL', 'x', [], [], 'runtime'), null);
});

test('values are one line and at most 4096 bytes', () => {
  assert.equal(envValueProblem('https://api.example.com'), null);
  assert.equal(envValueProblem(''), null);
  assert.equal(envValueProblem('x'.repeat(4096)), null);
  assert.ok(envValueProblem('x'.repeat(4097)));
  assert.ok(envValueProblem('é'.repeat(2049)));
  assert.ok(envValueProblem('a\nb'));
  assert.ok(envValueProblem('a\u0000b'));
});

test('a patch carries values to set and names to remove', () => {
  const r = buildPatch(pending([['API_URL', 'https://x.example']], ['OLD']), ['OLD', 'KEEP']);
  assert.deepEqual(r, { patch: { set: { API_URL: 'https://x.example' }, unset: ['OLD'] } });
  assert.match(buildPatch(pending(), []).problem, /Nothing/);
  assert.match(buildPatch(pending([['bad', 'x']]), []).problem, /^bad:/);
  assert.match(buildPatch(pending([['PATH', 'x']]), []).problem, /reserved/);
  assert.match(buildPatch(pending([['A', 'x']], ['A']), []).problem, /both replaced and removed/);
  assert.match(buildPatch(pending([], ['bad name']), []).problem, /not valid/);
});

test('the limits on count and size are checked before sending', () => {
  const many = Array.from({ length: 129 }, (_, i) => [`V${i}`, '1']);
  assert.match(buildPatch(pending(many), []).problem, /at most 128/);
  const existing = Array.from({ length: 128 }, (_, i) => `E${i}`);
  assert.match(buildPatch(pending([['NEW', '1']]), existing).problem, /holds at most 128/);
  assert.equal(buildPatch(pending([['NEW', '1']], ['E0']), existing).problem, undefined);
  assert.equal(buildPatch(pending([['E0', '2']]), existing).problem, undefined);
  const big = Array.from({ length: 7 }, (_, i) => [`B${i}`, 'x'.repeat(4000)]);
  assert.match(buildPatch(pending(big), []).problem, /24 KiB/);
});

test('a new row needs a free name and a value', () => {
  assert.equal(addProblem('API_URL', 'x', ['OTHER']), null);
  assert.match(addProblem('', 'x', []), /Enter a variable name/);
  assert.match(addProblem('api', 'x', []), /capital letters/);
  assert.match(addProblem('API_URL', 'x', ['API_URL']), /already in the list/);
  assert.match(addProblem('API_URL', 'x', [], ['API_URL']), /already in the list/);
  assert.match(addProblem('API_URL', '', []), /Enter a value/);
  assert.match(addProblem('API_URL', 'a\nb', []), /one line/);
});

test('pending changes are counted and described', () => {
  const p = pending([['A', '1'], ['B', '2']], ['C']);
  assert.equal(pendingCount(p), 3);
  assert.equal(pendingSummary(p), '2 to set, 1 to remove');
  assert.equal(pendingSummary(emptyPending()), 'No changes');
  assert.equal(pendingSummary(pending([], ['C'])), '1 to remove');
});

test('a typed token is checked without being echoed', () => {
  const t = ['ghp', '_', 'abc123'].join('');
  assert.equal(tokenInputProblem(`  ${t}  `), null);
  assert.equal(tokenInputProblem(''), 'Enter the token.');
  assert.equal(tokenInputProblem('   '), 'Enter the token.');
  assert.ok(!tokenInputProblem('has space inside').includes('space inside'));
  assert.ok(tokenInputProblem('has space inside'));
  assert.ok(tokenInputProblem('tab\there'));
  assert.ok(tokenInputProblem('é'));
  assert.ok(tokenInputProblem('a'.repeat(513)));
  assert.equal(tokenInputProblem('a'.repeat(512)), null);
});

test('the token card says where the token in use comes from', () => {
  assert.match(tokenSourceText({ source: 'site' }), /its own token/);
  assert.match(tokenSourceText({ source: 'node' }), /node token/);
  assert.match(tokenSourceText({ source: 'none' }), /No token is set/);
  assert.match(tokenSourceText({}), /No token is set/);
  assert.match(tokenSourceText(null), /No token is set/);
  assert.match(tokenSourceText({ site_token_set: true }), /its own token/);
});

test('token health separates rejected, verified and unknown', () => {
  assert.equal(tokenHealth({ verified: false }).kind, 'bad');
  assert.match(tokenHealth({ status: 'invalid token' }).text, /rejected the token: invalid token/);
  assert.equal(tokenHealth({ verified: true }).kind, 'ok');
  assert.match(tokenHealth({ verified: true, expires_at: '2027-01-01' }).text, /Expires 2027-01-01/);
  assert.deepEqual(tokenHealth({ status: 'unchecked' }), { kind: 'muted', text: 'unchecked' });
  assert.deepEqual(tokenHealth(null), { kind: 'muted', text: '' });
});

test('falling back to the node token only makes sense with a site token', () => {
  assert.equal(canUseNodeToken({ site_token_set: true }), true);
  assert.equal(canUseNodeToken({ site_token_set: false }), false);
  assert.equal(canUseNodeToken(null), false);
  assert.match(nodeTokenNote({ node_token_configured: false }), /no token of its own/);
  assert.equal(nodeTokenNote({ node_token_configured: true }), '');
  assert.equal(nodeTokenNote(null), '');
});
