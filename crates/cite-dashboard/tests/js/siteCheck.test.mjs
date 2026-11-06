import test from 'node:test';
import assert from 'node:assert/strict';
import {
  siteProblem, repoProblem, branchProblem, runtimeProblem, pollProblem, gitRefProblem, cleanToken,
  TOKEN_HELP_HAVE, TOKEN_HELP_NONE, TOKEN_TOGGLE, tokenPlan, tokenProblem, tokenState,
} from '../../web/js/siteCheck.js';

test('a node reports whether it already holds a GitHub token', () => {
  assert.equal(tokenState({ github: { token_configured: true, source: 'env' } }), 'yes');
  assert.equal(tokenState({ github: { token_configured: false, source: 'none' } }), 'no');
  assert.equal(tokenState({}), 'unknown');
  assert.equal(tokenState(null), 'unknown');
});

test('the token field is hidden when every selected node has a token', () => {
  const one = tokenPlan(['yes']);
  assert.deepEqual([one.show, one.required], [false, false]);
  assert.equal(one.help, 'This node already has a GitHub token (CITE_GITHUB_TOKEN). Leave this empty to use it.');
  assert.equal(one.help, TOKEN_HELP_HAVE);
  assert.equal(TOKEN_TOGGLE, 'Use a different token for this site');
  const all = tokenPlan(['yes', 'yes']);
  assert.equal(all.show, false);
  assert.match(all.help, /Every selected node/);
});

test('a node without a token makes the field visible and required', () => {
  const none = tokenPlan(['no']);
  assert.deepEqual([none.show, none.required], [true, true]);
  assert.equal(none.help, TOKEN_HELP_NONE);
  assert.match(none.help, /Contents: read/);
  assert.match(none.help, /CITE_GITHUB_TOKEN/);
  const mixed = tokenPlan(['yes', 'no', 'yes']);
  assert.deepEqual([mixed.show, mixed.required], [true, true]);
});

test('an unknown node never forces a token but still offers the field', () => {
  for (const states of [[], ['unknown'], ['yes', 'unknown']]) {
    const plan = tokenPlan(states);
    assert.deepEqual([plan.show, plan.required], [true, false], JSON.stringify(states));
  }
  assert.deepEqual(tokenPlan(undefined).required, false);
});

test('a required token must not be blank', () => {
  const required = tokenPlan(['no']);
  assert.match(tokenProblem(required, ''), /GitHub token/);
  assert.match(tokenProblem(required, '   '), /GitHub token/);
  assert.equal(tokenProblem(required, 'abc'), null);
  assert.equal(tokenProblem(tokenPlan(['yes']), ''), null);
});

const valid = {
  name: 'App', id: 'app', hostCount: 1, pathError: null, targetProblem: null, blueCount: 1, healthPath: '/', pickNodes: true, nodePicked: true,
};

test('a complete form has no problem so it can be submitted', () => {
  assert.equal(siteProblem(valid), null);
});

test('each missing or invalid field is reported', () => {
  assert.match(siteProblem({ ...valid, name: ' ' }), /name/);
  assert.match(siteProblem({ ...valid, id: 'Bad Id' }), /site id/);
  assert.match(siteProblem({ ...valid, hostCount: 0 }), /host/);
  assert.match(siteProblem({ ...valid, pathError: 'bad' }), /regex/);
  assert.equal(siteProblem({ ...valid, targetProblem: 'x is not a host:port address.' }), 'x is not a host:port address.');
  assert.match(siteProblem({ ...valid, blueCount: 0 }), /blue target/);
  assert.match(siteProblem({ ...valid, healthPath: 'health' }), /health check/);
});

test('node selection only matters when placing on chosen nodes', () => {
  assert.match(siteProblem({ ...valid, nodePicked: false }), /node/);
  assert.equal(siteProblem({ ...valid, pickNodes: false, nodePicked: false }), null);
});

const src = { repo: 'acme/shop', branch: 'main', runtime: 'node', poll: '5m' };

test('repository must be owner/name with allowed characters', () => {
  assert.equal(repoProblem('acme/shop'), null);
  assert.equal(repoProblem(' a.b/c_d-e '), null);
  for (const bad of ['', 'acme', 'a/b/c', '/b', 'a/', '.a/b', 'a/..', 'a/.hidden', 'a b/c']) {
    assert.match(repoProblem(bad), /owner\/name/, bad);
  }
  assert.equal(repoProblem('https://github.com/a/b'), null);
  assert.equal(repoProblem('git@github.com:a/b.git'), null);
});

test('branch, runtime and poll interval are checked', () => {
  assert.equal(branchProblem('release/1.2'), null);
  assert.ok(branchProblem(''));
  assert.ok(branchProblem('/x'));
  assert.ok(branchProblem('a..b'));
  assert.ok(branchProblem('a b'));
  assert.equal(runtimeProblem('bun'), null);
  assert.ok(runtimeProblem('python'));
  for (const ok of ['60s', '5m', '1h', '5d', 'off', '0', '366d']) assert.equal(pollProblem(ok), null, ok);
  for (const bad of ['', '5', 'm', '5 m', '30s', '-5m', '367d', '5w']) assert.ok(pollProblem(bad), bad);
});

test('git refs follow the deploy endpoint rule', () => {
  for (const ok of ['main', 'v1.2.3', 'feature/x_y', 'a'.repeat(100), '0123abcd']) assert.equal(gitRefProblem(ok), null, ok);
  for (const bad of ['', '  ', '-x', 'a..b', 'a b', 'a;b', 'a'.repeat(101)]) assert.ok(gitRefProblem(bad), bad);
});

test('a token is trimmed and a blank one is dropped', () => {
  assert.equal(cleanToken('  ghp_x \n'), 'ghp_x');
  assert.equal(cleanToken('   '), undefined);
  assert.equal(cleanToken(undefined), undefined);
});

test('github mode checks the source and ignores targets', () => {
  const gh = { ...valid, mode: 'github', source: src, blueCount: 0, targetProblem: 'ignored' };
  assert.equal(siteProblem(gh), null);
  assert.match(siteProblem({ ...gh, source: { ...src, repo: 'nope' } }), /owner\/name/);
  assert.match(siteProblem({ ...gh, source: { ...src, poll: 'x' } }), /poll/);
  assert.match(siteProblem({ ...gh, source: { ...src, runtime: 'x' } }), /node, bun/);
});

test('existing upstream mode still requires targets', () => {
  const up = { ...valid, mode: 'upstreams', source: src };
  assert.equal(siteProblem(up), null);
  assert.match(siteProblem({ ...up, blueCount: 0 }), /blue target/);
  assert.equal(siteProblem({ ...up, targetProblem: 'bad addr' }), 'bad addr');
});
