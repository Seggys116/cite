import test from 'node:test';
import assert from 'node:assert/strict';
import {
  siteProblem, repoProblem, branchProblem, runtimeProblem, pollProblem, gitRefProblem, cleanToken,
} from '../../web/js/siteCheck.js';

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
  for (const bad of ['', 'acme', 'a/b/c', '/b', 'a/', '.a/b', 'a/..', 'a/.hidden', 'a b/c', 'https://github.com/a/b']) {
    assert.match(repoProblem(bad), /owner\/name/, bad);
  }
});

test('branch, runtime and poll interval are checked', () => {
  assert.equal(branchProblem('release/1.2'), null);
  assert.ok(branchProblem(''));
  assert.ok(branchProblem('/x'));
  assert.ok(branchProblem('a..b'));
  assert.ok(branchProblem('a b'));
  assert.equal(runtimeProblem('bun'), null);
  assert.ok(runtimeProblem('python'));
  for (const ok of ['30s', '5m', '1h']) assert.equal(pollProblem(ok), null);
  for (const bad of ['', '5', 'm', '5 m', '5d', '-5m']) assert.ok(pollProblem(bad), bad);
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
