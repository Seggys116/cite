import test from 'node:test';
import assert from 'node:assert/strict';
import {
  canRollback, commitOf, deployFailureText, deployRefFor, failureNote, historyRows, latestFailure, unhealthyTargets,
} from '../../web/js/historylib.js';

const d = (id, slot, action, note = '', extra = {}) => ({ id, at: '2026-11-06T10:00:00Z', slot, action, note, ...extra });
const history = [
  d('d1', 'blue', 'promote', 'Initial'),
  d('d2', 'green', 'promote', 'Release 2 abcdef1'),
  d('d3', 'blue', 'failed', 'build exited 1'),
];

test('commits come from the entry or from the note', () => {
  assert.equal(commitOf({ sha: 'ABCDEF1234' }), 'abcdef1234');
  assert.equal(commitOf({ note: 'Release 2 abcdef1' }), 'abcdef1');
  assert.equal(commitOf({ note: 'Deployed 0123456789abcdef0123456789abcdef01234567' }), '0123456789abcdef0123456789abcdef01234567');
  assert.equal(commitOf({ note: 'Fix deadbeef-ish' }), '');
  assert.equal(commitOf({ note: 'decade of changes' }), '');
  assert.equal(commitOf({ sha: 'not hex', note: '' }), '');
  assert.equal(commitOf(null), '');
});

test('rows are newest first with the live release marked', () => {
  const rows = historyRows(history, 'green');
  assert.deepEqual(rows.map((r) => r.id), ['d3', 'd2', 'd1']);
  assert.deepEqual(rows.map((r) => r.current), [false, true, false]);
  assert.equal(rows[0].failed, true);
  assert.equal(rows[1].commit, 'abcdef1');
  assert.deepEqual(historyRows(null, 'blue'), []);
});

test('each row offers the actions that make sense', () => {
  const rows = historyRows(history, 'green');
  const [failed, live, first] = rows;
  assert.equal(failed.canRedeploy, true);
  assert.equal(failed.canDeployCommit, false);
  assert.equal(live.canRedeploy, true);
  assert.equal(live.canDeployCommit, false);
  assert.equal(first.canRedeploy, false);
  const older = historyRows([d('a', 'blue', 'promote', 'built 1234567'), d('b', 'green', 'promote', 'built 7654321')], 'green');
  assert.equal(older[1].canDeployCommit, true);
  assert.equal(older[0].canDeployCommit, false);
});

test('rollback needs an earlier release on the other slot', () => {
  assert.equal(canRollback(history, 'green'), true);
  assert.equal(canRollback([d('a', 'blue', 'promote')], 'blue'), false);
  assert.equal(canRollback([d('a', 'blue', 'promote'), d('b', 'blue', 'promote')], 'blue'), false);
  assert.equal(canRollback([d('a', 'blue', 'failed'), d('b', 'green', 'failed')], 'green'), false);
  assert.equal(canRollback(null, 'blue'), false);
});

test('a deploy ref is the commit, then the stored ref, then the branch', () => {
  assert.equal(deployRefFor({ commit: 'abc1234' }, { branch: 'dev' }), 'abc1234');
  assert.equal(deployRefFor({ commit: '', ref: 'v2' }, { branch: 'dev' }), 'v2');
  assert.equal(deployRefFor({}, { branch: 'dev' }), 'dev');
  assert.equal(deployRefFor({}, null), 'main');
});

test('a failure counts until a later success', () => {
  assert.equal(latestFailure(history).id, 'd3');
  assert.equal(latestFailure([...history, d('d4', 'blue', 'promote')]), null);
  assert.equal(latestFailure([]), null);
  assert.equal(latestFailure(undefined), null);
});

test('the list note names the failure or the unhealthy targets', () => {
  assert.equal(failureNote({ history }), 'Last deploy failed: build exited 1');
  assert.equal(failureNote({ history: [d('x', 'blue', 'failed')] }), 'Last deploy failed.');
  const site = { active: 'blue', history: [d('a', 'blue', 'promote')], live: { blue: [{ addr: '10.0.0.1:80', status: 'UP' }, { addr: '10.0.0.2:80', status: 'DOWN' }] } };
  assert.deepEqual(unhealthyTargets(site).map((t) => t.addr), ['10.0.0.2:80']);
  assert.equal(failureNote(site), 'A target is not passing the health check: 10.0.0.2:80');
  site.live.blue.push({ addr: '10.0.0.3:80', status: 'DOWN' });
  assert.match(failureNote(site), /^2 targets are not passing/);
  assert.equal(failureNote({ active: 'blue', history: [], live: { blue: [{ addr: 'a:1', status: 'UP' }] } }), '');
  assert.equal(failureNote(null), '');
});

test('the deploy toast carries the whole node message', () => {
  const long = 'build failed: '.concat('x'.repeat(400));
  assert.equal(deployFailureText({ message: long }), `Deploy failed: ${long}`);
  assert.equal(deployFailureText({ message: '  ' }), 'The deploy failed.');
  assert.equal(deployFailureText(null, 'custom'), 'custom');
});
