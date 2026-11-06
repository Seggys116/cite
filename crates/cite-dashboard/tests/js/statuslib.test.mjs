import test from 'node:test';
import assert from 'node:assert/strict';
import {
  detectedOf, errorText, healthTone, pendingChanges, pendingLabel, phaseOf, phaseView, pollDelay, shortSha, showsBanner, slotRows, unsupported,
} from '../../web/js/statuslib.js';

const slot = (over = {}) => ({ slot: 'blue', container: 'site-blue', health: 'healthy', restart_count: 0, ...over });
const status = (over = {}) => ({ phase: 'idle', active: 'blue', slots: [slot()], settings_current: true, ...over });

test('each phase has a chip and only the working phases are busy', () => {
  for (const [phase, busy] of [['fetching', true], ['building', true], ['packing', true], ['promoting', true], ['idle', false], ['failed', false]]) {
    const v = phaseView(status({ phase }));
    assert.equal(v.phase, phase);
    assert.equal(v.busy, busy, phase);
  }
  assert.equal(phaseView(status({ phase: 'failed' })).kind, 'bad');
  assert.equal(phaseView(status({ phase: 'idle' })).kind, 'ok');
  assert.equal(phaseView(status({ phase: 'BUILDING' })).phase, 'building');
});

test('an idle site whose live slot is down shows as unhealthy', () => {
  assert.equal(phaseOf(status({ slots: [slot({ health: 'unhealthy' })] })), 'unhealthy');
  assert.equal(phaseOf(status({ slots: [slot({ haproxy_check: 'L4CON' })] })), 'idle');
  assert.equal(phaseOf(status({ slots: [slot({ haproxy_check: 'DOWN' })] })), 'unhealthy');
  assert.equal(phaseOf(status({ slots: [slot({ slot: 'green', health: 'unhealthy' })] })), 'idle');
  assert.equal(phaseOf(status({ phase: 'building', slots: [slot({ health: 'unhealthy' })] })), 'building');
});

test('unknown or missing phases fall back sensibly', () => {
  assert.equal(phaseOf(null), 'idle');
  assert.equal(phaseOf({}), 'idle');
  assert.equal(phaseOf({ phase: 'weird' }), 'idle');
  assert.equal(phaseOf({ phase: '', error: 'boom' }), 'failed');
});

test('the operation is described while the manager works', () => {
  const v = phaseView(status({ phase: 'building', operation: { kind: 'deploy', slot: 'green', step: 'npm ci' } }));
  assert.equal(v.detail, 'deploy, slot green, npm ci');
  assert.equal(phaseView(status({ operation: { kind: 'deploy' } })).detail, '');
});

test('the failure reason is the most specific message the node gave', () => {
  assert.equal(errorText(status({ phase: 'failed', error: ' build exited 1 ' })), 'build exited 1');
  assert.equal(errorText(status({ phase: 'failed', last_failure: { note: 'token rejected' } })), 'token rejected');
  const report = { last_error: 'repository not found', deploy: { result: 'failed', reason: 'other' } };
  assert.equal(errorText(status({ phase: 'failed', slots: [slot({ report })] })), 'repository not found');
  const deploy = { deploy: { result: 'failed', reason: 'health check timed out' } };
  assert.equal(errorText(status({ phase: 'failed', slots: [slot({ report: deploy })] })), 'health check timed out');
  assert.match(errorText(status({ phase: 'failed' })), /no reason/);
  assert.match(errorText(status({ slots: [slot({ health: 'unhealthy' })] })), /blue slot is not passing/);
  assert.equal(errorText(status()), '');
  assert.equal(errorText(null), '');
});

test('the banner shows for failures and unhealthy sites only', () => {
  assert.equal(showsBanner(status({ phase: 'failed' })), true);
  assert.equal(showsBanner(status({ slots: [slot({ health: 'unhealthy' })] })), true);
  assert.equal(showsBanner(status({ phase: 'building' })), false);
  assert.equal(showsBanner(status()), false);
  assert.equal(showsBanner(status({ error: 'x' })), true);
});

test('pending changes follow settings_current', () => {
  assert.equal(pendingChanges(status({ settings_current: false })), true);
  assert.equal(pendingChanges(status()), false);
  assert.equal(pendingChanges({}), false);
  assert.equal(pendingChanges(null), false);
  assert.equal(pendingLabel(status({ settings_current: false })), 'Changes not built yet');
  assert.equal(pendingLabel(status()), '');
});

test('slot rows are ready to draw', () => {
  const rows = slotRows(status({
    slots: [
      slot({ report: { phase: 'idle', head_sha: 'abcdef0123456789', live_sha: '1234567890abcdef', last_build_secs: 75, last_error: 'old' } }),
      slot({ slot: 'green', health: 'unhealthy', restart_count: 3, exit_code: 137, oom_killed: true }),
    ],
  }));
  assert.equal(rows.length, 2);
  assert.deepEqual([rows[0].active, rows[0].head, rows[0].live, rows[0].lastBuild, rows[0].tone], [true, 'abcdef0', '1234567', '1m 15s', 'ok']);
  assert.deepEqual([rows[1].active, rows[1].tone, rows[1].restarts, rows[1].exitCode, rows[1].oom], [false, 'bad', 3, 137, true]);
  assert.deepEqual(slotRows(null), []);
  assert.equal(slotRows(status({ slots: [slot({ report: { last_build_secs: 9 } })] }))[0].lastBuild, '9s');
});

test('health words map to tones', () => {
  for (const [word, tone] of [['healthy', 'ok'], ['running', 'ok'], ['UP', 'ok'], ['unhealthy', 'bad'], ['exited', 'bad'], ['restarting', 'bad'], ['starting', 'muted'], ['', 'muted'], [undefined, 'muted']]) {
    assert.equal(healthTone(word), tone, String(word));
  }
});

test('detected settings come from the live slot first', () => {
  const s = status({
    slots: [slot({ slot: 'green', report: { detected: { output_dir: 'out' } } }), slot({ report: { detected: { output_dir: 'dist' } } })],
  });
  assert.equal(detectedOf(s).output_dir, 'dist');
  assert.equal(detectedOf(status({ slots: [slot({ slot: 'green', report: { detected: { a: 1 } } }), slot()] })).a, 1);
  assert.equal(detectedOf(status()), null);
  assert.equal(detectedOf(null), null);
});

test('polling is quick only while the manager works', () => {
  assert.equal(pollDelay(status({ phase: 'building' })), 2000);
  assert.equal(pollDelay(status()), 10000);
  assert.equal(pollDelay(null), 10000);
});

test('shas are shortened and old nodes are recognised', () => {
  assert.equal(shortSha('0123456789abcdef'), '0123456');
  assert.equal(shortSha(null), '');
  assert.equal(unsupported({ status: 404 }), true);
  assert.equal(unsupported({ status: 501 }), true);
  assert.equal(unsupported({ status: 500 }), false);
  assert.equal(unsupported(null), false);
});
