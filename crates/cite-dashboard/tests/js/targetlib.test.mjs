import test from 'node:test';
import assert from 'node:assert/strict';
import {
  applyToNodes, canConfirm, confirmLabel, initialTargets, normalizeTargets, notTargeted, offlineTargets, resultKind, resultMessage,
  targetSummary, toggleTarget,
} from '../../web/js/targetlib.js';

const nodes = [
  { name: 'edge-fra', online: true },
  { name: 'edge-nyc', online: true },
  { name: 'edge-ams', online: false },
];

test('all nodes selects nothing, one node selects itself', () => {
  assert.deepEqual(initialTargets('all', nodes), []);
  assert.deepEqual(initialTargets(undefined, nodes), []);
  assert.deepEqual(initialTargets('edge-nyc', nodes), ['edge-nyc']);
  assert.deepEqual(initialTargets('gone', nodes), []);
});

test('toggle adds and removes a node', () => {
  assert.deepEqual(toggleTarget([], 'edge-fra'), ['edge-fra']);
  assert.deepEqual(toggleTarget(['edge-fra', 'edge-nyc'], 'edge-fra'), ['edge-nyc']);
});

test('a selection keeps node order and drops removed nodes', () => {
  assert.deepEqual(normalizeTargets(['edge-nyc', 'ghost', 'edge-fra'], nodes), ['edge-fra', 'edge-nyc']);
});

test('confirm needs at least one known node', () => {
  assert.equal(canConfirm([], nodes), false);
  assert.equal(canConfirm(['ghost'], nodes), false);
  assert.equal(canConfirm(['edge-fra'], nodes), true);
});

test('offline and untargeted nodes are listed', () => {
  assert.deepEqual(offlineTargets(['edge-fra', 'edge-ams'], nodes), ['edge-ams']);
  assert.deepEqual(notTargeted(['edge-nyc'], nodes), ['edge-fra', 'edge-ams']);
});

test('the summary and the confirm label name the nodes', () => {
  assert.equal(targetSummary([], nodes), 'No node selected');
  assert.equal(targetSummary(['edge-nyc'], nodes), 'edge-nyc');
  assert.equal(targetSummary(['edge-nyc', 'edge-fra'], nodes), '2 nodes: edge-fra, edge-nyc');
  assert.equal(confirmLabel('Turn on', ['edge-nyc'], nodes), 'Turn on for edge-nyc');
  assert.equal(confirmLabel('Turn on', ['edge-nyc', 'edge-fra'], nodes), 'Turn on for 2 nodes');
  assert.equal(confirmLabel('Turn on', [], nodes), 'Turn on');
});

test('applyToNodes reports each node and never throws', async () => {
  const seen = [];
  const results = await applyToNodes(['edge-fra', 'edge-nyc'], async (node) => {
    seen.push(node);
    if (node === 'edge-nyc') throw new Error('refused');
    return 7;
  });
  assert.deepEqual(seen.sort(), ['edge-fra', 'edge-nyc']);
  assert.equal(results[0].ok, true);
  assert.equal(results[0].value, 7);
  assert.equal(results[1].ok, false);
  assert.equal(resultMessage('Added', results), 'Added on edge-fra. Failed on edge-nyc: refused');
  assert.equal(resultKind(results), 'error');
  assert.equal(resultKind(results.slice(0, 1)), 'success');
});

test('a synchronous throw in fn is also captured', async () => {
  const results = await applyToNodes(['edge-fra'], () => {
    throw new Error('sync');
  });
  assert.equal(results[0].ok, false);
});
