import test from 'node:test';
import assert from 'node:assert/strict';
import {
  bulkBodyFor, enabledDiffers, enabledEverywhere, hitsForRule, mergePresets, mergeRules, mergeSites, presetBlurb, presetRulesModel, rowHits, ruleContentKey,
  unreachableNote, writableNodes,
} from '../../web/js/firewalllib.js';

const wp = (extra = {}) => ({ id: 'r-wp', name: 'WordPress probes', enabled: true, action: 'deny', matchers: { path_regexes: ['^/wp-login'] }, site: null, ...extra });

test('identical rules on two nodes merge into one row with both holders', () => {
  const rows = mergeRules([
    { node: 'edge-fra', rules: [wp()] },
    { node: 'edge-nyc', rules: [wp()] },
  ]);
  assert.equal(rows.length, 1);
  assert.deepEqual(rows[0].holders, ['edge-fra', 'edge-nyc']);
  assert.equal(rows[0].differs, false);
  assert.equal(rows[0].key, 'r-wp');
});

test('key order and the enabled flag do not make rules differ', () => {
  const a = wp();
  const b = { site: null, matchers: { path_regexes: ['^/wp-login'] }, action: 'deny', name: 'WordPress probes', id: 'r-wp', enabled: false };
  assert.equal(ruleContentKey(a), ruleContentKey(b));
  const rows = mergeRules([{ node: 'edge-fra', rules: [a] }, { node: 'edge-nyc', rules: [b] }]);
  assert.equal(rows.length, 1);
  assert.deepEqual(rows[0].nodes.map((n) => [n.node, n.enabled]), [['edge-fra', true], ['edge-nyc', false]]);
  assert.equal(enabledEverywhere(rows[0]), false);
});

test('the same id with different content gives two flagged rows', () => {
  const rows = mergeRules([
    { node: 'edge-fra', rules: [wp()] },
    { node: 'edge-nyc', rules: [wp({ action: 'drop' })] },
  ]);
  assert.equal(rows.length, 2);
  assert.ok(rows.every((r) => r.differs));
  assert.deepEqual(rows.map((r) => r.holders), [['edge-fra'], ['edge-nyc']]);
  assert.notEqual(rows[0].key, rows[1].key);
});

test('a rule on one node only lists that node and is not flagged', () => {
  const rows = mergeRules([
    { node: 'edge-fra', rules: [wp(), { id: 'r-env', name: 'Dotfiles', enabled: true, action: 'deny', matchers: {}, site: null }] },
    { node: 'edge-nyc', rules: [wp()] },
  ]);
  assert.equal(rows.length, 2);
  assert.deepEqual(rows.find((r) => r.id === 'r-env').holders, ['edge-fra']);
  assert.equal(rows.find((r) => r.id === 'r-env').differs, false);
});

test('hits are summed over the nodes that hold the row only', () => {
  const rows = mergeRules([
    { node: 'edge-fra', rules: [wp()] },
    { node: 'edge-nyc', rules: [wp()] },
    { node: 'edge-ams', rules: [] },
  ]);
  const summaries = {
    'edge-fra': { top_blocked: [{ key: 'r-wp', count: 10 }] },
    'edge-nyc': { top_blocked: [{ key: 'WordPress probes', count: 5 }] },
    'edge-ams': { top_blocked: [{ key: 'r-wp', count: 99 }] },
  };
  assert.equal(rowHits(rows[0], summaries), 15);
  assert.equal(rowHits(rows[0], {}), 0);
});

test('hits match by id, label or name', () => {
  const rule = wp({ label: 'wp-probes' });
  assert.equal(hitsForRule(rule, { top_blocked: [{ key: 'wp-probes', count: 3 }] }), 3);
  assert.equal(hitsForRule(rule, null), 0);
});

test('sites and presets merge by id and name', () => {
  assert.deepEqual(mergeSites([{ sites: [{ id: 'a', name: 'A' }] }, { sites: [{ id: 'a', name: 'Other' }, { id: 'b', name: 'B' }] }]).map((s) => s.name), ['A', 'B']);
  assert.deepEqual(mergePresets([{ presets: [{ name: 'p1' }] }, { presets: [{ name: 'p1' }, { name: 'p2' }] }]).map((p) => p.name), ['p1', 'p2']);
});

test('writable nodes are online and hold the site when one is set', () => {
  const nodes = [{ name: 'edge-fra', online: true }, { name: 'edge-nyc', online: true }, { name: 'edge-ams', online: false }];
  const sitesByNode = { 'edge-fra': [{ id: 'shop' }], 'edge-nyc': [], 'edge-ams': [{ id: 'shop' }] };
  assert.deepEqual(writableNodes(nodes, sitesByNode, ''), ['edge-fra', 'edge-nyc']);
  assert.deepEqual(writableNodes(nodes, sitesByNode, 'shop'), ['edge-fra']);
});

test('the preset model lists every rule with its action and real patterns', () => {
  const preset = {
    name: 'mixed',
    description: 'Blocks dotfiles and sends http to https. Skipped when TLS is off.',
    rules: [
      { name: 'Dotfiles', action: 'deny', matchers: { path_regexes: ['/\\.env'] } },
      { name: 'Scanners', action: 'tarpit', matchers: { user_agent_regexes: ['sqlmap'] } },
      { name: 'Silent', action: 'drop', matchers: { path_prefixes: ['/pma'] } },
      { name: 'Force HTTPS', matchers: { scheme: 'http' }, redirect: { to: 'https://{host}{path}', status: 301 } },
    ],
  };
  const model = presetRulesModel(preset);
  assert.deepEqual(model.map((m) => m.action), ['Deny', 'Tarpit', 'Drop', 'Redirect']);
  assert.deepEqual(model[0].patterns, ['path ~ /\\.env']);
  assert.deepEqual(model[3].patterns, ['scheme http']);
  assert.equal(model[3].target, 'https://{host}{path}');
  assert.equal(presetBlurb(preset), 'Blocks dotfiles and sends http to https.');
});

const redirect = (extra = {}) => ({
  id: 'redirect-1', name: 'Old blog', enabled: true, matchers: { path_prefixes: ['/blog'] }, site: null, label: 'redirect-1', redirect: { to: '/news', status: 301 }, ...extra,
});
// the body the editor builds from its merged copy (the first node's, which is on)
const edited = (extra = {}) => redirect({ redirect: { to: '/updated', status: 301 }, ...extra });
const heldBy = {
  'edge-fra': new Map([['redirect-1', redirect({ enabled: true })]]),
  'edge-nyc': new Map([['redirect-1', redirect({ enabled: false })]]),
  'edge-ams': new Map(),
};
const heldByNode = new Map(Object.entries(heldBy));

test('an untouched row keeps each node its own enabled state', () => {
  const diff = { replace: [edited()], delete: [] };
  const fra = bulkBodyFor('edge-fra', diff, new Set(), heldByNode);
  const nyc = bulkBodyFor('edge-nyc', diff, new Set(), heldByNode);
  assert.equal(fra.replace[0].enabled, true);
  assert.equal(nyc.replace[0].enabled, false);
  assert.equal(nyc.replace[0].redirect.to, '/updated');
});

test('a touched row sets the new value on every picked node', () => {
  const diff = { replace: [edited({ enabled: false })], delete: [] };
  for (const node of ['edge-fra', 'edge-nyc']) {
    assert.equal(bulkBodyFor(node, diff, new Set(['redirect-1']), heldByNode).replace[0].enabled, false);
  }
});

test('a row the node does not hold is created with the value in the edit', () => {
  const diff = { replace: [edited({ enabled: true })], delete: [] };
  const body = bulkBodyFor('edge-ams', diff, new Set(), heldByNode);
  assert.equal(body.replace[0].enabled, true);
  assert.equal(body.replace[0].id, 'redirect-1');
});

test('deletes are limited to the ids the node holds', () => {
  const diff = { replace: [], delete: ['redirect-1', 'redirect-9'] };
  assert.deepEqual(bulkBodyFor('edge-fra', diff, new Set(), heldByNode).delete, ['redirect-1']);
  assert.deepEqual(bulkBodyFor('edge-ams', diff, new Set(), heldByNode).delete, []);
});

test('on at some nodes and off at others is reported as differing', () => {
  assert.equal(enabledDiffers('redirect-1', heldByNode), true);
  assert.equal(enabledDiffers('redirect-1', new Map([['a', heldBy['edge-fra']], ['b', heldBy['edge-fra']]])), false);
  assert.equal(enabledDiffers('missing', heldByNode), false);
});

test('the unreachable note names the nodes', () => {
  assert.equal(unreachableNote([]), null);
  assert.equal(unreachableNote(['edge-nyc']), 'edge-nyc is unreachable and is left out.');
  assert.equal(unreachableNote(['a', 'b']), 'a, b are unreachable and are left out.');
});
