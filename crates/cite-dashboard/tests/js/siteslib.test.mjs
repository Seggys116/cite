import test from 'node:test';
import assert from 'node:assert/strict';
import {
  SCOPE_ALL, SCOPE_ATTENTION, chipTitle, filterRows, groupSites, homeNode, mergeSeries, needsAttention, nodeScope, nodeStatus,
  rowRps, rowStatus, scopeRows, subtitleFor,
} from '../../web/js/siteslib.js';

const shop = { id: 'shop', name: 'Storefront', hosts: ['shop.example.com', 'www.example.com'], maintenance: { enabled: false }, history: [] };
const api = {
  id: 'api', name: 'Public API', kind: 'api', hosts: ['api.example.com'], path_regexes: ['^/v1/(quote|price)$'], maintenance: { enabled: false }, history: [],
};
const docsFailed = {
  id: 'docs', name: 'Documentation', hosts: ['docs.example.com'], maintenance: { enabled: false },
  history: [{ action: 'promote', slot: 'blue' }, { action: 'failed', slot: 'green', note: 'Health check timed out' }],
};
const docsMaint = { ...docsFailed, history: [], maintenance: { enabled: true, page_id: 'soon' } };

test('a site on two nodes is one row with a chip per node', () => {
  const { rows, nodes, unreachable } = groupSites([
    { node: 'fra', sites: [shop, api] },
    { node: 'nyc', sites: [{ ...shop, hosts: ['shop.example.com', 'extra.example.com'] }] },
    { node: 'ams', sites: null },
  ]);
  assert.deepEqual(rows.map((r) => r.id), ['api', 'shop']);
  const row = rows.find((r) => r.id === 'shop');
  assert.deepEqual(row.nodes.map((n) => n.node), ['fra', 'nyc']);
  assert.deepEqual(row.hosts, ['shop.example.com', 'www.example.com', 'extra.example.com']);
  assert.deepEqual(row.paths, []);
  assert.equal(rows[0].kind, 'api');
  assert.deepEqual(rows[0].paths, ['~ ^/v1/(quote|price)$']);
  assert.deepEqual(nodes, ['fra', 'nyc']);
  assert.deepEqual(unreachable, ['ams']);
});

test('an unreachable node is named and never dropped silently', () => {
  const out = groupSites([{ node: 'fra', sites: null }, { node: 'nyc', sites: null }]);
  assert.deepEqual(out.rows, []);
  assert.deepEqual(out.unreachable, ['fra', 'nyc']);
});

test('state comes from maintenance, failing targets and the last deploy', () => {
  assert.equal(nodeStatus(shop, null).state, 'serving');
  assert.equal(nodeStatus(shop, null).health, 'ok');
  const failed = nodeStatus(docsFailed, null);
  assert.equal(failed.state, 'failed');
  assert.equal(failed.reason, 'Last deploy failed: Health check timed out');
  assert.equal(nodeStatus(docsMaint, null).state, 'maintenance');
  const down = nodeStatus(shop, { ...shop, active: 'blue', live: { blue: [{ addr: '10.0.0.1:80', status: 'DOWN' }] } });
  assert.equal(down.state, 'attention');
  assert.equal(down.health, 'bad');
  assert.match(down.reason, /10\.0\.0\.1:80/);
  const unread = nodeStatus(shop, null, { unreadable: true });
  assert.equal(unread.state, 'serving');
  assert.equal(unread.health, 'warn');
});

test('a row shows the most serious state of any node, naming the node', () => {
  const status = rowStatus([
    { node: 'fra', ...nodeStatus(docsFailed, null) },
    { node: 'nyc', ...nodeStatus(docsMaint, null) },
  ]);
  assert.equal(status.state, 'failed');
  assert.equal(status.label, 'Deploy failed');
  assert.equal(status.reason, 'fra: Last deploy failed: Health check timed out');
  const single = rowStatus([{ node: 'fra', ...nodeStatus(docsFailed, null) }]);
  assert.equal(single.reason, 'Last deploy failed: Health check timed out');
  assert.equal(rowStatus([]).state, 'serving');
  assert.equal(needsAttention(status), true);
  assert.equal(needsAttention(rowStatus([{ node: 'x', ...nodeStatus(docsMaint, null) }])), false);
});

test('chip titles explain the dot', () => {
  assert.equal(chipTitle('fra', nodeStatus(shop, null)), 'fra: healthy');
  assert.equal(chipTitle('fra', { ...nodeStatus(docsFailed, null), label: 'Deploy failed' }), 'fra: Last deploy failed: Health check timed out');
});

test('scopes pick a node or the sites that need attention', () => {
  const { rows } = groupSites([{ node: 'fra', sites: [shop, docsFailed] }, { node: 'nyc', sites: [shop, api] }]);
  const statusOf = (row) => rowStatus(row.nodes.map((n) => ({ node: n.node, ...nodeStatus(n.site, null) })));
  assert.equal(scopeRows(rows, SCOPE_ALL, statusOf).length, 3);
  assert.deepEqual(scopeRows(rows, nodeScope('nyc'), statusOf).map((r) => r.id), ['api', 'shop']);
  assert.deepEqual(scopeRows(rows, nodeScope('fra'), statusOf).map((r) => r.id), ['docs', 'shop']);
  assert.deepEqual(scopeRows(rows, nodeScope('ams'), statusOf), []);
  assert.deepEqual(scopeRows(rows, SCOPE_ATTENTION, statusOf).map((r) => r.id), ['docs']);
});

test('the name and host filter is case insensitive', () => {
  const { rows } = groupSites([{ node: 'fra', sites: [shop, api] }]);
  assert.equal(filterRows(rows, '').length, 2);
  assert.deepEqual(filterRows(rows, 'STORE').map((r) => r.id), ['shop']);
  assert.deepEqual(filterRows(rows, 'api.example').map((r) => r.id), ['api']);
  assert.deepEqual(filterRows(rows, 'nothing'), []);
});

test('a row opens on the scoped node, else the first node that has it', () => {
  const { rows } = groupSites([{ node: 'fra', sites: [shop] }, { node: 'nyc', sites: [shop] }]);
  assert.equal(homeNode(rows[0], SCOPE_ALL), 'fra');
  assert.equal(homeNode(rows[0], nodeScope('nyc')), 'nyc');
  assert.equal(homeNode(rows[0], nodeScope('ams')), 'fra');
});

test('load adds the nodes that reported a figure and stays unknown otherwise', () => {
  const { rows } = groupSites([{ node: 'fra', sites: [shop] }, { node: 'nyc', sites: [shop] }]);
  assert.equal(rowRps(rows[0], { fra: { shop: 4 }, nyc: { shop: 1.5 } }), 5.5);
  assert.equal(rowRps(rows[0], { fra: { shop: 4 }, nyc: null }), 4);
  assert.equal(rowRps(rows[0], { fra: {}, nyc: { api: 3 } }), 0);
  assert.equal(rowRps(rows[0], { fra: null, nyc: null }), null);
  assert.equal(rowRps(rows[0], null), null);
});

test('series from several nodes add up from the newest point back', () => {
  assert.deepEqual(mergeSeries([[1, 2, 3], [10, 20]]), [1, 12, 23]);
  assert.deepEqual(mergeSeries([[1, 2], null, []]), [1, 2]);
  assert.deepEqual(mergeSeries([]), []);
});

test('the subtitle is short', () => {
  assert.equal(subtitleFor(4, 2), '4 across 2 nodes');
  assert.equal(subtitleFor(1, 1), '1 across 1 node');
});
