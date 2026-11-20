import test from 'node:test';
import assert from 'node:assert/strict';
import {
  differentHolders, holderNodes, maintenanceMessage, nodeSaveBody, peerNames, siteRelation,
} from '../../web/js/sitenodeslib.js';

test('copies with an overlapping host are the same site, ignoring case', () => {
  assert.equal(siteRelation({ hosts: ['Blog.example.com', 'a.example.com'] }, { hosts: ['b.example.com', 'blog.example.com'] }), 'same');
});

test('copies built from the same repository are the same site even with different hosts', () => {
  assert.equal(siteRelation({ hosts: ['a.example.com'], source: { repo: 'acme/blog' } }, { hosts: ['b.example.org'], source: { repo: 'Acme/Blog' } }), 'same');
});

test('a shared id with no shared host or repository is a different site', () => {
  assert.equal(siteRelation({ hosts: ['blog.example.com'], source: null }, { hosts: ['api.example.org'], source: null }), 'different');
  assert.equal(siteRelation({ hosts: ['a.example.com'], source: { repo: 'acme/a' } }, { hosts: ['b.example.com'], source: { repo: 'acme/b' } }), 'different');
  assert.equal(siteRelation({ hosts: [] }, { hosts: [] }), 'different');
});

test('different holders name the node and its hosts and skip the current node and non-holders', () => {
  const site = { id: 'blog', hosts: ['blog.example.com'] };
  const peers = [
    { node: 'edge-nyc', sites: [{ id: 'blog', hosts: ['api.example.org'] }] },
    { node: 'edge-sin', sites: [{ id: 'blog', hosts: ['blog.example.com'] }] },
    { node: 'edge-lon', sites: [{ id: 'docs', hosts: ['x.example.net'] }] },
    { node: 'edge-ams', sites: null },
  ];
  const holders = ['edge-fra', 'edge-nyc', 'edge-sin'];
  assert.deepEqual(differentHolders(site, 'edge-fra', peers, holders), [{ node: 'edge-nyc', hosts: ['api.example.org'] }]);
});
import {
  ENV_NAMES_NOTE, ENV_VALUE_HINT, ENV_VALUE_LABEL, WRITE_ONLY_HINT,
} from '../../web/js/envlib.js';

test('the write-only wording says what is stored and that it is not sent back', () => {
  assert.equal(ENV_VALUE_LABEL, 'Value (write-only)');
  assert.match(ENV_VALUE_HINT, /never sends it back/);
  assert.match(ENV_NAMES_NOTE, /names only/);
  assert.equal(WRITE_ONLY_HINT, 'Write-only: the node stores it and does not send it back');
});

const health = { path: '/health', interval_ms: 2000, timeout_ms: 1000, rise: 2, fall: 3 };
const stored = (over = {}) => ({
  id: 'shop',
  name: 'Shop',
  hosts: ['shop.example.com'],
  path_prefixes: [],
  path_regexes: [],
  kind: 'site',
  blue: { targets: [{ addr: '10.0.0.1:8080', weight: 100 }] },
  green: { targets: [] },
  active: 'blue',
  health,
  source: null,
  ...over,
});

test('peers are the online nodes other than the current one', () => {
  const nodes = [{ name: 'edge-fra', online: true }, { name: 'edge-nyc', online: true }, { name: 'edge-ams', online: false }];
  assert.deepEqual(peerNames(nodes, 'edge-fra'), ['edge-nyc']);
  assert.deepEqual(peerNames([], 'edge-fra'), []);
});

test('holders are the current node and every peer that lists the site, in node order', () => {
  const peers = [
    { node: 'edge-nyc', sites: [{ id: 'shop' }, { id: 'blog' }] },
    { node: 'edge-sin', sites: [{ id: 'blog' }] },
    { node: 'edge-lon', sites: null },
  ];
  assert.deepEqual(holderNodes('shop', 'edge-fra', peers, ['edge-fra', 'edge-nyc', 'edge-sin', 'edge-lon']), ['edge-fra', 'edge-nyc']);
  assert.deepEqual(holderNodes('shop', 'edge-nyc', peers, ['edge-fra', 'edge-nyc']), ['edge-nyc']);
});

test('the current node is a holder even when it is not in the node order', () => {
  assert.deepEqual(holderNodes('shop', 'edge-fra', [], []), ['edge-fra']);
});

test('a shared save keeps the targets, live slot and source of the node it is written to', () => {
  const theirs = stored({
    blue: { targets: [{ addr: '10.9.9.9:9000', weight: 50 }] },
    active: 'green',
    source: { repo: 'acme/shop', branch: 'main' },
    name: 'Old name',
  });
  const body = nodeSaveBody(theirs, {
    name: 'Shop', kind: 'api', hosts: ['a.example.com', 'b.example.com'], path_prefixes: ['/v1'], path_regexes: [], health: { ...health, interval_ms: 5000 },
    access: { cloudflare_only: false, tls: 'full', bots: 'allow', zone_lock: false },
  });
  assert.equal(body.name, 'Shop');
  assert.equal(body.kind, 'api');
  assert.deepEqual(body.hosts, ['a.example.com', 'b.example.com']);
  assert.deepEqual(body.path_prefixes, ['/v1']);
  assert.equal(body.health.interval_ms, 5000);
  assert.deepEqual(body.blue, theirs.blue);
  assert.equal(body.active, 'green');
  assert.deepEqual(body.source, theirs.source);
});

test('access is left out for a default value on a node that had none, and kept when it had some', () => {
  const plain = { cloudflare_only: false, tls: 'full', bots: 'allow', zone_lock: false };
  const shared = { name: 'Shop', kind: 'site', hosts: ['shop.example.com'], path_prefixes: [], path_regexes: [], health, access: plain };
  assert.equal('access' in nodeSaveBody(stored(), shared), false);
  const had = nodeSaveBody(stored({ access: { cloudflare_only: true, tls: 'full' } }), shared);
  assert.deepEqual(had.access, { cloudflare_only: false, tls: 'full' });
  const locked = nodeSaveBody(stored(), { ...shared, access: { cloudflare_only: true, tls: 'flexible', bots: 'block_bad', zone_lock: false } });
  assert.deepEqual(locked.access, { cloudflare_only: true, tls: 'flexible', bots: 'block_bad' });
});

test('the maintenance message names the nodes that changed and the ones that failed', () => {
  const results = [
    { node: 'edge-fra', ok: true },
    { node: 'edge-nyc', ok: true },
    { node: 'edge-ams', ok: false, error: new Error('timeout') },
  ];
  assert.equal(maintenanceMessage(true, results), 'Maintenance enabled on edge-fra, edge-nyc. Failed on edge-ams: timeout');
  assert.equal(maintenanceMessage(false, [results[0]]), 'Maintenance disabled on edge-fra');
});
