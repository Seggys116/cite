import test from 'node:test';
import assert from 'node:assert/strict';
import {
  COLUMNS, VIEW_WIDTH, buildTopology, clip, fmtRps, layoutTopology, lineWidth, linksThrough, loadFromFacets, pathLabel,
  shapeKey, siteKindLabel,
} from '../../web/js/topologylib.js';

const shop = { id: 'shop', name: 'Storefront', hosts: ['shop.example.com'], maintenance: { enabled: false } };
const api = {
  id: 'api', name: 'Public API', kind: 'api', hosts: ['api.example.com'], path_regexes: ['^/v1/(quote|price)$'], source: { runtime: 'rust' }, maintenance: { enabled: false },
};

test('facet counts become requests per second', () => {
  const load = loadFromFacets({ site: [{ key: 'shop', count: 900 }, { key: 'api', count: 90 }, { key: 7, count: 1 }, { key: 'bad', count: -4 }] }, 900);
  assert.deepEqual(load, { shop: 1, api: 0.1 });
  assert.deepEqual(loadFromFacets(null), {});
  assert.deepEqual(loadFromFacets({}), {});
});

test('the path label says what reaches the site', () => {
  assert.equal(pathLabel(shop), 'any path');
  assert.equal(pathLabel(api), '~ ^/v1/(quote|price)$');
  assert.equal(pathLabel({ path_prefixes: ['/blog'], path_regexes: ['^/a$'] }), '/blog  ~ ^/a$');
});

test('entries, nodes and sites are linked with load', () => {
  const g = buildTopology([
    { name: 'fra', online: true, sites: [shop], load: { shop: 41 } },
    { name: 'nyc', online: true, sites: [shop, api], load: { shop: 0, api: 128 } },
  ]);
  assert.equal(g.nodes.find((n) => n.name === 'nyc').rps, 128);
  assert.equal(g.nodes.find((n) => n.name === 'fra').rps, 41);
  assert.equal(g.sites.find((s) => s.id === 'shop').rps, 41);
  assert.deepEqual(g.sites.find((s) => s.id === 'shop').nodes, ['fra', 'nyc']);
  assert.equal(g.entries.length, 2);
  const idle = g.links.find((l) => l.via === 'nyc' && l.to === 'shop');
  assert.equal(idle.standby, true);
  assert.equal(g.links.find((l) => l.via === 'fra' && l.to === 'shop').standby, false);
  assert.equal(g.peak, 128);
});

test('an offline or unreadable node is shown, never dropped', () => {
  const g = buildTopology([
    { name: 'fra', online: true, sites: [shop], load: {} },
    { name: 'ams', online: false, sites: null, load: null },
  ]);
  const ams = g.nodes.find((n) => n.name === 'ams');
  assert.equal(ams.online, false);
  assert.equal(ams.readable, false);
  assert.equal(ams.rps, 0);
});

test('maintenance on any node shows on the site', () => {
  const down = { ...shop, maintenance: { enabled: true, page_id: 'soon' } };
  const g = buildTopology([
    { name: 'fra', online: true, sites: [shop], load: {} },
    { name: 'nyc', online: true, sites: [down], load: {} },
  ]);
  assert.equal(g.sites[0].state, 'maintenance');
});

test('line width grows with load and stays within bounds', () => {
  assert.equal(lineWidth(0, 100), 1.5);
  assert.equal(lineWidth(100, 100), 8);
  assert.ok(lineWidth(25, 100) > 1.5 && lineWidth(25, 100) < 8);
  assert.equal(lineWidth(5, 0), 1.5);
  assert.equal(lineWidth(500, 100), 8);
});

test('rates read cleanly', () => {
  assert.equal(fmtRps(0), '0/s');
  assert.equal(fmtRps(0.04), '0.0/s');
  assert.equal(fmtRps(4.26), '4.3/s');
  assert.equal(fmtRps(128.4), '128/s');
});

test('links through a node', () => {
  const g = buildTopology([
    { name: 'fra', online: true, sites: [shop], load: { shop: 1 } },
    { name: 'nyc', online: true, sites: [api], load: { api: 2 } },
  ]);
  assert.deepEqual(linksThrough(g, 'nyc').map((l) => l.to), ['api']);
});

test('clip keeps short text and shortens long text with an ellipsis', () => {
  assert.equal(clip('shop.example.com', 20), 'shop.example.com');
  assert.equal(clip('abcdefghij', 6), 'abcde…');
  assert.equal(clip('abc', 1), 'a…');
});

test('the kind line names the runtime of an API as one endpoint', () => {
  assert.equal(siteKindLabel({ kind: 'api', runtime: 'rust' }), 'Rust, one endpoint');
  assert.equal(siteKindLabel({ kind: 'api', runtime: null }), 'API');
  assert.equal(siteKindLabel({ kind: 'site', runtime: 'node' }), 'Node site');
  assert.equal(siteKindLabel({ kind: 'site', runtime: null }), 'Site');
});

const twoNodes = () => buildTopology([
  { name: 'fra', online: true, sites: [shop], load: { shop: 41 } },
  { name: 'nyc', online: true, sites: [shop, api], load: { shop: 0, api: 128 } },
]);

test('layout puts boxes in three columns inside the view and sizes the height from the rows', () => {
  const g = twoNodes();
  const lay = layoutTopology(g);
  assert.equal(lay.width, VIEW_WIDTH);
  assert.equal(lay.entries.length, 2);
  assert.equal(lay.nodes.length, 2);
  assert.equal(lay.sites.length, 2);
  for (const b of lay.entries) assert.equal(b.x, COLUMNS.entry.x);
  for (const b of lay.nodes) assert.equal(b.x, COLUMNS.node.x);
  for (const b of lay.sites) assert.equal(b.x, COLUMNS.site.x);
  for (const b of [...lay.entries, ...lay.nodes, ...lay.sites]) {
    assert.ok(b.y >= 0 && b.y + b.h <= lay.height, 'box inside the view');
    assert.ok(b.x + b.w <= lay.width);
  }
  const ys = lay.nodes.map((b) => b.y);
  assert.ok(ys[1] - ys[0] >= COLUMNS.node.h, 'boxes in a column do not overlap');
  const many = buildTopology([{
    name: 'fra', online: true, load: {}, sites: Array.from({ length: 12 }, (_, i) => ({ id: `s${i}`, name: `Site ${i}`, hosts: [`h${i}.example.com`] })),
  }]);
  assert.ok(layoutTopology(many).height > lay.height);
});

test('every link is a cubic path from one box edge to the next, drawn once', () => {
  const g = twoNodes();
  const lay = layoutTopology(g);
  const into = lay.links.filter((l) => l.stage === 'in');
  const out = lay.links.filter((l) => l.stage === 'out');
  assert.equal(into.length, g.links.length);
  assert.equal(out.length, 3);
  assert.equal(new Set(lay.links.map((l) => l.id)).size, lay.links.length);
  for (const l of lay.links) assert.match(l.d, /^M[\d.]+,[\d.]+ C[\d.]+,[\d.]+ [\d.]+,[\d.]+ [\d.]+,[\d.]+$/);
  const fra = lay.nodes.find((b) => b.name === 'fra');
  const firstIn = into.find((l) => l.via === 'fra');
  // numbers in order: x1 y1, control 1, control 2, x2 y2
  const nums = firstIn.d.match(/[\d.]+/g).map(Number);
  assert.equal(nums[6], fra.x);
  assert.equal(nums[7], fra.y + fra.h / 2, 'a lone link ends at the middle of the node edge');
});

test('the busiest link is marked and the idle one is a thin standby', () => {
  const lay = layoutTopology(twoNodes());
  const busiest = lay.links.filter((l) => l.busiest);
  assert.ok(busiest.length > 0);
  assert.ok(busiest.every((l) => l.via === 'nyc' && l.siteId === 'api'));
  const idle = lay.links.find((l) => l.id === 'out:nyc>shop');
  assert.equal(idle.standby, true);
  assert.equal(idle.width, 1.5);
  assert.equal(lay.links.find((l) => l.id === 'out:nyc>api').width, 8);
});

test('with no traffic nothing is busiest and every link is standby', () => {
  const g = buildTopology([{ name: 'fra', online: true, sites: [shop], load: {} }]);
  const lay = layoutTopology(g);
  assert.ok(lay.links.every((l) => !l.busiest && l.standby));
});

test('the shape key ignores load but notices boxes and links coming and going', () => {
  const a = twoNodes();
  const b = buildTopology([
    { name: 'fra', online: true, sites: [shop], load: { shop: 5 } },
    { name: 'nyc', online: true, sites: [shop, api], load: { shop: 9, api: 1 } },
  ]);
  assert.equal(shapeKey(a), shapeKey(b));
  const c = buildTopology([
    { name: 'fra', online: true, sites: [shop], load: {} },
    { name: 'nyc', online: true, sites: [shop], load: {} },
  ]);
  assert.notEqual(shapeKey(a), shapeKey(c));
  const offline = buildTopology([
    { name: 'fra', online: true, sites: [shop], load: {} },
    { name: 'nyc', online: false, sites: [shop, api], load: {} },
  ]);
  assert.notEqual(shapeKey(a), shapeKey(offline));
});
