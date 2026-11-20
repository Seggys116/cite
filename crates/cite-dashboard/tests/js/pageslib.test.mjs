import test from 'node:test';
import assert from 'node:assert/strict';
import {
  bulkMessage, driftPlan, drainPlan, missingPlan, nodesNeedingPage, planLines, restorePlan, rowPage, saveConfirmLines, savePlan, siteMatrix, syncSummary, unionPages,
} from '../../web/js/pageslib.js';

const page = (id, over = {}) => ({ id, name: id.toUpperCase(), html: `<p>${id}</p>`, status: 503, ...over });

test('a page held by one node is missing from the other', () => {
  const u = unionPages([
    { node: 'a', pages: [page('soon'), page('incident')] },
    { node: 'b', pages: [page('soon')] },
  ]);
  assert.equal(u.pages.length, 2);
  const incident = u.pages.find((p) => p.id === 'incident');
  assert.deepEqual(incident.missing, ['b']);
  assert.deepEqual(missingPlan(u).map((m) => [m.node, m.page.id]), [['b', 'incident']]);
  assert.equal(syncSummary(u).inSync, false);
  assert.equal(syncSummary(u).text, 'b is missing 1 page');
});

test('a node that could not be read is never reported as missing pages', () => {
  const u = unionPages([
    { node: 'a', pages: [page('soon')] },
    { node: 'b', pages: null },
  ]);
  assert.deepEqual(missingPlan(u), []);
  assert.deepEqual(u.unreadable, ['b']);
  assert.equal(syncSummary(u).inSync, false);
});

test('differing copies are drift and the majority wins', () => {
  const u = unionPages([
    { node: 'a', pages: [page('soon')] },
    { node: 'b', pages: [page('soon', { html: '<p>old</p>' })] },
    { node: 'c', pages: [page('soon')] },
  ]);
  const soon = u.pages[0];
  assert.equal(soon.drift, true);
  assert.equal(soon.html, '<p>soon</p>');
  assert.deepEqual(driftPlan(u).map((d) => d.node), ['b']);
});

test('a tie goes to the node listed first', () => {
  const u = unionPages([
    { node: 'a', pages: [page('soon', { html: 'A' })] },
    { node: 'b', pages: [page('soon', { html: 'B' })] },
  ]);
  assert.equal(u.pages[0].html, 'A');
  assert.deepEqual(driftPlan(u).map((d) => d.node), ['b']);
});

test('identical copies are in sync', () => {
  const u = unionPages([
    { node: 'a', pages: [page('soon')] },
    { node: 'b', pages: [page('soon')] },
  ]);
  assert.deepEqual(syncSummary(u), { inSync: true, text: 'In sync on every node' });
});

test('a node that needs a page before maintenance can use it', () => {
  const u = unionPages([
    { node: 'a', pages: [page('soon')] },
    { node: 'b', pages: [] },
  ]);
  assert.deepEqual(nodesNeedingPage(u, 'soon', ['a', 'b']), ['b']);
  assert.deepEqual(nodesNeedingPage(u, 'nope', ['a', 'b']), []);
});

test('saving a page puts where the node holds it and posts where it does not', () => {
  const u = unionPages([
    { node: 'a', pages: [page('soon')] },
    { node: 'b', pages: [] },
  ]);
  assert.deepEqual(savePlan(u, 'soon', ['a', 'b']), [{ node: 'a', method: 'put' }, { node: 'b', method: 'post' }]);
  assert.deepEqual(savePlan(u, 'fresh', ['a', 'b']), [{ node: 'a', method: 'post' }, { node: 'b', method: 'post' }]);
});

test('save confirmation lines warn where a differing copy is replaced', () => {
  const u = unionPages([
    { node: 'a', pages: [page('soon')] },
    { node: 'b', pages: [page('soon', { html: 'old' })] },
    { node: 'c', pages: [page('soon')] },
    { node: 'd', pages: [] },
  ]);
  const plan = savePlan(u, 'soon', ['a', 'b', 'c', 'd']);
  assert.deepEqual(saveConfirmLines(u, 'soon', plan, 'Incident notice'), [
    'a: update Incident notice',
    'b: update Incident notice (its copy differs and will be replaced)',
    'c: update Incident notice',
    'd: add Incident notice',
  ]);
  assert.deepEqual(saveConfirmLines(u, 'fresh', savePlan(u, 'fresh', ['a']), 'New'), ['a: add New']);
});

test('plan lines group additions and updates per node', () => {
  const u = unionPages([
    { node: 'a', pages: [page('soon'), page('incident'), page('sale')] },
    { node: 'b', pages: [page('soon', { html: 'old' }), page('sale')] },
    { node: 'c', pages: [page('soon'), page('incident'), page('sale')] },
  ]);
  assert.deepEqual(planLines(missingPlan(u), driftPlan(u)), ['b: add INCIDENT; update SOON']);
  assert.deepEqual(planLines([], []), []);
});

test('a bulk message names the node, the sites that changed and the ones that failed', () => {
  const rows = [{ id: 'shop', name: 'Storefront' }, { id: 'docs', name: 'Docs' }];
  const results = [
    { node: 'shop', ok: true },
    { node: 'docs', ok: false, error: new Error('page in use') },
  ];
  assert.equal(bulkMessage('on', 'edge-nyc', rows, results), 'Maintenance on for Storefront on edge-nyc. Failed for Docs: page in use');
  assert.equal(bulkMessage('off', 'edge-nyc', rows, [results[0]]), 'Maintenance off for Storefront on edge-nyc');
});

const site = (id, enabled, pageId) => ({ id, name: id, maintenance: { enabled, page_id: pageId } });

test('the matrix has one row per site and a cell per node', () => {
  const m = siteMatrix([
    { node: 'a', online: true, sites: [site('shop', false, 'soon'), site('api', false, null)] },
    { node: 'b', online: true, sites: [site('shop', true, 'soon')] },
  ]);
  assert.deepEqual(m.rows.map((r) => r.id), ['api', 'shop']);
  const shop = m.rows.find((r) => r.id === 'shop');
  assert.equal(shop.cells.b.enabled, true);
  assert.equal(m.rows[0].cells.b.present, false);
  assert.equal(rowPage(shop), 'soon');
});

test('drain lists the sites not yet in maintenance on that node only', () => {
  const m = siteMatrix([
    { node: 'a', online: true, sites: [site('shop', false, null), site('api', true, 'soon')] },
    { node: 'b', online: true, sites: [site('shop', false, null)] },
  ]);
  assert.deepEqual(drainPlan(m, 'a'), ['shop']);
  assert.deepEqual(restorePlan(m, 'a'), ['api']);
  assert.deepEqual(drainPlan(m, 'b'), ['shop']);
});
