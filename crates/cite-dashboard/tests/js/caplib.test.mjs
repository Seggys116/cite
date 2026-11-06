import test from 'node:test';
import assert from 'node:assert/strict';
import {
  FEATURES, capabilitiesOf, forgetNodeInfo, hasFeature, nodeInfoCached, showsBuildSettings, siteFeatures,
} from '../../web/js/caplib.js';

test('a feature shows only when the node lists it', () => {
  const info = { capabilities: ['site-status', 'site-logs', 'alerts', 7] };
  assert.equal(hasFeature(info, 'status'), true);
  assert.equal(hasFeature(info, 'logs'), true);
  assert.equal(hasFeature(info, 'alerts'), true);
  assert.equal(hasFeature(info, 'token'), false);
  assert.equal(hasFeature(info, 'nonsense'), false);
  assert.equal(capabilitiesOf(info).size, 3);
});

test('an older node lists nothing so everything stays hidden', () => {
  for (const info of [null, undefined, {}, { capabilities: null }, { capabilities: 'site-status' }]) {
    assert.ok(Object.values(siteFeatures(info)).every((v) => v === false), JSON.stringify(info));
  }
});

test('every known capability name has a feature key', () => {
  const names = ['site-status', 'site-logs', 'source-build', 'site-github-token', 'site-build-env', 'site-runtime-env', 'deploy-async', 'cert-generate', 'cert-origin-ca', 'cert-acme', 'alerts', 'forges'];
  assert.deepEqual(Object.values(FEATURES).sort(), [...names].sort());
  assert.ok(Object.values(siteFeatures({ capabilities: names })).every(Boolean));
});

test('build settings need both a built site and the node feature', () => {
  const info = { capabilities: ['source-build'] };
  assert.equal(showsBuildSettings(info, { source: { repo: 'a/b' } }), true);
  assert.equal(showsBuildSettings(info, { source: null }), false);
  assert.equal(showsBuildSettings({ capabilities: [] }, { source: { repo: 'a/b' } }), false);
  assert.equal(showsBuildSettings(info, null), false);
});

test('node info is fetched once per minute and shared while in flight', async () => {
  forgetNodeInfo();
  let calls = 0;
  const load = async () => {
    calls += 1;
    return { n: calls };
  };
  const [a, b] = await Promise.all([nodeInfoCached('n1', load, 1000), nodeInfoCached('n1', load, 1001)]);
  assert.deepEqual([a.n, b.n, calls], [1, 1, 1]);
  assert.equal((await nodeInfoCached('n1', load, 30000)).n, 1);
  assert.equal((await nodeInfoCached('n1', load, 62000)).n, 2);
  assert.equal((await nodeInfoCached('n2', load, 62000)).n, 3);
  forgetNodeInfo('n2');
  assert.equal((await nodeInfoCached('n2', load, 62001)).n, 4);
});

test('a failed fetch is not cached', async () => {
  forgetNodeInfo();
  let fail = true;
  const load = async () => {
    if (fail) throw new Error('down');
    return { ok: true };
  };
  await assert.rejects(nodeInfoCached('n3', load, 1), /down/);
  fail = false;
  assert.deepEqual(await nodeInfoCached('n3', load, 2), { ok: true });
});
