import test from 'node:test';
import assert from 'node:assert/strict';
import {
  SOURCES, STEPS, buildSite, emptySiteForm, firstProblem, reviewLines, stepProblem,
} from '../../web/js/sitewizard.js';
import { tokenPlan } from '../../web/js/siteCheck.js';
import { newRow } from '../../web/js/conditionlib.js';

const github = (over = {}) => ({
  ...emptySiteForm(), source: 'github', repo: 'acme/storefront', name: 'Storefront', id: 'storefront', hosts: ['shop.example.com'], nodes: ['edge-1'], ...over,
});
const servers = (over = {}) => ({
  ...emptySiteForm(), source: 'servers', blue: [{ addr: '10.0.0.12:8080', weight: 100 }], name: 'Api', id: 'api', hosts: ['api.example.com'], nodes: ['edge-1'], ...over,
});
const have = tokenPlan(['yes']);
const missing = tokenPlan(['no']);

test('GitHub is the first choice and the steps keep their order', () => {
  assert.equal(SOURCES[0].value, 'github');
  assert.equal(SOURCES[1].title, 'Serve servers I already run');
  assert.equal(STEPS.length, 5);
  assert.equal(emptySiteForm().source, '');
});

test('step one needs a source', () => {
  assert.match(stepProblem(emptySiteForm(), 0), /Choose where/);
  assert.equal(stepProblem(github(), 0), null);
  assert.equal(stepProblem(servers(), 0), null);
});

test('GitHub details are checked field by field', () => {
  assert.equal(stepProblem(github(), 1), null);
  assert.match(stepProblem(github({ repo: 'nope' }), 1), /owner\/name/);
  assert.match(stepProblem(github({ branch: 'a..b' }), 1), /branch/);
  assert.match(stepProblem(github({ runtime: 'ruby' }), 1), /node, bun, static or rust/);
  assert.match(stepProblem(github({ poll: 'often' }), 1), /poll interval/);
});

test('the token is required only when a selected node has none', () => {
  assert.equal(stepProblem(github(), 1, { tokenPlan: have, token: '' }), null);
  assert.match(stepProblem(github(), 1, { tokenPlan: missing, token: '  ' }), /GitHub token/);
  assert.equal(stepProblem(github(), 1, { tokenPlan: missing, token: 'abc' }), null);
  const mixed = tokenPlan(['yes', 'no']);
  assert.match(stepProblem(github(), 4, { tokenPlan: mixed, token: '' }), /GitHub token/);
  assert.equal(stepProblem(github(), 4, { tokenPlan: mixed, token: 'abc' }), null);
  assert.equal(stepProblem(github(), 4, { tokenPlan: tokenPlan(['yes', 'yes']), token: '' }), null);
  assert.equal(stepProblem(servers(), 4, { tokenPlan: missing, token: '' }), null);
});

test('server details need a live server and a health path', () => {
  assert.equal(stepProblem(servers(), 1), null);
  assert.match(stepProblem(servers({ blue: [] }), 1), /at least one server/);
  assert.equal(stepProblem(servers({ targetProblem: '"x" is not a host:port address.' }), 1), '"x" is not a host:port address.');
  assert.match(stepProblem(servers({ healthPath: 'health' }), 1), /start with \//);
});

test('name, id, domains and paths are checked on step three', () => {
  assert.equal(stepProblem(github(), 2), null);
  assert.match(stepProblem(github({ name: ' ' }), 2), /name/);
  assert.match(stepProblem(github({ id: 'Bad Id' }), 2), /site id/);
  assert.match(stepProblem(github({ hosts: [] }), 2), /domain/);
  const bad = { ...newRow('path_regex'), value: '(' };
  assert.match(stepProblem(github({ paths: [bad] }), 2), /^Condition 1:/);
  const good = { ...newRow('path_prefix'), value: '/api' };
  assert.equal(stepProblem(github({ paths: [good] }), 2), null);
});

test('protection never blocks and the last step needs a node', () => {
  assert.equal(stepProblem(github(), 3), null);
  assert.match(stepProblem(github({ nodes: [] }), 4), /at least one node/);
  assert.equal(stepProblem(github({ nodes: [], replicate: true }), 4), null);
});

test('create sends the user back to the first step with a problem', () => {
  assert.equal(firstProblem(github(), { tokenPlan: have, token: '' }), null);
  assert.equal(firstProblem(github({ id: '' }), { tokenPlan: have }).step, 2);
  assert.equal(firstProblem(github({ repo: '' }), {}).step, 1);
  assert.equal(firstProblem(emptySiteForm(), {}).step, 0);
});

test('a GitHub site is sent with empty slots and its source', () => {
  const site = buildSite(github({ paths: [{ ...newRow('path_prefix'), value: '/shop' }, { ...newRow('path_regex'), value: '^/v[0-9]+/' }] }));
  assert.deepEqual(site.blue, { targets: [], label: null });
  assert.deepEqual(site.green, { targets: [], label: null });
  assert.equal(site.active, 'blue');
  assert.deepEqual(site.source, { repo: 'acme/storefront', branch: 'main', runtime: 'node', node_major: 22, poll_interval: '5m' });
  assert.deepEqual(site.path_prefixes, ['/shop']);
  assert.deepEqual(site.path_regexes, ['^/v[0-9]+/']);
  assert.equal('path_regex' in site, false);
  assert.equal(site.health.path, '/');
  assert.equal('access' in site, false);
  assert.equal(buildSite(github({ runtime: 'rust' })).source.node_major, null);
});

test('a site on your own servers keeps its targets and has no source', () => {
  const site = buildSite(servers({ green: [{ addr: '10.0.0.13:8080', weight: 50 }], healthPath: '/healthz' }));
  assert.deepEqual(site.blue.targets, [{ addr: '10.0.0.12:8080', weight: 100 }]);
  assert.deepEqual(site.green.targets, [{ addr: '10.0.0.13:8080', weight: 50 }]);
  assert.equal(site.source, null);
  assert.equal(site.health.path, '/healthz');
  assert.deepEqual(site.path_prefixes, []);
});

test('protection choices reach the site body', () => {
  const access = { cloudflare_only: true, tls: 'flexible', bots: 'block_bad', zone_lock: false };
  assert.deepEqual(buildSite(github({ access })).access, { cloudflare_only: true, tls: 'flexible', bots: 'block_bad' });
});

test('the review describes the choices and the GitHub path never mentions blue, green or upstreams', () => {
  const access = { cloudflare_only: true, tls: 'flexible', bots: 'block_all', zone_lock: true };
  const lines = reviewLines(github({ access, nodes: ['edge-1', 'edge-2'] }), { tokenText: 'the node token' });
  const text = lines.map((l) => l.join(' ')).join('\n');
  assert.doesNotMatch(text, /blue|green|upstream/i);
  assert.match(text, /GitHub repository acme\/storefront \(main, node\)/);
  assert.match(text, /only through the Cloudflare proxy, Cloudflare handles HTTPS, my Cloudflare account only, all bots blocked/);
  assert.match(text, /GitHub token the node token/);
  assert.match(text, /Nodes edge-1, edge-2/);
  const open = reviewLines(servers(), {}).map((l) => l.join(' ')).join('\n');
  assert.match(open, /1 server you run/);
  assert.match(open, /open to any visitor/);
  assert.doesNotMatch(open, /GitHub token/);
  assert.match(reviewLines(github({ replicate: true }), {}).map((l) => l.join(' ')).join('\n'), /every online node/);
});
