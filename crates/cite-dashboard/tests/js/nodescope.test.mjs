import test from 'node:test';
import assert from 'node:assert/strict';
import { pickScopeNode, rememberScope, scopeFor } from '../../web/js/views/nodeScope.js';

const nodes = [
  { name: 'edge-ams', online: false },
  { name: 'edge-fra', online: true },
  { name: 'edge-nyc', online: true },
];

test('a single selected node is the starting scope', () => {
  assert.equal(pickScopeNode({ node: 'edge-nyc', nodes }), 'edge-nyc');
});

test('all nodes picks nothing for the person, even with one online node', () => {
  assert.equal(pickScopeNode({ node: 'all', nodes }), null);
  assert.equal(pickScopeNode({ node: 'all', nodes: [nodes[1]] }), null);
  assert.equal(pickScopeNode({ node: 'all', nodes: [] }), null);
});

test('all nodes with no remembered choice on the page gives null', () => {
  assert.equal(scopeFor('fresh-page', { node: 'all', nodes }), null);
});

test('a clicked node on the page bar wins under all nodes and stays per page', () => {
  const state = { node: 'all', nodes };
  rememberScope('settings', state, 'edge-nyc');
  assert.equal(scopeFor('settings', state), 'edge-nyc');
  assert.equal(scopeFor('traffic', state), null);
});

test('a single selected node is the scope when the page has no remembered choice', () => {
  assert.equal(scopeFor('other-page', { node: 'edge-fra', nodes }), 'edge-fra');
});

test('the remembered choice is dropped when the global switcher changes', () => {
  rememberScope('settings', { node: 'all', nodes }, 'edge-nyc');
  assert.equal(scopeFor('settings', { node: 'edge-fra', nodes }), 'edge-fra');
  assert.equal(scopeFor('settings', { node: 'all', nodes }), 'edge-nyc');
  rememberScope('settings', { node: 'edge-fra', nodes }, 'edge-nyc');
  assert.equal(scopeFor('settings', { node: 'all', nodes }), null);
});

test('a remembered node that no longer exists is ignored', () => {
  rememberScope('alerts', { node: 'all', nodes }, 'edge-gone');
  assert.equal(scopeFor('alerts', { node: 'all', nodes }), null);
});
