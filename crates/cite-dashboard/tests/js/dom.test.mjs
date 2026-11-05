import test from 'node:test';
import assert from 'node:assert/strict';

class FakeNode {
  constructor(kind, value) { this.kind = kind; this.value = value; this.children = []; this.attrs = {}; }
  appendChild(kid) { this.children.push(kid); return kid; }
  setAttribute(k, v) { this.attrs[k] = v; }
  addEventListener() {}
}
globalThis.Node = FakeNode;
globalThis.document = {
  createElement: (tag) => new FakeNode('el', tag),
  createElementNS: (ns, tag) => new FakeNode('el', tag),
  createTextNode: (text) => new FakeNode('text', text),
};
const { h } = await import('../../web/js/dom.js');

test('markup in string children stays a text node', () => {
  const payload = '<img src=x onerror=alert(1)>';
  const el = h('p', {}, payload);
  assert.equal(el.children.length, 1);
  assert.equal(el.children[0].kind, 'text');
  assert.equal(el.children[0].value, payload);
});

test('exception text and numbers become text nodes, nodes are appended as is', () => {
  const inner = h('b', {}, 'x');
  const el = h('div', {}, new Error('<b>boom</b>'), 7, [inner, null, false, 'a']);
  assert.deepEqual(el.children.map((c) => c.kind), ['text', 'text', 'el', 'text']);
  assert.equal(el.children[0].value, 'Error: <b>boom</b>');
  assert.equal(el.children[2], inner);
});
