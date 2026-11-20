import { h } from '../dom.js';
import { segmented } from '../ui.js';

// The node a single-node screen starts on: the node chosen in the switcher, else nothing.
// Under "All nodes" no node is picked for the person, so a write can never land on one they did not choose.
export function pickScopeNode(state) {
  if (state && state.node && state.node !== 'all') return state.node;
  return null;
}

// Shown in place of the page body until a node is chosen on the bar
export function chooseNodeNotice() {
  return h('p', { class: 'muted' }, 'Choose a node to continue');
}

// A page keeps its own node choice while the switcher stays where it was, so tab changes do not reset it
const remembered = new Map();

export function scopeFor(page, state) {
  const mem = remembered.get(page);
  const nodes = (state && state.nodes) || [];
  if (mem && mem.global === state.node && nodes.some((n) => n.name === mem.name)) return mem.name;
  return pickScopeNode(state);
}

export function rememberScope(page, state, name) {
  remembered.set(page, { global: state.node, name });
}

// One entry per node so the target of every write on the page is a visible choice
export function nodeScopeBar({
  nodes, selected, onChange, label = 'Node',
}) {
  let current = selected;
  const seg = segmented({
    label,
    value: selected,
    options: nodes.map((n) => ({
      value: n.name,
      label: n.online ? n.name : [n.name, h('span', { class: 'node-scope-off' }, 'Offline')],
    })),
    onChange: (name) => {
      if (name === current) return;
      current = name;
      onChange(name);
    },
  });
  Array.from(seg.children).forEach((btn, i) => {
    if (nodes[i].online) return;
    btn.disabled = true;
    btn.title = `${nodes[i].name} is offline`;
  });
  return h('div', { class: 'node-scope' }, h('span', { class: 'node-scope-label' }, label), seg);
}
