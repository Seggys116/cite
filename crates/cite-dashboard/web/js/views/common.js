import { h } from '../dom.js';
import { state } from '../state.js';
import { emptyState, pill, dot } from '../ui.js';

export function noNodes() {
  return emptyState({
    iconName: 'server',
    title: 'No nodes connected',
    text: 'Connect a Cite node first. Its sites, traffic and firewall then appear here.',
    action: h('a', { class: 'btn btn-primary', href: '#/nodes' }, 'Add a node'),
  });
}

// A one-line reminder shown on single-node screens while the switcher is on "All nodes"
export function nodeNotice(name) {
  if (state.node !== 'all' || !name) return null;
  return h('p', { class: 'notice' }, 'Showing node ', h('b', {}, name), '. Pick a node in the switcher above to change it.');
}

export function siteHref(node, id, tab) {
  const base = `#/sites/${encodeURIComponent(node)}/${encodeURIComponent(id)}`;
  return tab ? `${base}/${tab}` : base;
}

export function slotPill(slot) {
  return pill(slot, slot === 'green' ? 'green' : 'blue');
}

const ACTIONS = {
  promote: ['Promoted', 'ok'],
  rollback: ['Rolled back', 'warn'],
  switch: ['Switched', 'info'],
  failed: ['Failed', 'bad'],
};

export function actionPill(action) {
  const [label, kind] = ACTIONS[action] || [String(action), 'muted'];
  return pill(label, kind);
}

export function healthKind(status) {
  const text = String(status || '').toUpperCase();
  if (text.startsWith('UP') || text === 'OK') return 'ok';
  if (text.includes('DOWN') || text.includes('FAIL')) return 'bad';
  if (text.includes('MAINT') || text.includes('DRAIN')) return 'warn';
  return 'idle';
}

export function healthDots(servers) {
  if (!servers || !servers.length) return h('span', { class: 'muted' }, 'no targets');
  return h('span', { class: 'dots' }, servers.map((srv) => dot(healthKind(srv.status), `${srv.addr}: ${srv.status}`)));
}

export function settledValue(result) {
  return result.status === 'fulfilled' ? result.value : null;
}

export function listOf(value) {
  if (Array.isArray(value)) return value;
  return (value && value.nodes) || [];
}
