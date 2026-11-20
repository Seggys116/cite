import { h } from '../dom.js';
import { state } from '../state.js';
import { openModal, button, pill } from '../ui.js';
import {
  canConfirm, confirmLabel, initialTargets, normalizeTargets, notTargeted, targetSummary, toggleTarget,
} from '../targetlib.js';

// Asks which nodes a change lands on. Resolves with the chosen node names, or null when cancelled.
// With "All nodes" selected nothing is ticked, so a write can never reach a node the person did not pick.
export function pickTargets({
  title, message, verb = 'Apply', scope = state.node, nodes = state.nodes, danger = false, only = null,
}) {
  return new Promise((resolve) => {
    let selected = initialTargets(scope, nodes);
    // `only` limits the choices to nodes that can take the change, for example nodes that hold the site
    const choices = only ? nodes.filter((n) => only.includes(n.name)) : nodes;
    let decided = false;
    const finish = (value) => {
      if (decided) return;
      decided = true;
      modal.close();
      resolve(value);
    };
    const summary = h('p', { class: 'target-summary', role: 'status' });
    const confirm = button(verb, { kind: danger ? 'danger' : 'primary', onClick: () => finish(normalizeTargets(selected, choices)) });
    const list = h('div', { class: 'target-list', role: 'group', 'aria-label': 'Nodes' });
    const rows = new Map();
    const refresh = () => {
      for (const [name, row] of rows) {
        const on = selected.includes(name);
        row.setAttribute('aria-checked', String(on));
        row.classList.toggle('on', on);
      }
      const picked = normalizeTargets(selected, choices);
      const rest = notTargeted(picked, choices);
      summary.textContent = picked.length
        ? `Will change ${targetSummary(picked, choices)}.${rest.length ? ` Not changed: ${rest.join(', ')}.` : ''}`
        : 'Pick at least one node.';
      confirm.disabled = !canConfirm(picked, choices);
      confirm.querySelector('span').textContent = confirmLabel(verb, picked, choices);
    };
    for (const node of choices) {
      const row = h('button', {
        class: 'target-row', type: 'button', role: 'checkbox', 'aria-checked': 'false', disabled: node.online === false,
        onClick: () => {
          selected = toggleTarget(selected, node.name);
          refresh();
        },
      }, h('span', { class: 'target-box', 'aria-hidden': 'true' }), h('span', { class: 'target-name' }, node.name),
      node.online === false ? pill('Offline', 'warn') : null);
      rows.set(node.name, row);
      list.appendChild(row);
    }
    const modal = openModal({
      title,
      content: h('div', { class: 'target-dialog' }, message ? h('p', { class: 'dialog-text' }, message) : null, list, summary),
      actions: [button('Cancel', { onClick: () => finish(null) }), confirm],
      onClose: () => finish(null),
    });
    refresh();
  });
}
