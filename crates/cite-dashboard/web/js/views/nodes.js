import { h } from '../dom.js';
import { api } from '../api.js';
import { state, loadNodes, selectNode } from '../state.js';
import {
  pageHeader, button, iconButton, loadInto, card, pill, dataTable, emptyState, field, openDrawer,
  confirmDialog, toast, withBusy, formatError,
} from '../ui.js';

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$/;

// Shared with the command palette, which can open the drawer from any screen
export function openAddNode(onDone) {
  const name = h('input', { class: 'input mono', type: 'text', placeholder: 'edge-fra-1', autocomplete: 'off', spellcheck: 'false' });
  const url = h('input', { class: 'input mono', type: 'url', placeholder: 'https://edge.example.com:8443', autocomplete: 'off', spellcheck: 'false' });
  const token = h('input', { class: 'input mono', type: 'password', placeholder: 'Connector API token', autocomplete: 'off' });
  const ca = h('textarea', { class: 'textarea mono', rows: '6', placeholder: '-----BEGIN CERTIFICATE-----', spellcheck: 'false', 'aria-label': 'Connector CA certificate' });
  const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const save = button('Add node', { kind: 'primary', iconName: 'plus' });
  let drawer = null;

  const fail = (message) => {
    err.textContent = message;
    err.hidden = !message;
  };

  save.addEventListener('click', async () => {
    if (!NAME_RE.test(name.value.trim())) return fail('Use letters, digits, dot, dash or underscore for the node name.');
    if (!/^https?:\/\/\S+$/i.test(url.value.trim())) return fail('The connector URL must start with http:// or https://.');
    if (!token.value.trim()) return fail('Paste an API token created on the node.');
    if (ca.value.trim() && !ca.value.includes('-----BEGIN CERTIFICATE-----')) return fail('The CA certificate must be a PEM block starting with BEGIN CERTIFICATE.');
    fail('');
    try {
      const body = { name: name.value.trim(), url: url.value.trim(), token: token.value.trim() };
      if (ca.value.trim()) body.ca_pem = ca.value.trim();
      await withBusy(save, () => api.post('/nodes', body));
      await loadNodes();
      toast(`Node ${name.value.trim()} added`, 'success');
      drawer.close();
      if (onDone) onDone();
    } catch (ex) {
      fail(formatError(ex));
    }
  });

  drawer = openDrawer({
    title: 'Add node',
    subtitle: 'Register a connector the dashboard can manage.',
    content: h('div', { class: 'form' },
      field('Name', name, 'A short label shown in the node switcher.'),
      field('Connector URL', url, 'Base address of the node connector, without /api/v1.'),
      field('API token', token, 'Stored by the dashboard server and never shown again.'),
      field('CA certificate', ca, 'Optional. The connector ca.pem, needed when the node uses its own certificate authority.'),
      err),
    footer: [button('Cancel', { onClick: () => drawer.close() }), save],
  });
}

function render(nodes, reload) {
  const table = dataTable({
    columns: [
      { label: 'Name', render: (n) => h('b', { class: 'cell-strong' }, n.name) },
      { label: 'Connector', render: (n) => h('span', { class: 'mono muted' }, n.url) },
      { label: 'Status', render: (n) => (n.online ? pill('Online', 'ok') : pill('Offline', 'bad')) },
      { label: 'Version', render: (n) => h('span', { class: 'mono' }, n.version ? 'v' + n.version : '-') },
      {
        label: '',
        align: 'right',
        render: (n) => h('div', { class: 'row-actions' },
          button('Open', { size: 'sm', onClick: () => { selectNode(n.name); location.hash = '#/sites'; } }),
          iconButton('trash', 'Remove node ' + n.name, async () => {
            const ok = await confirmDialog({
              title: 'Remove node',
              message: `Remove ${n.name} from the dashboard? The node keeps running and serving traffic; only this console forgets it.`,
              confirmLabel: 'Remove node',
              danger: true,
            });
            if (!ok) return;
            try {
              await api.del('/nodes/' + encodeURIComponent(n.name));
              await loadNodes();
              toast(`Node ${n.name} removed`, 'success');
              reload();
            } catch (ex) {
              toast(formatError(ex), 'error');
            }
          })),
      },
    ],
    rows: nodes,
    empty: emptyState({
      iconName: 'server',
      title: 'No nodes yet',
      text: 'A node is a server running the Cite connector. Add one with its URL and an API token.',
      action: button('Add node', { kind: 'primary', iconName: 'plus', onClick: () => openAddNode(reload) }),
    }),
  });
  return card({ flush: true, body: table });
}

export function nodesView(ctx) {
  ctx.setCrumbs([{ label: 'Nodes' }]);
  const body = h('div', {});
  let reload = null;
  const add = button('Add node', { kind: 'primary', iconName: 'plus', onClick: () => openAddNode(() => reload()) });
  ctx.root.append(pageHeader({ title: 'Nodes', subtitle: 'Connectors this console manages', actions: add }), body);
  reload = loadInto(body, async () => {
    await loadNodes();
    return state.nodes;
  }, render);
}
