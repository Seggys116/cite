import { h } from '../dom.js';
import { nodeApi } from '../api.js';
import { currentNode, state } from '../state.js';
import {
  pageHeader, button, iconButton, loadInto, card, emptyState, toggle, segmented, toast, withBusy, formatError, skeletonRows,
} from '../ui.js';
import { noNodes, nodeNotice } from './common.js';
import { PLACEHOLDERS } from '../rulelib.js';
import {
  STATUS_CHOICES, blankRow, describeFrom, diffRows, presetRow, rowForError, rowsProblems, rulesToRows,
} from '../redirectlib.js';

function editor(rules, reload, node) {
  const rows = rulesToRows(rules);
  let lastTarget = null;
  const list = h('div', { class: 'redirect-list stack-sm' });
  const save = button('Save changes', { kind: 'primary', iconName: 'check' });
  const discard = button('Discard changes', { onClick: () => reload() });
  const summary = h('p', { class: 'muted', role: 'status', 'aria-live': 'polite' });
  const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const errorSlots = new Map();
  const nodeErrors = new Map();

  const sync = () => {
    const problems = rowsProblems(rows);
    for (const row of rows) {
      const slot = errorSlots.get(row.key);
      if (!slot) continue;
      const message = problems.get(row.key) || nodeErrors.get(row.key) || '';
      slot.textContent = message;
      slot.hidden = !message;
    }
    const diff = diffRows(rows, rules);
    const changes = diff.replace.length + diff.delete.length;
    save.disabled = changes === 0 || problems.size > 0;
    discard.disabled = changes === 0;
    summary.textContent = changes ? `${diff.replace.length} to save, ${diff.delete.length} to delete.` : 'No unsaved changes.';
  };

  function draw(focusKey = '') {
    errorSlots.clear();
    list.replaceChildren();
    if (!rows.length) list.append(emptyState({ iconName: 'swap', title: 'No redirects', text: 'Add a redirect, or use one of the quick actions.' }));
    rows.forEach((row, i) => {
      const n = i + 1;
      const on = toggle({ checked: row.enabled, label: `Enable redirect ${n}`, onChange: (v) => { row.enabled = v; sync(); } });
      let from;
      if (row.simple) {
        const mode = segmented({
          label: `Redirect ${n} matches`, value: row.mode,
          options: [{ value: 'prefix', label: 'Path starts with' }, { value: 'regex', label: 'Path matches regex' }],
          onChange: (v) => { row.mode = v; sync(); },
        });
        const value = h('input', {
          class: 'input mono', type: 'text', value: row.value, placeholder: row.mode === 'regex' ? '^/blog/[0-9]+$' : '/old-page', spellcheck: 'false', autocomplete: 'off', 'aria-label': `Redirect ${n} from`,
        });
        value.addEventListener('input', () => { row.value = value.value; sync(); });
        from = h('div', { class: 'stack-sm' }, mode, value);
        if (focusKey === row.key) queueMicrotask(() => value.focus());
      } else {
        from = h('p', { class: 'muted' }, describeFrom(row));
      }
      const to = h('input', { class: 'input mono', type: 'text', value: row.to, placeholder: 'https://example.com/new{query}', spellcheck: 'false', autocomplete: 'off', 'aria-label': `Redirect ${n} to` });
      to.addEventListener('input', () => { row.to = to.value; sync(); });
      to.addEventListener('focus', () => { lastTarget = { input: to, row }; });
      const status = h('select', { class: 'select', 'aria-label': `Redirect ${n} status`, value: String(row.status) },
        STATUS_CHOICES.map((c) => h('option', { value: String(c) }, String(c))));
      status.addEventListener('change', () => { row.status = Number(status.value); sync(); });
      const remove = iconButton('trash', `Delete redirect ${n}`, () => {
        rows.splice(i, 1);
        draw();
        sync();
      });
      const slot = h('span', { class: 'error-text', role: 'status', 'aria-live': 'polite', hidden: true });
      errorSlots.set(row.key, slot);
      list.append(h('div', { class: 'redirect-row' },
        on, from, h('span', { class: 'redirect-arrow', 'aria-hidden': 'true' }, 'to'), to, status, remove), slot);
    });
  }

  const chips = PLACEHOLDERS.map((token) => h('button', {
    class: 'chip mono', type: 'button', title: `Insert ${token} into the target you last used`, 'aria-label': `Insert ${token}`,
    onClick: () => {
      if (!lastTarget) {
        toast('Click a target first, then a placeholder', 'info');
        return;
      }
      const { input, row } = lastTarget;
      const at = input.selectionStart ?? input.value.length;
      const end = input.selectionEnd ?? at;
      input.value = input.value.slice(0, at) + token + input.value.slice(end);
      row.to = input.value;
      input.focus();
      input.setSelectionRange(at + token.length, at + token.length);
      sync();
    },
  }, token));

  const add = (row) => {
    rows.push(row);
    draw(row.key);
    sync();
  };

  save.addEventListener('click', async () => {
    err.hidden = true;
    nodeErrors.clear();
    const diff = diffRows(rows, rules);
    try {
      const res = await withBusy(save, () => nodeApi(node).post('/firewall/bulk', { replace: diff.replace, delete: diff.delete }));
      toast(`Redirects saved: ${(res && res.created) || 0} added, ${(res && res.replaced) || 0} changed, ${(res && res.deleted) || 0} removed`, 'success');
      reload();
    } catch (ex) {
      const message = formatError(ex);
      const key = rowForError(message, diff.owners);
      if (key) nodeErrors.set(key, message);
      else {
        err.textContent = message;
        err.hidden = false;
      }
      sync();
    }
  });

  draw();
  sync();
  return h('div', { class: 'stack' },
    card({
      title: 'Redirects',
      subtitle: 'Each row sends visitors from one path to another address. Changes are saved together in one step.',
      actions: [
        button('Add redirect', { iconName: 'plus', onClick: () => add(blankRow()) }),
        button('Add www redirect', { onClick: () => add(presetRow('www')) }),
        button('Add https redirect', { onClick: () => add(presetRow('https')) }),
      ],
      body: h('div', { class: 'stack-sm' },
        h('div', { class: 'stack-sm' }, h('span', { class: 'field-label' }, 'Placeholders for the target'), h('div', { class: 'chips' }, chips)),
        list),
    }),
    err,
    h('div', { class: 'form-actions' }, summary, discard, save));
}

export function redirectsView(ctx) {
  ctx.setCrumbs([{ label: 'Firewall', href: '#/firewall' }, { label: 'Redirects' }]);
  const node = currentNode();
  const body = h('div', {});
  ctx.root.append(...[pageHeader({ title: 'Redirects', subtitle: node ? 'Redirects served by ' + node : 'Send visitors from old addresses to new ones' }), nodeNotice(node), body].filter(Boolean));
  if (!node || !state.nodes.length) {
    body.appendChild(noNodes());
    return;
  }
  loadInto(body, () => nodeApi(node).get('/firewall/rules'), (rules, again) => editor(rules, again, node), { skeleton: () => skeletonRows(5) });
}
