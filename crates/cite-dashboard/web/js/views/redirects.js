import { h } from '../dom.js';
import { nodeApi } from '../api.js';
import { state } from '../state.js';
import {
  pageHeader, button, iconButton, loadInto, card, emptyState, pill, toggle, segmented, toast, withBusy, formatError, skeletonRows,
} from '../ui.js';
import { noNodes, listOf } from './common.js';
import {
  onlineNodes, readNodes, scopeLine, scopeNodes,
} from './firewall.js';
import { pickTargets } from './targetDialog.js';
import { applyToNodes, resultKind, resultMessage } from '../targetlib.js';
import {
  bulkBodyFor, enabledDiffers, mergeRules, unreachableNote,
} from '../firewalllib.js';
import { PLACEHOLDERS } from '../rulelib.js';
import {
  STATUS_CHOICES, blankRow, describeFrom, diffRows, presetRow, rowForError, rowsProblems, rulesToRows,
} from '../redirectlib.js';

// rules is one copy of every rule id across the nodes read; heldByNode maps each reachable node to Map(rule id -> its own stored rule)
function editor({ rules, heldByNode, down, differing }, reload) {
  const rows = rulesToRows(rules);
  const note = unreachableNote(down);
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
      const mixed = h('p', {
        class: 'fw-mixed', title: 'This redirect is on at some nodes and off at others. Saving keeps each node as it is unless you use the switch.',
      }, pill('differs by node', 'warn'));
      mixed.hidden = !row.id || row.enabledTouched || !enabledDiffers(row.id, heldByNode);
      const on = toggle({
        checked: row.enabled,
        label: `Enable redirect ${n}`,
        onChange: (v) => {
          row.enabled = v;
          row.enabledTouched = true;
          mixed.hidden = true;
          sync();
        },
      });
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
        on, from, h('span', { class: 'redirect-arrow', 'aria-hidden': 'true' }, 'to'), to, status, remove), mixed, slot);
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
    const only = onlineNodes().filter((name) => heldByNode.has(name));
    if (!only.length) {
      err.textContent = 'No node is online to save to.';
      err.hidden = false;
      return;
    }
    const picked = await pickTargets({
      title: 'Save redirects',
      message: `${diff.replace.length} to save, ${diff.delete.length} to delete.`,
      verb: 'Save redirects',
      scope: state.node,
      only,
    });
    if (!picked) return;
    // Each node gets its own body: its stored copy and its own on/off state, changed only where the switch was touched
    const touched = new Set(rows.filter((row) => row.enabledTouched && row.id).map((row) => row.id));
    const results = await withBusy(save, () => applyToNodes(picked, (name) => nodeApi(name).post('/firewall/bulk', bulkBodyFor(name, diff, touched, heldByNode))));
    const lines = [];
    for (const r of results.filter((x) => !x.ok)) {
      const message = formatError(r.error);
      const key = rowForError(message, diff.owners);
      if (key) nodeErrors.set(key, `${r.node}: ${message}`);
      else lines.push(`${r.node}: ${message}`);
    }
    err.textContent = lines.join('. ');
    err.hidden = lines.length === 0;
    if (results.some((r) => r.ok)) {
      toast(resultMessage('Redirects saved', results, formatError), resultKind(results));
      reload();
      return;
    }
    sync();
  });

  draw();
  sync();
  return h('div', { class: 'stack' },
    note ? h('p', { class: 'notice warn', role: 'status' }, note) : null,
    differing.length ? h('p', { class: 'notice warn', role: 'status' }, `${differing.join(', ')} differ between nodes; the first copy is shown.`) : null,
    card({
      title: 'Redirects',
      subtitle: 'Each row sends visitors from one path to another address. Changes are saved together.',
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
  const body = h('div', {});
  ctx.root.append(pageHeader({ title: 'Redirects', subtitle: scopeLine() }), body);
  if (!state.nodes.length) {
    body.appendChild(noNodes());
    return;
  }
  const names = scopeNodes();
  loadInto(body, async () => {
    const results = await readNodes(names, '/firewall/rules');
    const reached = results.filter((r) => r.ok);
    if (!reached.length) throw results[0].error;
    const perNode = reached.map((r) => ({ node: r.node, rules: listOf(r.value) }));
    const rows = mergeRules(perNode);
    const seen = new Set();
    const rules = [];
    for (const row of rows) {
      if (seen.has(row.id)) continue;
      seen.add(row.id);
      rules.push(row.rule);
    }
    return {
      rules,
      heldByNode: new Map(perNode.map((p) => [p.node, new Map(p.rules.map((r) => [r.id, r]))])),
      down: results.filter((r) => !r.ok).map((r) => r.node),
      differing: [...new Set(rows.filter((r) => r.differs && r.rule.redirect).map((r) => r.rule.name))],
    };
  }, (data, again) => editor(data, again), { skeleton: () => skeletonRows(5) });
}
