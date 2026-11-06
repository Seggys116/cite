import { h } from '../dom.js';
import { nodeApi } from '../api.js';
import {
  button, card, confirmDialog, loadInto, pill, toast, withBusy, formatError, skeletonBlock,
} from '../ui.js';
import {
  changedLabels, firstSourceProblem, formToSource, needsRebuild, sourceDiff, sourceToForm,
} from '../buildlib.js';
import { siteBody } from '../sitelib.js';
import { makeDirty } from '../dirtylib.js';
import {
  addProblem, buildPatch, emptyPending, pendingCount, pendingSummary,
} from '../envlib.js';
import {
  canUseNodeToken, nodeTokenNote, tokenHealth, tokenInputProblem, tokenSourceText,
} from '../tokenlib.js';
import { sourceFields } from './sourceFields.js';
import { askRebuild, deployWithToasts } from './deployFlow.js';

const noAutofill = {
  autocomplete: 'new-password', spellcheck: 'false', autocapitalize: 'off', 'data-lpignore': 'true', 'data-1p-ignore': 'true', 'data-bwignore': 'true', 'data-form-type': 'other',
};

// What the manager detected is shown as the default; the Status panel calls handle.setDetected(d) when it learns it.
export function buildSettingsCard({ node, site, info, onSaved, onStatusChange }) {
  const form = sourceToForm(site.source);
  const fields = sourceFields({ form, info, advancedOpen: false });
  const dirty = makeDirty(() => form);
  const badge = pill('Unsaved changes', 'warn');
  badge.hidden = true;
  const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const save = button('Save build settings', { kind: 'primary', iconName: 'check' });
  const reset = button('Discard changes', { onClick: () => {
    Object.assign(form, sourceToForm(site.source));
    fields.refresh();
    update();
  } });
  const update = () => {
    const d = dirty.dirty();
    badge.hidden = !d;
    save.disabled = !d;
    reset.disabled = !d;
    if (onStatusChange) onStatusChange(d);
  };
  fields.el.addEventListener('input', update);
  fields.el.addEventListener('change', update);
  update();

  save.addEventListener('click', async () => {
    err.hidden = true;
    const bad = firstSourceProblem(form);
    if (bad) {
      fields.touchAll();
      fields.focusField(bad.field);
      err.textContent = bad.message;
      err.hidden = false;
      return;
    }
    const next = formToSource(form, site.source);
    const changed = sourceDiff(site.source, next);
    try {
      await withBusy(save, () => nodeApi(node).put(`/sites/${encodeURIComponent(site.id)}`, siteBody(site, { source: next })));
      toast('Build settings saved', 'success');
    } catch (ex) {
      err.textContent = formatError(ex);
      err.hidden = false;
      return;
    }
    dirty.reset();
    update();
    // Asked every time: a change to how the site is built does nothing until a build runs
    if (needsRebuild(changed) && await askRebuild(changedLabels(changed))) {
      await deployWithToasts({ node, siteId: site.id, info }, { onAfter: () => onSaved(true) });
      return;
    }
    onSaved(false);
  });

  const el = card({
    title: 'Build settings',
    subtitle: 'Where the code comes from and how it is built. Leave a field on Auto to use what the manager detects.',
    actions: badge,
    body: h('div', { class: 'form' }, fields.el, err, h('div', { class: 'form-actions' }, reset, save)),
  });
  return { el, setDetected: (d) => fields.setDetected(d), dirty: () => dirty.dirty() };
}

// Names are listed from the node; a value can only be typed in, never read back. Typed values live in one Map until saved, then are dropped.
export function envCard({ node, siteId, which, title, subtitle, note }) {
  const base = `/sites/${encodeURIComponent(siteId)}/${which}`;
  const body = h('div', {});
  const list = h('div', {});
  let names = [];
  let pending = emptyPending();
  let revealed = new Set();
  const wipe = () => {
    pending = emptyPending();
    revealed = new Set();
  };

  const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const summary = h('span', { class: 'muted', role: 'status', 'aria-live': 'polite' });
  const save = button('Save variables', { kind: 'primary', iconName: 'check' });
  const discard = button('Discard', { onClick: () => { wipe(); draw(); } });

  const nameInput = h('input', { class: 'input mono', type: 'text', placeholder: 'NAME', spellcheck: 'false', autocomplete: 'off', autocapitalize: 'characters', 'aria-label': 'New variable name' });
  const valueInput = h('input', { class: 'input mono', type: 'password', placeholder: 'Value', 'aria-label': 'New variable value', ...noAutofill });
  const addErr = h('span', { class: 'error-text', role: 'status', 'aria-live': 'polite', hidden: true });
  const add = button('Add', { size: 'sm', iconName: 'plus' });
  add.addEventListener('click', () => {
    const name = nameInput.value.trim();
    const bad = addProblem(name, valueInput.value, names, [...pending.set.keys()]);
    addErr.textContent = bad || '';
    addErr.hidden = !bad;
    if (bad) return;
    pending.set.set(name, valueInput.value);
    nameInput.value = '';
    valueInput.value = '';
    draw();
    nameInput.focus();
  });

  function refreshState() {
    const count = pendingCount(pending);
    summary.textContent = pendingSummary(pending);
    save.disabled = count === 0;
    discard.disabled = count === 0;
  }

  function rowFor(name) {
    const removing = pending.unset.has(name);
    const replacing = pending.set.has(name);
    const value = h('input', { class: 'input mono', type: 'password', placeholder: 'New value', 'aria-label': `New value for ${name}`, ...noAutofill });
    value.hidden = !revealed.has(name);
    value.addEventListener('input', () => {
      if (value.value) pending.set.set(name, value.value);
      else pending.set.delete(name);
      refreshState();
    });
    const replace = button(value.hidden ? 'Replace value' : 'Cancel', { size: 'sm' });
    replace.addEventListener('click', () => {
      if (revealed.has(name)) {
        revealed.delete(name);
        pending.set.delete(name);
      } else {
        revealed.add(name);
      }
      draw();
    });
    const remove = button(removing ? 'Keep' : 'Remove', { size: 'sm', kind: removing ? 'default' : 'danger' });
    remove.addEventListener('click', () => {
      if (removing) pending.unset.delete(name);
      else {
        pending.unset.add(name);
        pending.set.delete(name);
        revealed.delete(name);
      }
      draw();
    });
    return h('div', { class: `env-row${removing ? ' removing' : ''}` },
      h('code', { class: 'mono env-name' }, name),
      removing ? pill('Will be removed', 'warn') : replacing ? pill('Will be replaced', 'info') : h('span', { class: 'muted' }, 'value stored'),
      removing ? null : value, removing ? null : replace, remove);
  }

  function draw() {
    const added = [...pending.set.keys()].filter((n) => !names.includes(n));
    list.replaceChildren(
      names.length || added.length
        ? h('div', { class: 'stack-sm' }, names.map(rowFor), added.map((name) => h('div', { class: 'env-row' },
          h('code', { class: 'mono env-name' }, name), pill('New', 'info'), h('span', { class: 'muted' }, 'value hidden'),
          button('Undo', { size: 'sm', onClick: () => { pending.set.delete(name); draw(); } }))))
        : h('p', { class: 'muted' }, 'No variables are set.'),
      h('div', { class: 'env-add' }, nameInput, valueInput, add), addErr);
    refreshState();
  }

  save.addEventListener('click', async () => {
    err.hidden = true;
    const built = buildPatch(pending, names);
    if (built.problem) {
      err.textContent = built.problem;
      err.hidden = false;
      return;
    }
    const removing = built.patch.unset.length;
    if (removing && !(await confirmDialog({ title: 'Remove variables', message: `Remove ${removing} variable${removing === 1 ? '' : 's'}? The next build will not have ${removing === 1 ? 'it' : 'them'}.`, confirmLabel: 'Remove', danger: true }))) return;
    try {
      const res = await withBusy(save, () => nodeApi(node).patch(base, built.patch));
      names = Array.isArray(res && res.names) ? res.names : names;
      toast('Variables saved. They apply on the next build.', 'success');
      // The values are dropped as soon as the node has them
      built.patch.set = {};
      wipe();
      load();
    } catch (ex) {
      err.textContent = formatError(ex);
      err.hidden = false;
    }
  });

  const el = card({ title, subtitle, body: h('div', { class: 'stack-sm' }, note ? h('p', { class: 'muted' }, note) : null, body, err, h('div', { class: 'form-actions' }, summary, discard, save)) });

  function load() {
    loadInto(body, async () => {
      const res = await nodeApi(node).get(base);
      names = Array.isArray(res && res.names) ? res.names : [];
      return names;
    }, () => {
      draw();
      return list;
    }, { skeleton: () => skeletonBlock(60) });
  }
  load();
  // Values still in the boxes are wiped when the page route changes, which includes switching tabs
  const leave = () => {
    wipe();
    valueInput.value = '';
    for (const box of list.querySelectorAll('input[type="password"]')) box.value = '';
    window.removeEventListener('hashchange', leave);
  };
  window.addEventListener('hashchange', leave);
  return { el };
}

// The per-site GitHub token. It is write-only: the box is emptied as soon as the request leaves.
export function tokenCard({ node, siteId, onChanged }) {
  const base = `/sites/${encodeURIComponent(siteId)}/github-token`;
  const body = h('div', {});
  const content = h('div', { class: 'stack-sm' });
  const input = h('input', { class: 'input mono', type: 'password', placeholder: 'Paste a token', 'aria-label': 'Site GitHub token', ...noAutofill });
  const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const set = button('Set token', { kind: 'primary', iconName: 'check' });
  const useNode = button('Use the node token', { iconName: 'refresh' });
  let status = null;

  function draw() {
    const health = tokenHealth(status);
    const noteText = nodeTokenNote(status);
    content.replaceChildren(
      h('p', {}, tokenSourceText(status)),
      health.text ? h('p', { class: health.kind === 'bad' ? 'error-text' : 'muted' }, health.text) : null,
      h('div', { class: 'field' }, h('span', { class: 'field-label' }, status && status.site_token_set ? 'Change the site token' : 'Set a token for this site'), input,
        h('span', { class: 'hint' }, 'Fine-grained and read-only for the one repository. The node tests it with the git host before storing it, and never shows it again.')),
      err,
      h('div', { class: 'form-actions' }, canUseNodeToken(status) ? useNode : null, set),
      noteText ? h('p', { class: 'muted' }, noteText) : null);
  }

  set.addEventListener('click', async () => {
    err.hidden = true;
    const bad = tokenInputProblem(input.value);
    if (bad) {
      err.textContent = bad;
      err.hidden = false;
      return;
    }
    const token = input.value.trim();
    input.value = '';
    try {
      status = await withBusy(set, () => nodeApi(node).put(base, { token }));
      toast('Token saved', 'success');
      if (onChanged) onChanged();
      draw();
    } catch (ex) {
      err.textContent = formatError(ex);
      err.hidden = false;
    }
  });

  useNode.addEventListener('click', async () => {
    const ok = await confirmDialog({ title: 'Use the node token', message: 'The site token is removed and the site fetches with the node token from now on.', confirmLabel: 'Use node token' });
    if (!ok) return;
    try {
      await withBusy(useNode, () => nodeApi(node).del(base));
      toast('The site now uses the node token', 'success');
      if (onChanged) onChanged();
      reload();
    } catch (ex) {
      err.textContent = formatError(ex);
      err.hidden = false;
    }
  });

  const el = card({ title: 'GitHub token', subtitle: 'Used to fetch a private repository and to avoid rate limits.', body });
  const reload = () => loadInto(body, () => nodeApi(node).get(base), (res) => {
    status = res || {};
    draw();
    return content;
  }, { skeleton: () => skeletonBlock(60) });
  reload();
  // The box is emptied when the page route changes, so a half-typed token never lingers
  const leave = () => {
    input.value = '';
    window.removeEventListener('hashchange', leave);
  };
  window.addEventListener('hashchange', leave);
  return { el };
}
