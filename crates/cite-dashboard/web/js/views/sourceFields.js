import { h, debounce } from '../dom.js';
import { button } from '../ui.js';
import {
  FIELD_LABELS, NODE_MAJORS, PACKAGE_MANAGERS, RENDERINGS, RUNTIMES, autoHint, sourceProblems,
} from '../buildlib.js';
import { branchSuggestion, forgeHint, parseRepo, repoSummary } from '../repolib.js';

const option = (value, label) => h('option', { value }, label);
const VALIDATE_MS = 120;

// One labelled control with its own error line; only that line changes while typing
function row(key, control, help) {
  const error = h('span', { class: 'error-text', role: 'status', 'aria-live': 'polite', hidden: true });
  const wrap = h('div', { class: 'field', 'data-field': key },
    h('label', { class: 'field-label' }, FIELD_LABELS[key]), control, help ? h('span', { class: 'hint' }, help) : null, error);
  wrap.querySelector('label').addEventListener('click', () => control.focus());
  return { key, wrap, error };
}

// Build settings shared by the create wizard and the site page; the form object is edited in place.
export function sourceFields({ form, info = null, detected = null, advancedOpen = false, onChange }) {
  const rows = new Map();
  const inputs = new Map();
  const touched = new Set();
  let hints = detected;

  const changed = (key) => {
    touched.add(key);
    validate();
    if (onChange) onChange(key);
  };

  // A field that was never touched and is still empty is not scolded; everything shows after touchAll()
  const validate = debounce(() => {
    const problems = sourceProblems(form);
    for (const [key, r] of rows) {
      const show = touched.has(key) || String(form[key] ?? '').trim() !== '';
      const message = show ? (problems[key] || '') : '';
      r.error.textContent = message;
      r.error.hidden = !message;
      const input = inputs.get(key);
      if (input) input.setAttribute('aria-invalid', message ? 'true' : 'false');
    }
  }, VALIDATE_MS);

  function text(key, { placeholder = '', mono = true, help = '' } = {}) {
    const input = h('input', {
      class: mono ? 'input mono' : 'input', type: 'text', value: form[key], placeholder, spellcheck: 'false', autocomplete: 'off', autocapitalize: 'off', 'aria-label': FIELD_LABELS[key],
    });
    input.addEventListener('input', () => {
      form[key] = input.value;
      changed(key);
    });
    inputs.set(key, input);
    const r = row(key, input, help);
    rows.set(key, r);
    return r;
  }

  function select(key, items, { autoLabel = '' } = {}) {
    const el = h('select', { class: 'select', 'aria-label': FIELD_LABELS[key], value: form[key] },
      autoLabel ? option('', autoLabel) : null, items.map(([v, label]) => option(v, label)));
    el.addEventListener('change', () => {
      form[key] = el.value;
      changed(key);
    });
    inputs.set(key, el);
    const r = row(key, el);
    rows.set(key, r);
    return r;
  }

  // Repository: a pasted address is turned into owner/name when the field loses focus, and what was understood is shown beneath it
  const repo = text('repo', { placeholder: 'owner/name or https://github.com/owner/name' });
  const repoNote = h('span', { class: 'hint', role: 'status', 'aria-live': 'polite' });
  const branchHint = h('span', { class: 'hint', hidden: true });
  const useBranch = button('Use suggested branch', { size: 'sm' });
  branchHint.append(useBranch);
  repo.wrap.append(repoNote, branchHint);
  const showRepoNote = () => {
    const parsed = parseRepo(form.repo);
    const hint = forgeHint(parsed, info);
    repoNote.textContent = [repoSummary(parsed) && parsed.repo !== form.repo.trim() ? repoSummary(parsed) : '', hint].filter(Boolean).join('. ');
    const suggestion = branchSuggestion(parsed, form.branch);
    branchHint.hidden = !suggestion;
    useBranch.querySelector('span').textContent = suggestion ? `Use branch ${suggestion}` : '';
    useBranch.onclick = () => {
      if (!suggestion) return;
      form.branch = suggestion;
      inputs.get('branch').value = suggestion;
      branchHint.hidden = true;
      changed('branch');
    };
  };
  const repoInput = inputs.get('repo');
  repoInput.addEventListener('input', showRepoNote);
  repoInput.addEventListener('blur', () => {
    const parsed = parseRepo(form.repo);
    if (parsed.ok && parsed.repo !== form.repo.trim()) {
      form.repo = parsed.repo;
      repoInput.value = parsed.repo;
      showRepoNote();
      changed('repo');
    }
  });
  showRepoNote();

  const branch = text('branch', { placeholder: 'main' });
  const runtime = select('runtime', RUNTIMES.map((r) => [r, r]));
  const major = select('node_major', NODE_MAJORS.map((m) => [String(m), `Node ${m}`]));
  const poll = text('poll_interval', { placeholder: '5m', help: 'Such as 5m, 1h or 1d. Use off to check only when you deploy.' });
  const syncMajor = () => {
    major.wrap.hidden = form.runtime === 'rust';
  };
  inputs.get('runtime').addEventListener('change', syncMajor);
  syncMajor();

  const root = text('root_dir', { placeholder: 'Auto' });
  const pm = select('package_manager', PACKAGE_MANAGERS.map((p) => [p, p]), { autoLabel: 'Auto' });
  const install = text('install_command', { placeholder: 'Auto' });
  const build = text('build_command', { placeholder: 'Auto' });
  const out = text('output_dir', { placeholder: 'Auto' });
  const rendering = select('rendering', RENDERINGS.map((r) => [r, r]), { autoLabel: 'Auto' });
  const start = text('start_command', { placeholder: 'Auto', help: 'Server rendering only. One program with arguments, run without a shell.' });
  const spa = text('spa_fallback', { placeholder: 'Auto', help: 'The file served for unknown paths so client-side routes survive a reload.' });
  const framework = text('framework', { placeholder: 'Auto' });
  const prune = select('prune', [['true', 'Yes'], ['false', 'No']], { autoLabel: 'Auto' });
  const advancedRows = [root, pm, install, build, out, rendering, start, spa, framework, prune];

  // An unset field says what the manager picked on its own, so "Auto" is never a blank
  const applyHints = () => {
    for (const r of advancedRows) {
      const input = inputs.get(r.key);
      const hint = autoHint(r.key, hints);
      if (input.tagName === 'INPUT') input.placeholder = hint;
      else if (input.options.length && input.options[0].value === '') input.options[0].textContent = hint;
    }
  };
  applyHints();

  const advanced = h('div', { class: 'stack-sm', hidden: !advancedOpen }, h('div', { class: 'two-col' }, advancedRows.map((r) => r.wrap)));
  const toggleBtn = button(advancedOpen ? 'Hide build settings' : 'Show build settings', { size: 'sm' });
  toggleBtn.addEventListener('click', () => {
    advanced.hidden = !advanced.hidden;
    toggleBtn.querySelector('span').textContent = advanced.hidden ? 'Show build settings' : 'Hide build settings';
    toggleBtn.setAttribute('aria-expanded', String(!advanced.hidden));
  });
  toggleBtn.setAttribute('aria-expanded', String(advancedOpen));

  const el = h('div', { class: 'form' },
    repo.wrap,
    h('div', { class: 'two-col' }, branch.wrap, poll.wrap),
    h('div', { class: 'two-col' }, runtime.wrap, major.wrap),
    h('div', {}, toggleBtn), advanced);
  validate();

  return {
    el,
    // Writes a new value into the form and the control, for programmatic resets
    set(key, value) {
      form[key] = value;
      const input = inputs.get(key);
      if (input) input.value = value;
      if (key === 'runtime') syncMajor();
      validate();
    },
    refresh() {
      for (const [key, input] of inputs) input.value = form[key];
      syncMajor();
      showRepoNote();
      validate();
    },
    setDetected(next) {
      hints = next;
      applyHints();
    },
    setInfo(next) {
      info = next;
      showRepoNote();
    },
    problems: () => sourceProblems(form),
    touchAll() {
      for (const key of rows.keys()) touched.add(key);
      validate();
    },
    openAdvanced() {
      advanced.hidden = false;
      toggleBtn.setAttribute('aria-expanded', 'true');
      toggleBtn.querySelector('span').textContent = 'Hide build settings';
    },
    focusField(key) {
      const input = inputs.get(key);
      if (input) {
        const wrap = rows.get(key).wrap;
        if (advancedRows.some((r) => r.key === key)) this.openAdvanced();
        wrap.scrollIntoView({ block: 'center' });
        input.focus();
      }
    },
  };
}
