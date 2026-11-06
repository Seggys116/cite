import { h } from '../dom.js';
import { button, iconButton } from '../ui.js';
import { KEEP_SECRET_NOTE } from '../rulelib.js';
import {
  CONDITION_TYPES, emptyHeader, newRow, rowProblem, typeOf,
} from '../conditionlib.js';

const option = (value, label) => h('option', { value }, label);

// The header test of one row; a secret value goes in a password box and is never filled back in
function headerEditor(row, changed, label) {
  const hd = row.header;
  const name = h('input', { class: 'input mono', type: 'text', value: hd.name, placeholder: 'X-Env', spellcheck: 'false', autocomplete: 'off', 'aria-label': `${label} header name` });
  const mode = h('select', { class: 'select', 'aria-label': `${label} header test`, value: hd.mode }, option('equals', 'Equals'), option('regex', 'Matches regex'));
  const value = h('input', {
    class: 'input mono', type: 'text', value: hd.value, spellcheck: 'false', autocomplete: 'new-password', autocapitalize: 'off',
    'data-lpignore': 'true', 'data-1p-ignore': 'true', 'data-bwignore': 'true', 'data-form-type': 'other', 'aria-label': `${label} header value`,
  });
  const negate = h('input', { type: 'checkbox', checked: hd.negate, 'aria-label': `${label} matches when the test fails` });
  const secret = h('input', { type: 'checkbox', checked: hd.secret, 'aria-label': `${label} treat the value as a secret` });
  const hint = h('span', { class: 'hint' });
  const sync = () => {
    value.type = hd.secret && hd.mode === 'equals' ? 'password' : 'text';
    secret.disabled = hd.mode === 'regex';
    value.placeholder = hd.secret && hd.stored ? 'Unchanged' : '';
    hint.textContent = hd.secret && hd.stored ? KEEP_SECRET_NOTE : hd.secret ? 'The value is not shown again after you save.' : '';
  };
  name.addEventListener('input', () => { hd.name = name.value; changed(); });
  value.addEventListener('input', () => { hd.value = value.value; changed(); });
  mode.addEventListener('change', () => {
    hd.mode = mode.value;
    if (hd.mode === 'regex') {
      hd.secret = false;
      secret.checked = false;
    }
    sync();
    changed();
  });
  negate.addEventListener('change', () => { hd.negate = negate.checked; changed(); });
  secret.addEventListener('change', () => { hd.secret = secret.checked; sync(); changed(); });
  sync();
  return h('div', { class: 'cond-header stack-sm' },
    h('div', { class: 'three-col' }, name, mode, value),
    h('div', { class: 'pill-row' },
      h('label', { class: 'check-row' }, negate, h('span', {}, 'Match when the test fails')),
      h('label', { class: 'check-row' }, secret, h('span', {}, 'Secret value'))),
    hint);
}

// A list of condition rows. Rows of one type are OR'd and different types AND'd by whoever reads the rows; this only edits them.
export function conditionList({
  rows, types = CONDITION_TYPES.map((t) => t.id), onChange, label = 'Condition', addLabel = 'Add another condition',
}) {
  const root = h('div', { class: 'cond-list stack-sm' });
  const allowed = CONDITION_TYPES.filter((t) => types.includes(t.id));
  const changed = () => {
    if (onChange) onChange(rows);
  };

  function draw(focusIndex = -1) {
    root.replaceChildren();
    rows.forEach((row, i) => {
      const name = `${label} ${i + 1}`;
      const type = h('select', { class: 'select', 'aria-label': `${name} type`, value: row.type }, allowed.map((t) => option(t.id, t.label)));
      const error = h('span', { class: 'error-text', role: 'status', 'aria-live': 'polite', hidden: true });
      const check = () => {
        const bad = rowProblem(row);
        error.textContent = bad || '';
        error.hidden = !bad;
        changed();
      };
      let valueEl;
      if (row.type === 'header') {
        valueEl = headerEditor(row, check, name);
      } else if (row.type === 'scheme') {
        valueEl = h('select', { class: 'select', 'aria-label': `${name} value`, value: row.value }, option('', 'Choose'), option('http', 'http'), option('https', 'https'));
        valueEl.addEventListener('change', () => { row.value = valueEl.value; check(); });
      } else {
        valueEl = h('input', {
          class: 'input mono', type: 'text', value: row.value, placeholder: typeOf(row.type).placeholder, spellcheck: 'false', autocomplete: 'off', 'aria-label': `${name} value`,
        });
        valueEl.addEventListener('input', () => { row.value = valueEl.value; check(); });
      }
      type.addEventListener('change', () => {
        const fresh = newRow(type.value);
        row.type = fresh.type;
        row.value = '';
        row.header = emptyHeader();
        draw(i);
        changed();
      });
      const remove = iconButton('x', `Remove ${name.toLowerCase()}`, () => {
        rows.splice(i, 1);
        draw(-2);
        changed();
      });
      root.append(h('div', { class: 'cond-row' }, h('div', { class: 'cond-fields' }, type, valueEl), remove), error);
      if (rowProblem(row)) check();
      if (focusIndex === i) (valueEl.querySelector ? (valueEl.querySelector('input,select') || valueEl) : valueEl).focus();
    });
    const add = button(addLabel, {
      size: 'sm', iconName: 'plus',
      onClick: () => {
        rows.push(newRow(allowed[0].id));
        draw(rows.length - 1);
        changed();
      },
    });
    root.append(h('div', {}, add));
    if (focusIndex === -2) add.focus();
  }
  draw();
  return { el: root, redraw: () => draw() };
}
