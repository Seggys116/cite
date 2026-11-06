import { h } from '../dom.js';
import { nodeApi } from '../api.js';
import {
  button, field, iconButton, kvList, openDrawer, toast, formatError, newId,
} from '../ui.js';
import {
  KINDS, STEPS, buildRule, emptyForm, reviewLines, ruleToForm, stepProblem,
} from '../rulebuilder.js';
import { PLACEHOLDERS, REDIRECT_STATUSES, corsFromForm, corsProblem, parseTemplate } from '../rulelib.js';
import { describeRows } from '../conditionlib.js';
import { conditionList } from './conditions.js';
import { wizard } from './wizard.js';

const ACTIONS = [
  { value: 'deny', label: 'Deny', text: 'Answer with 403 Forbidden. Clear to the client and cheap for the edge.' },
  { value: 'drop', label: 'Drop silently', text: 'Close the connection with no reply at all, so scanners learn nothing.' },
  { value: 'tarpit', label: 'Tarpit', text: 'Hold the connection open and answer slowly to waste the scanner\'s time.' },
];

const option = (value, label) => h('option', { value }, label);

function choiceCards(name, items, current, onPick) {
  return h('div', { class: 'choice-cards', role: 'radiogroup', 'aria-label': name }, items.map((item) => {
    const radio = h('input', { type: 'radio', name, value: item.value, checked: item.value === current, onChange: () => onPick(item.value) });
    return h('label', { class: 'radio-card' }, radio, h('div', {}, h('b', {}, item.label), h('p', { class: 'muted' }, item.text)));
  }));
}

// Target template with placeholder chips that insert themselves at the cursor
function redirectDetails(form, refresh) {
  const to = h('input', { class: 'input mono', type: 'text', value: form.redirect.to, placeholder: '{scheme}://{www_host}{path}{query}', spellcheck: 'false', autocomplete: 'off', 'aria-label': 'Redirect target' });
  const status = h('select', { class: 'select', 'aria-label': 'Redirect status', value: String(form.redirect.status) },
    REDIRECT_STATUSES.map((code) => option(String(code), `${code} ${code === 301 || code === 308 ? 'permanent' : 'temporary'}`)));
  const note = h('span', { class: 'error-text', role: 'status', 'aria-live': 'polite', hidden: true });
  const check = () => {
    form.redirect.to = to.value;
    const parsed = to.value ? parseTemplate(to.value) : {};
    note.textContent = parsed.error ? `The target ${parsed.error}.` : '';
    note.hidden = !parsed.error;
    refresh();
  };
  to.addEventListener('input', check);
  status.addEventListener('change', () => { form.redirect.status = Number(status.value); refresh(); });
  const chips = PLACEHOLDERS.map((token) => h('button', {
    class: 'chip mono', type: 'button', title: `Insert ${token}`, 'aria-label': `Insert ${token}`,
    onClick: () => {
      const at = to.selectionStart ?? to.value.length;
      const end = to.selectionEnd ?? at;
      to.value = to.value.slice(0, at) + token + to.value.slice(end);
      to.focus();
      to.setSelectionRange(at + token.length, at + token.length);
      check();
    },
  }, token));
  check();
  return h('div', { class: 'form' },
    field('Redirect to', h('div', { class: 'stack-sm' }, to, h('div', { class: 'chips' }, chips), note),
      'An absolute http or https address, or a path starting with /. Click a placeholder to insert it.', { group: true }),
    field('Status', status, 'Use 301 or 308 for a move that stays, 302 or 307 for a temporary one.'));
}

function headerDetails(form, refresh) {
  const list = h('div', { class: 'stack-sm' });
  const draw = () => {
    list.replaceChildren();
    form.headers.forEach((row, i) => {
      const target = h('select', { class: 'select', 'aria-label': `Change ${i + 1} applies to`, value: row.target }, option('response', 'Response'), option('request', 'Request'));
      const op = h('select', { class: 'select', 'aria-label': `Change ${i + 1} operation`, value: row.op }, option('set', 'Set'), option('add', 'Add'), option('remove', 'Remove'));
      const name = h('input', { class: 'input mono', type: 'text', value: row.name, placeholder: 'X-Frame-Options', spellcheck: 'false', autocomplete: 'off', 'aria-label': `Change ${i + 1} header name` });
      const value = h('input', { class: 'input mono', type: 'text', value: row.value, placeholder: 'DENY', spellcheck: 'false', autocomplete: 'off', disabled: row.op === 'remove', 'aria-label': `Change ${i + 1} header value` });
      target.addEventListener('change', () => { row.target = target.value; refresh(); });
      op.addEventListener('change', () => {
        row.op = op.value;
        value.disabled = op.value === 'remove';
        refresh();
      });
      name.addEventListener('input', () => { row.name = name.value; refresh(); });
      value.addEventListener('input', () => { row.value = value.value; refresh(); });
      list.append(h('div', { class: 'header-row' }, target, op, name, value, iconButton('x', `Remove change ${i + 1}`, () => {
        form.headers.splice(i, 1);
        draw();
        refresh();
      })));
    });
  };
  draw();
  const add = button('Add header change', { size: 'sm', iconName: 'plus', onClick: () => { form.headers.push({ target: 'response', op: 'set', name: '', value: '' }); draw(); refresh(); } });
  return h('div', { class: 'form' },
    field('Header changes', h('div', { class: 'stack-sm' }, list, add),
      'Set replaces a header, Add appends one and Remove deletes it. Request changes reach your site; response changes reach the visitor.', { group: true }));
}

// CORS fields with the node's rules checked as you type, so a wildcard with credentials is caught before moving on
function corsDetails(form, refresh) {
  const c = form.cors;
  const text = (label, key, placeholder) => {
    const input = h('input', { class: 'input mono', type: 'text', value: c[key], placeholder, spellcheck: 'false', autocomplete: 'off', 'aria-label': label });
    input.addEventListener('input', () => { c[key] = input.value; sync(); });
    return input;
  };
  const origins = h('textarea', { class: 'textarea mono', rows: '3', placeholder: 'https://app.example.com', spellcheck: 'false', autocomplete: 'off', 'aria-label': 'Allowed origins, one per line' });
  origins.value = c.origins;
  origins.addEventListener('input', () => { c.origins = origins.value; sync(); });
  const credentials = h('input', { type: 'checkbox', checked: c.credentials, 'aria-label': 'Allow credentials' });
  credentials.addEventListener('change', () => { c.credentials = credentials.checked; sync(); });
  const age = h('input', { class: 'input mono', type: 'number', min: '0', max: '86400', value: c.max_age, 'aria-label': 'Preflight max age in seconds' });
  age.addEventListener('input', () => { c.max_age = age.value; sync(); });
  const note = h('span', { class: 'error-text', role: 'status', 'aria-live': 'polite', hidden: true });
  function sync() {
    const problem = corsProblem(corsFromForm(c));
    note.textContent = problem || '';
    note.hidden = !problem;
    refresh();
  }
  const el = h('div', { class: 'form' },
    field('Allowed origins', origins, 'One exact origin per line, such as https://app.example.com, or a single * for any origin.'),
    h('div', { class: 'two-col narrow' }, field('Methods', text('Allowed methods', 'methods', 'GET POST'), 'Space or comma separated, uppercase.'), field('Max age (seconds)', age, '0 to 86400.')),
    h('div', { class: 'two-col narrow' }, field('Allowed request headers', text('Allowed request headers', 'allow_headers', 'Content-Type Authorization')),
      field('Exposed response headers', text('Exposed response headers', 'expose_headers', 'X-Request-Id'))),
    h('label', { class: 'check-row' }, credentials, h('span', {}, 'Allow credentials (cookies and authorization headers)')),
    note);
  sync();
  return el;
}

// Opens the rule builder in a drawer; an existing rule loads into the same four steps
export function openRuleBuilder({ node, rule, sites, onSaved }) {
  const form = rule ? ruleToForm(rule) : emptyForm();
  const siteName = (id) => (sites.find((s) => s.id === id) || { name: id }).name;
  const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
  let drawer = null;
  let flow = null;
  const refresh = () => flow.refresh();

  const steps = [
    {
      title: STEPS[0].title,
      problem: () => stepProblem(form, 0),
      render: () => h('div', { class: 'form' }, choiceCards('Rule kind', KINDS, form.kind, (v) => { form.kind = v; refresh(); })),
    },
    {
      title: STEPS[1].title,
      problem: () => stepProblem(form, 1),
      render: () => {
        const sentence = h('p', { class: 'notice', role: 'status', 'aria-live': 'polite' });
        const show = () => { sentence.textContent = describeRows(form.conditions); };
        const list = conditionList({ rows: form.conditions, onChange: () => { show(); refresh(); } });
        show();
        return h('div', { class: 'form' },
          h('p', { class: 'muted' }, 'Conditions of the same kind are alternatives (any one can match); different kinds must all match.'),
          list.el, sentence);
      },
    },
    {
      title: STEPS[2].title,
      problem: () => stepProblem(form, 2),
      render: () => {
        if (form.kind === 'redirect') return redirectDetails(form, refresh);
        if (form.kind === 'headers') return headerDetails(form, refresh);
        if (form.kind === 'cors') return corsDetails(form, refresh);
        return h('div', { class: 'form' }, choiceCards('Block action', ACTIONS, form.action, (v) => { form.action = v; refresh(); }));
      },
    },
    {
      title: STEPS[3].title,
      problem: () => stepProblem(form, 3),
      render: () => {
        const name = h('input', { class: 'input', type: 'text', value: form.name, placeholder: 'Block WordPress probes', 'aria-label': 'Rule name' });
        const label = h('input', { class: 'input mono', type: 'text', value: form.label, placeholder: 'Defaults to the rule id', spellcheck: 'false', autocomplete: 'off', 'aria-label': 'Rule label' });
        const scope = h('select', { class: 'select', 'aria-label': 'Scope', value: form.site },
          option('', 'All sites on this node'), sites.map((x) => option(x.id, x.name)));
        const review = h('div', {});
        const drawReview = () => review.replaceChildren(kvList(reviewLines(form, siteName).map(([k, v]) => [k, h('span', { class: 'wrap-any' }, v)])));
        name.addEventListener('input', () => { form.name = name.value; refresh(); });
        label.addEventListener('input', () => { form.label = label.value; refresh(); });
        scope.addEventListener('change', () => { form.site = scope.value; drawReview(); });
        drawReview();
        return h('div', { class: 'form' },
          h('div', { class: 'two-col narrow' }, field('Name', name), field('Label', label, 'Optional. Shown in logs and the blocked-by-rule table instead of the id.')),
          field('Applies to', scope),
          h('h4', { class: 'section-title' }, 'Review'), review, err);
      },
    },
  ];

  flow = wizard({
    steps,
    finishLabel: rule ? 'Save rule' : 'Add rule',
    onCancel: () => drawer.close(),
    onFinish: async () => {
      err.hidden = true;
      if (!form.id) form.id = rule ? rule.id : newId('rule');
      const built = buildRule(form);
      if (built.error) {
        flow.go(built.step);
        return;
      }
      try {
        const body = built.rule;
        await (rule ? nodeApi(node).put('/firewall/rules/' + encodeURIComponent(rule.id), body) : nodeApi(node).post('/firewall/rules', body));
        toast(`Rule ${body.name} saved`, 'success');
        drawer.close();
        onSaved();
      } catch (ex) {
        err.textContent = formatError(ex);
        err.hidden = false;
      }
    },
  });

  drawer = openDrawer({
    title: rule ? 'Edit rule' : 'Add firewall rule',
    subtitle: 'Four short steps: what should happen, when, the details, and a name.',
    wide: true,
    content: flow.el,
  });
  return drawer;
}
