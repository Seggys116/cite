import { h } from '../dom.js';
import { button } from '../ui.js';
import {
  advance, back, isLast, progressText, stepStates,
} from '../wizardlib.js';

// A step-by-step form: each step is built when it is entered, Next stays off until the step is clean, and focus moves to the step heading.
// steps: [{ title, render(wizard) -> Node, problem() -> string|null }]
export function wizard({ steps, finishLabel = 'Finish', onFinish, onCancel }) {
  let current = 0;
  let busy = false;
  const heading = h('h2', { class: 'wizard-title', tabindex: '-1' });
  const status = h('p', { class: 'hint', role: 'status', 'aria-live': 'polite' });
  const body = h('div', { class: 'wizard-body' });
  const list = h('ol', { class: 'wizard-progress', 'aria-label': 'Progress' });
  const backBtn = button('Back', { onClick: () => go(back(current)) });
  const nextBtn = button('Next', { kind: 'primary', type: 'submit' });
  const cancelBtn = onCancel ? button('Cancel', { onClick: onCancel }) : null;
  const form = h('form', { class: 'wizard', novalidate: true }, list, heading, body, status, h('div', { class: 'form-actions' }, cancelBtn, backBtn, nextBtn));

  const problem = () => steps[current].problem();

  function refresh() {
    const bad = problem();
    nextBtn.disabled = Boolean(bad) || busy;
    backBtn.disabled = current === 0 || busy;
    status.textContent = bad || '';
    nextBtn.querySelector('span').textContent = isLast(current, steps.length) ? finishLabel : 'Next';
  }

  function drawProgress() {
    list.replaceChildren(...stepStates(steps.length, current).map(({ index, state }) => h('li', {
      class: 'wizard-step ' + state, 'aria-current': state === 'current' ? 'step' : null,
    }, h('span', { class: 'wizard-num' }, String(index + 1)), h('span', {}, steps[index].title))));
  }

  function go(index, { focus = true } = {}) {
    current = index;
    body.replaceChildren(steps[current].render(api));
    heading.textContent = progressText(current, steps.length, steps[current].title);
    drawProgress();
    refresh();
    if (focus) heading.focus();
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (problem() || busy) return;
    if (!isLast(current, steps.length)) {
      go(advance(current, steps.length, null));
      return;
    }
    busy = true;
    refresh();
    try {
      await onFinish();
    } finally {
      busy = false;
      refresh();
    }
  });

  const api = {
    el: form,
    refresh,
    go,
    current: () => current,
  };
  go(0, { focus: false });
  return api;
}
