import { h, icon, clear, sanitizeSvg } from '../dom.js';
import { api } from '../api.js';
import { startDither } from '../dither.js';
import { button, field, withBusy, formatError, copyText } from '../ui.js';

function authLayout(card) {
  const canvas = h('canvas', { class: 'dither-canvas', 'aria-hidden': 'true' });
  const root = h('main', { class: 'auth' }, canvas,
    h('div', { class: 'auth-inner' },
      h('img', { class: 'auth-logo', src: '/assets/logo.svg', alt: 'Cite', width: '150', height: '50' }),
      card,
      h('p', { class: 'auth-foot muted' }, 'Cite blue/green edge console')));
  const stop = startDither(canvas, { cell: 4, alpha: 0.2 });
  return { el: root, cleanup: stop };
}

// Six single-digit boxes with auto-advance, backspace navigation and paste support
function codeInput({ onComplete }) {
  const boxes = Array.from({ length: 6 }, (_, i) => h('input', {
    class: 'code-box mono', type: 'text', inputmode: 'numeric', pattern: '[0-9]*',
    autocomplete: i === 0 ? 'one-time-code' : 'off', 'aria-label': `Digit ${i + 1} of 6`,
  }));
  const value = () => boxes.map((b) => b.value).join('');
  const fill = (start, digits) => {
    digits.split('').forEach((d, k) => {
      if (boxes[start + k]) boxes[start + k].value = d;
    });
    boxes[Math.min(start + digits.length, 5)].focus();
    if (value().length === 6) onComplete(value());
  };
  boxes.forEach((box, i) => {
    box.addEventListener('input', () => {
      const digits = box.value.replace(/\D/g, '');
      box.value = '';
      if (digits) fill(i, digits);
    });
    box.addEventListener('paste', (e) => {
      e.preventDefault();
      const digits = ((e.clipboardData && e.clipboardData.getData('text')) || '').replace(/\D/g, '').slice(0, 6);
      if (digits) fill(0, digits);
    });
    box.addEventListener('keydown', (e) => {
      if (e.key === 'Backspace' && !box.value && i > 0) {
        boxes[i - 1].value = '';
        boxes[i - 1].focus();
        e.preventDefault();
      } else if (e.key === 'ArrowLeft' && i > 0) {
        boxes[i - 1].focus();
      } else if (e.key === 'ArrowRight' && i < 5) {
        boxes[i + 1].focus();
      }
    });
    box.addEventListener('focus', () => box.select());
  });
  return {
    el: h('div', { class: 'code-row', role: 'group', 'aria-label': 'Six digit authentication code' }, boxes),
    value,
    clear() {
      boxes.forEach((b) => { b.value = ''; });
    },
    focus() {
      const empty = boxes.find((b) => !b.value) || boxes[5];
      empty.focus();
    },
  };
}

function formError() {
  return h('p', { class: 'form-error', role: 'alert', hidden: true });
}

function showError(el, message) {
  el.textContent = message || '';
  el.hidden = !message;
}

export function loginScreen({ onSuccess }) {
  const user = h('input', { class: 'input', type: 'text', autocomplete: 'username', required: true, spellcheck: 'false', autocapitalize: 'none' });
  const pass = h('input', { class: 'input', type: 'password', autocomplete: 'current-password', required: true });
  const err = formError();
  const code = codeInput({ onComplete: () => submit() });
  const submitBtn = button('Sign in', { kind: 'primary', type: 'submit' });
  submitBtn.classList.add('btn-block');
  let busy = false;

  async function submit() {
    if (busy) return;
    if (!user.value.trim() || !pass.value) {
      showError(err, 'Enter your username and password first.');
      (user.value.trim() ? pass : user).focus();
      return;
    }
    if (code.value().length !== 6) {
      showError(err, 'Enter the 6-digit code from your authenticator app.');
      code.focus();
      return;
    }
    busy = true;
    showError(err, '');
    try {
      await withBusy(submitBtn, () => api.post('/session', { username: user.value.trim(), password: pass.value, totp: code.value() }));
      onSuccess(user.value.trim());
    } catch (e) {
      showError(err, e.status === 401 ? 'Those credentials or that code were not accepted.' : formatError(e));
      code.clear();
      code.focus();
    } finally {
      busy = false;
    }
  }

  const form = h('form', { class: 'auth-card', novalidate: true, onSubmit: (e) => { e.preventDefault(); submit(); } },
    h('h1', { class: 'auth-title' }, 'Sign in'),
    h('p', { class: 'muted' }, 'Use your console account and a current authenticator code.'),
    field('Username', user),
    field('Password', pass),
    field('Authentication code', code.el, null, { group: true }),
    err,
    submitBtn);
  const layout = authLayout(form);
  queueMicrotask(() => user.focus());
  return layout;
}

// Rough 0 to 4 score from length and character variety, only used as a hint
function strengthOf(pw) {
  if (!pw) return 0;
  let score = 0;
  if (pw.length >= 8) score += 1;
  if (pw.length >= 12) score += 1;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score += 1;
  if (/\d/.test(pw) && /[^A-Za-z0-9]/.test(pw)) score += 1;
  return Math.max(1, score);
}

const STRENGTH_LABELS = ['Enter a password', 'Weak', 'Fair', 'Good', 'Strong'];

export function onboardingScreen({ onDone }) {
  const host = h('div', { class: 'auth-card wide' });
  const steps = h('ol', { class: 'steps', 'aria-label': 'Setup progress' },
    ['Account', 'Authenticator', 'Done'].map((label, i) => h('li', {}, h('span', { class: 'step-num' }, String(i + 1)), label)));
  const mark = (n) => {
    Array.from(steps.children).forEach((li, i) => {
      li.classList.toggle('active', i === n);
      li.classList.toggle('done', i < n);
    });
  };

  function stepAccount() {
    mark(0);
    const setupToken = h('input', { class: 'input mono', type: 'text', autocomplete: 'off', required: true, spellcheck: 'false', autocapitalize: 'none' });
    const user = h('input', { class: 'input', type: 'text', autocomplete: 'username', required: true, spellcheck: 'false', autocapitalize: 'none' });
    const pass = h('input', { class: 'input', type: 'password', autocomplete: 'new-password', required: true });
    const again = h('input', { class: 'input', type: 'password', autocomplete: 'new-password', required: true });
    const meterLabel = h('span', { class: 'meter-label muted' }, STRENGTH_LABELS[0]);
    const meter = h('div', { class: 'meter lvl-0', 'aria-hidden': 'true' }, [0, 1, 2, 3].map(() => h('i', {})));
    const err = formError();
    const next = button('Continue', { kind: 'primary', type: 'submit' });
    pass.addEventListener('input', () => {
      const level = strengthOf(pass.value);
      meter.className = 'meter lvl-' + level;
      meterLabel.textContent = STRENGTH_LABELS[level];
    });
    const form = h('form', {
      novalidate: true,
      onSubmit: async (e) => {
        e.preventDefault();
        if (!setupToken.value.trim()) return showError(err, 'Enter the setup token from the dashboard log.');
        if (!user.value.trim()) return showError(err, 'Choose a username.');
        if (pass.value.length < 8) return showError(err, 'Use at least 8 characters for the password.');
        if (pass.value !== again.value) return showError(err, 'The passwords do not match.');
        showError(err, '');
        try {
          const res = await withBusy(next, () => api.post('/setup', { setup_token: setupToken.value.trim(), username: user.value.trim(), password: pass.value }));
          stepScan(res);
        } catch (ex) {
          showError(err, formatError(ex));
        }
      },
    }, field('Setup token', setupToken, 'Printed in the container log: docker compose logs dashboard'),
    field('Username', user), field('Password', pass),
    h('div', { class: 'meter-row' }, meter, meterLabel),
    field('Confirm password', again), err, next);
    clear(host);
    host.append(h('h1', { class: 'auth-title' }, 'Create the console account'),
      h('p', { class: 'muted' }, 'This is the first run. The account protects every node you connect.'), steps, form);
    setupToken.focus();
  }

  function stepScan(res) {
    mark(1);
    const qr = sanitizeSvg(res.qr_svg || '');
    const err = formError();
    const code = codeInput({
      onComplete: async (digits) => {
        try {
          await api.post('/setup/confirm', { code: digits });
          stepDone();
        } catch (ex) {
          showError(err, formatError(ex));
          code.clear();
          code.focus();
        }
      },
    });
    const uri = String(res.totp_uri || '');
    const link = uri.startsWith('otpauth://') ? h('a', { class: 'link', href: uri }, 'Open in authenticator app') : null;
    clear(host);
    host.append(h('h1', { class: 'auth-title' }, 'Scan with your authenticator'),
      h('p', { class: 'muted' }, 'Scan the code, or enter the secret by hand, then type the 6-digit code it shows.'), steps,
      h('div', { class: 'scan-grid' },
        h('div', { class: 'qr-box' }, qr || h('p', { class: 'muted' }, 'QR code unavailable. Use the secret.')),
        h('div', { class: 'scan-side' },
          h('span', { class: 'field-label' }, 'Secret key'),
          h('div', { class: 'secret' }, h('code', { class: 'mono' }, res.totp_secret || ''),
            h('button', { class: 'btn-icon', type: 'button', 'aria-label': 'Copy secret', onClick: () => copyText(res.totp_secret || '', 'Secret copied') }, icon('copy'))),
          link)),
      field('Confirmation code', code.el, null, { group: true }), err);
    code.focus();
  }

  function stepDone() {
    mark(3);
    clear(host);
    host.append(h('div', { class: 'done-art' }, icon('check')),
      h('h1', { class: 'auth-title center' }, 'Console ready'),
      h('p', { class: 'muted center' }, 'Two-factor sign-in is active. Sign in to add your first node.'),
      button('Continue to sign in', { kind: 'primary', onClick: onDone }));
  }

  stepAccount();
  return authLayout(host);
}
