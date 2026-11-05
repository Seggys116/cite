import { h, icon, clear } from './dom.js';

export function formatError(err) {
  return err && err.message ? err.message : String(err);
}


const compact = new Intl.NumberFormat('en', { notation: 'compact', maximumFractionDigits: 1 });

export function fmtNum(n) {
  return compact.format(Number(n) || 0);
}

export function fmtInt(n) {
  return (Number(n) || 0).toLocaleString('en');
}

export function fmtBytes(n) {
  let value = Number(n) || 0;
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i += 1;
  }
  return (i === 0 ? String(Math.round(value)) : value.toFixed(value >= 100 ? 0 : 1)) + ' ' + units[i];
}

export function fmtPct(ratio, digits = 1) {
  return ((Number(ratio) || 0) * 100).toFixed(digits) + '%';
}

export function fmtMs(ms) {
  const value = Number(ms) || 0;
  return value < 1000 ? Math.round(value) + ' ms' : (value / 1000).toFixed(2) + ' s';
}

export function fmtUptime(secs) {
  const total = Math.floor(Number(secs) || 0);
  const d = Math.floor(total / 86400);
  const hr = Math.floor((total % 86400) / 3600);
  const m = Math.floor((total % 3600) / 60);
  if (d > 0) return `${d}d ${hr}h`;
  if (hr > 0) return `${hr}h ${m}m`;
  return `${m}m`;
}

// Accepts unix seconds, unix milliseconds or an ISO string
export function toMs(value) {
  if (typeof value === 'number') return value < 1e12 ? value * 1000 : value;
  if (typeof value === 'string' && /^\d+$/.test(value)) return toMs(Number(value));
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? 0 : parsed;
}

const pad = (n) => String(n).padStart(2, '0');

export function fmtTime(value) {
  const d = new Date(toMs(value));
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export function fmtDate(value) {
  const ms = toMs(value);
  if (!ms) return 'never';
  const d = new Date(ms);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function relTime(value) {
  const ms = toMs(value);
  if (!ms) return 'never';
  const secs = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (secs < 5) return 'just now';
  if (secs < 60) return secs + 's ago';
  if (secs < 3600) return Math.floor(secs / 60) + 'm ago';
  if (secs < 86400) return Math.floor(secs / 3600) + 'h ago';
  return Math.floor(secs / 86400) + 'd ago';
}

export function slugify(text) {
  return String(text).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48);
}

export function newId(prefix) {
  return `${prefix}-${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
}

// A hyphen is left alone because it is only special inside a character class
export function escapeRegex(text) {
  return String(text).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function checkRegex(source) {
  try {
    new RegExp(source);
    return null;
  } catch (err) {
    return err.message.replace(/^Invalid regular expression: /, '');
  }
}


export function pill(text, kind = 'muted', iconName = '') {
  return h('span', { class: 'pill pill-' + kind }, iconName ? icon(iconName) : null, text);
}

export function dot(kind, title = '') {
  return h('span', { class: 'dot dot-' + kind, title, role: 'img', 'aria-label': title || kind });
}

export function button(label, { kind = 'default', iconName = '', onClick, type = 'button', size = '', title = '', disabled = false } = {}) {
  const cls = ['btn', kind !== 'default' ? 'btn-' + kind : '', size ? 'btn-' + size : ''].filter(Boolean).join(' ');
  return h('button', { class: cls, type, onClick, title, disabled, 'aria-label': title || null },
    iconName ? icon(iconName) : null, label ? h('span', {}, label) : null);
}

export function iconButton(iconName, label, onClick) {
  return h('button', { class: 'btn-icon', type: 'button', 'aria-label': label, title: label, onClick }, icon(iconName));
}

export async function withBusy(btn, fn) {
  btn.disabled = true;
  btn.classList.add('busy');
  try {
    return await fn();
  } finally {
    btn.disabled = false;
    btn.classList.remove('busy');
  }
}

export function card({ title, subtitle, actions, body, cls = '', flush = false } = {}) {
  const head = title || actions
    ? h('header', { class: 'card-head' },
      h('div', { class: 'card-titles' }, title ? h('h3', { class: 'card-title' }, title) : null,
        subtitle ? h('p', { class: 'muted' }, subtitle) : null),
      actions ? h('div', { class: 'card-actions' }, actions) : null)
    : null;
  return h('section', { class: ('card ' + cls).trim() }, head, h('div', { class: 'card-body' + (flush ? ' flush' : '') }, body));
}

export function pageHeader({ title, subtitle, actions }) {
  return h('div', { class: 'page-head' },
    h('div', {}, h('h1', { class: 'page-title' }, title), subtitle ? h('div', { class: 'muted page-sub' }, subtitle) : null),
    actions ? h('div', { class: 'page-actions' }, actions) : null);
}

export function kvList(pairs) {
  const dl = h('dl', { class: 'kv' });
  for (const [key, value] of pairs) dl.append(h('dt', {}, key), h('dd', {}, value));
  return dl;
}

export function field(label, control, hint, { group = false } = {}) {
  return h(group ? 'div' : 'label', { class: 'field' },
    h('span', { class: 'field-label' }, label), control, hint ? h('span', { class: 'hint' }, hint) : null);
}

export function toggle({ checked = false, label, onChange }) {
  const el = h('button', { class: 'switch', type: 'button', role: 'switch', 'aria-label': label, 'aria-checked': String(checked) }, h('span', { class: 'switch-knob' }));
  const set = (value) => {
    el.setAttribute('aria-checked', String(value));
    el.classList.toggle('on', value);
  };
  set(checked);
  el.addEventListener('click', () => {
    const next = el.getAttribute('aria-checked') !== 'true';
    set(next);
    if (!onChange) return;
    Promise.resolve(onChange(next)).catch(() => set(!next));
  });
  el.setChecked = set;
  el.isChecked = () => el.getAttribute('aria-checked') === 'true';
  return el;
}

export function segmented({ options, value, onChange, label }) {
  const root = h('div', { class: 'segmented', role: 'radiogroup', 'aria-label': label });
  const buttons = new Map();
  const mark = (selected) => {
    for (const [key, btn] of buttons) {
      btn.setAttribute('aria-checked', String(key === selected));
      btn.classList.toggle('active', key === selected);
    }
  };
  for (const opt of options) {
    const btn = h('button', {
      class: 'seg', type: 'button', role: 'radio',
      onClick: () => {
        mark(opt.value);
        onChange(opt.value);
      },
    }, opt.label);
    buttons.set(opt.value, btn);
    root.appendChild(btn);
  }
  mark(value);
  return root;
}

export function routeTabs(items, active, hrefFor) {
  return h('nav', { class: 'tabs', role: 'tablist' }, items.map((item) => h('a', {
    class: 'tab' + (item.id === active ? ' active' : ''),
    href: hrefFor(item.id),
    role: 'tab',
    'aria-selected': String(item.id === active),
  }, item.icon ? icon(item.icon) : null, item.label)));
}

export function chipInput({ values = [], placeholder = 'Type and press Enter', validate, onChange, label }) {
  let list = [...values];
  const input = h('input', { class: 'chip-field', type: 'text', placeholder, 'aria-label': label || placeholder, autocomplete: 'off', spellcheck: 'false' });
  const wrap = h('div', { class: 'chips-input' });
  const err = h('p', { class: 'error-text', hidden: true });
  const draw = () => {
    const hadFocus = document.activeElement === input;
    clear(wrap);
    list.forEach((value, i) => {
      wrap.appendChild(h('span', { class: 'chip' }, h('span', { class: 'mono' }, value),
        h('button', {
          type: 'button', class: 'chip-x', 'aria-label': 'Remove ' + value,
          onClick: () => {
            list.splice(i, 1);
            draw();
            if (onChange) onChange([...list]);
          },
        }, icon('x'))));
    });
    wrap.appendChild(input);
    if (hadFocus) input.focus();
  };
  const commit = () => {
    const tokens = input.value.split(/[\s,]+/).filter(Boolean);
    let problem = null;
    for (const token of tokens) {
      problem = validate ? validate(token) : null;
      if (problem) break;
      if (!list.includes(token)) list.push(token);
    }
    err.hidden = !problem;
    err.textContent = problem || '';
    if (!problem) input.value = '';
    else input.value = tokens.slice(tokens.findIndex((t) => validate(t))).join(' ');
    draw();
    if (tokens.length && !problem && onChange) onChange([...list]);
    return !problem;
  };
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault();
      commit();
    } else if (e.key === 'Backspace' && !input.value && list.length) {
      list.pop();
      draw();
      if (onChange) onChange([...list]);
    }
  });
  input.addEventListener('input', () => {
    if (/[\s,]/.test(input.value.trim())) commit();
  });
  input.addEventListener('blur', () => {
    if (input.value.trim()) commit();
  });
  wrap.addEventListener('click', () => input.focus());
  draw();
  return {
    el: h('div', { class: 'chip-box' }, wrap, err),
    get() {
      if (input.value.trim()) commit();
      return [...list];
    },
    set(next) {
      list = [...next];
      draw();
    },
  };
}

export function copyText(text, okMessage = 'Copied to clipboard') {
  const done = () => toast(okMessage, 'success');
  const fallback = () => {
    const area = h('textarea', { class: 'sr-only', 'aria-hidden': 'true' });
    area.value = text;
    document.body.appendChild(area);
    area.select();
    try {
      document.execCommand('copy');
      done();
    } catch (err) {
      toast('Copy failed', 'error');
    }
    area.remove();
  };
  if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, fallback);
  else fallback();
}


// A same-origin navigation lets the browser stream the file to disk with the session cookie, so nothing is held in page memory
export function startNavigation(href) {
  const a = h('a', { href, download: '', class: 'sr-only', rel: 'noopener' });
  document.body.appendChild(a);
  a.click();
  a.remove();
}

export function saveText(text, name, mime) {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = h('a', { href: url, download: name, class: 'sr-only' });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

export function skeletonRows(n = 6) {
  return h('div', { class: 'skel-list', 'aria-busy': 'true', 'aria-label': 'Loading' },
    Array.from({ length: n }, () => h('div', { class: 'skeleton skel-row' })));
}

export function skeletonCards(n = 4) {
  return h('div', { class: 'grid-stats', 'aria-busy': 'true', 'aria-label': 'Loading' },
    Array.from({ length: n }, () => h('div', { class: 'skeleton skel-card' })));
}

export function skeletonBlock(height = 240) {
  const el = h('div', { class: 'skeleton skel-block', 'aria-busy': 'true', 'aria-label': 'Loading' });
  el.style.setProperty('height', height + 'px');
  return el;
}

export function emptyState({ iconName = 'layers', title, text, action }) {
  return h('div', { class: 'empty' },
    h('div', { class: 'empty-art' }, icon(iconName)),
    h('h3', {}, title),
    text ? h('p', { class: 'muted' }, text) : null,
    action || null);
}

export function errorState(err, retry) {
  return h('div', { class: 'empty empty-error', role: 'alert' },
    h('div', { class: 'empty-art' }, icon('alert')),
    h('h3', {}, 'Something went wrong'),
    h('p', { class: 'muted' }, formatError(err)),
    retry ? button('Retry', { iconName: 'refresh', onClick: retry }) : null);
}

// Shows a skeleton, runs the loader, then swaps in the rendered result or a retryable error
export function loadInto(container, load, render, { skeleton = () => skeletonRows(6) } = {}) {
  const run = async () => {
    container._ticket = (container._ticket || 0) + 1;
    const ticket = container._ticket;
    clear(container);
    container.appendChild(skeleton());
    try {
      const data = await load();
      if (container._ticket !== ticket) return;
      const out = render(data, run);
      clear(container);
      for (const node of [].concat(out || [])) container.appendChild(node);
    } catch (err) {
      if (container._ticket !== ticket) return;
      clear(container);
      container.appendChild(errorState(err, run));
    }
  };
  run();
  return run;
}

export function dataTable({ columns, rows, onRowClick, empty, rowLabel }) {
  if (!rows.length) return empty || emptyState({ title: 'Nothing here yet' });
  const head = h('tr', {}, columns.map((c) => h('th', { class: c.align === 'right' ? 'num' : '', scope: 'col' }, c.label)));
  const body = h('tbody', {});
  for (const row of rows) {
    const tr = h('tr', { class: onRowClick ? 'clickable' : '' }, columns.map((c) => {
      const content = c.render(row);
      return h('td', { class: [c.align === 'right' ? 'num' : '', c.cls || ''].join(' ').trim() }, content);
    }));
    if (onRowClick) {
      tr.tabIndex = 0;
      if (rowLabel) tr.setAttribute('aria-label', rowLabel(row));
      const open = (e) => {
        if (e.target.closest && e.target.closest('button, a, input, label, select')) return;
        onRowClick(row);
      };
      tr.addEventListener('click', open);
      tr.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && e.target === tr) onRowClick(row);
      });
    }
    body.appendChild(tr);
  }
  return h('div', { class: 'table-wrap' }, h('table', { class: 't' }, h('thead', {}, head), body));
}


export function toast(message, kind = 'info', ms = 4200) {
  const host = document.getElementById('toasts');
  const dismiss = () => {
    el.classList.add('leaving');
    // Matches the 0.2s fade-out on .toast.leaving
    setTimeout(() => el.remove(), 200);
  };
  // The message is added as a text node, so server error text can never inject markup
  const el = h('div', { class: 'toast toast-' + kind, role: kind === 'error' ? 'alert' : 'status' },
    icon(kind === 'error' ? 'alert' : kind === 'success' ? 'check' : 'info'),
    h('span', { class: 'toast-msg' }, message),
    iconButton('x', 'Dismiss', dismiss));
  host.appendChild(el);
  setTimeout(dismiss, ms);
}


const FOCUSABLE = 'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';
const layers = [];

function trapTab(e, panel) {
  if (e.key !== 'Tab') return;
  // Hidden controls have no offsetParent; counting them as first or last would let focus escape the panel
  const items = Array.from(panel.querySelectorAll(FOCUSABLE)).filter((el) => el.offsetParent !== null);
  if (!items.length) {
    e.preventDefault();
    return;
  }
  const first = items[0];
  const last = items[items.length - 1];
  if (e.shiftKey && document.activeElement === first) {
    e.preventDefault();
    last.focus();
  } else if (!e.shiftKey && document.activeElement === last) {
    e.preventDefault();
    first.focus();
  }
}

export function closeAllLayers() {
  for (const layer of [...layers]) layer.close();
}

function openLayer(panel, { onClose, focus } = {}) {
  const returnFocus = document.activeElement;
  let closed = false;
  const handle = { el: null, close };
  const onKey = (e) => {
    if (layers[layers.length - 1] !== handle) return;
    if (e.key === 'Escape') {
      e.preventDefault();
      close();
    } else {
      trapTab(e, panel);
    }
  };
  const wrap = h('div', { class: 'layer' }, h('div', { class: 'backdrop', onClick: () => close() }), panel);
  handle.el = wrap;
  function close(result) {
    if (closed) return;
    closed = true;
    layers.splice(layers.indexOf(handle), 1);
    document.removeEventListener('keydown', onKey);
    wrap.classList.add('closing');
    // Waits out the 0.16s fade-out on .layer.closing before removing the layer
    setTimeout(() => {
      wrap.remove();
      const idle = !layers.length && (!document.activeElement || document.activeElement === document.body);
      if (idle && returnFocus && returnFocus.isConnected && returnFocus.focus) returnFocus.focus();
    }, 160);
    if (onClose) onClose(result);
  }
  layers.push(handle);
  document.addEventListener('keydown', onKey);
  document.getElementById('overlays').appendChild(wrap);
  const target = (focus && panel.querySelector(focus))
    || panel.querySelector('.drawer-body input, .drawer-body textarea, .drawer-body select, .modal-body input')
    || panel.querySelector(FOCUSABLE) || panel;
  target.focus();
  return handle;
}

export const openPanel = openLayer;

export function openDrawer({ title, subtitle, content, footer, wide = false, onClose }) {
  const panel = h('aside', { class: 'drawer' + (wide ? ' drawer-wide' : ''), role: 'dialog', 'aria-modal': 'true', 'aria-label': title, tabindex: '-1' },
    h('header', { class: 'drawer-head' },
      h('div', {}, h('h2', { class: 'drawer-title' }, title), subtitle ? h('p', { class: 'muted' }, subtitle) : null),
      iconButton('x', 'Close', () => handle.close())),
    h('div', { class: 'drawer-body' }, content),
    footer ? h('footer', { class: 'drawer-foot' }, footer) : null);
  const handle = openLayer(panel, { onClose });
  return handle;
}

export function openModal({ title, content, actions, wide = false, onClose }) {
  const panel = h('div', { class: 'modal' + (wide ? ' modal-wide' : ''), role: 'dialog', 'aria-modal': 'true', 'aria-label': title, tabindex: '-1' },
    h('header', { class: 'modal-head' }, h('h2', { class: 'modal-title' }, title), iconButton('x', 'Close', () => handle.close())),
    h('div', { class: 'modal-body' }, content),
    actions ? h('footer', { class: 'modal-foot' }, actions) : null);
  const handle = openLayer(panel, { onClose });
  return handle;
}

export function confirmDialog({ title, message, confirmLabel = 'Confirm', danger = false, requireText = '' }) {
  return new Promise((resolve) => {
    let decided = false;
    const finish = (value) => {
      if (decided) return;
      decided = true;
      modal.close();
      resolve(value);
    };
    const okBtn = button(confirmLabel, { kind: danger ? 'danger' : 'primary', onClick: () => finish(true), disabled: Boolean(requireText) });
    let extra = null;
    if (requireText) {
      const input = h('input', { class: 'input mono', type: 'text', autocomplete: 'off', 'aria-label': 'Type ' + requireText + ' to confirm' });
      input.addEventListener('input', () => {
        okBtn.disabled = input.value !== requireText;
      });
      extra = field(`Type ${requireText} to confirm`, input);
    }
    const modal = openModal({
      title,
      content: h('div', {}, h('p', { class: 'dialog-text' }, message), extra),
      actions: [button('Cancel', { onClick: () => finish(false) }), okBtn],
      onClose: () => finish(false),
    });
  });
}
