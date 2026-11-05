import { h, icon, clear } from './dom.js';
import { openPanel } from './ui.js';

// Command palette: commands are { label, hint, icon, run }
export function openPalette(commands, onClose) {
  const input = h('input', {
    class: 'palette-input', type: 'text', placeholder: 'Type a command or search...', autocomplete: 'off', spellcheck: 'false',
    role: 'combobox', 'aria-expanded': 'true', 'aria-controls': 'palette-list', 'aria-label': 'Command palette',
  });
  const list = h('ul', { class: 'palette-list', id: 'palette-list', role: 'listbox' });
  let shown = commands;
  let active = 0;
  let handle = null;

  const mark = () => {
    Array.from(list.children).forEach((li, i) => {
      li.classList.toggle('active', i === active);
      li.setAttribute('aria-selected', String(i === active));
      if (i === active) {
        input.setAttribute('aria-activedescendant', li.id);
        li.scrollIntoView({ block: 'nearest' });
      }
    });
  };

  const run = (cmd) => {
    handle.close();
    setTimeout(cmd.run, 0);
  };

  const draw = () => {
    clear(list);
    if (!shown.length) {
      list.appendChild(h('li', { class: 'palette-empty muted' }, 'No matching commands'));
      return;
    }
    shown.forEach((cmd, i) => {
      list.appendChild(h('li', {
        class: 'palette-item', role: 'option', id: 'pal-' + i,
        onClick: () => run(cmd),
        onMouseMove: () => {
          if (active !== i) {
            active = i;
            mark();
          }
        },
      }, icon(cmd.icon), h('span', { class: 'palette-label' }, cmd.label), cmd.hint ? h('span', { class: 'palette-hint muted' }, cmd.hint) : null));
    });
    mark();
  };

  input.addEventListener('input', () => {
    const tokens = input.value.toLowerCase().split(/\s+/).filter(Boolean);
    shown = commands.filter((c) => tokens.every((t) => (c.label + ' ' + (c.hint || '')).toLowerCase().includes(t)));
    active = 0;
    draw();
  });
  input.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      if (!shown.length) return;
      active = (active + (e.key === 'ArrowDown' ? 1 : shown.length - 1)) % shown.length;
      mark();
    } else if (e.key === 'Enter' && shown[active]) {
      e.preventDefault();
      run(shown[active]);
    }
  });

  const panel = h('div', { class: 'palette', role: 'dialog', 'aria-modal': 'true', 'aria-label': 'Command palette', tabindex: '-1' },
    h('div', { class: 'palette-search' }, icon('search'), input, h('kbd', {}, 'Esc')), list);
  handle = openPanel(panel, { onClose });
  draw();
  return handle;
}
