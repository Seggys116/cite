import { h, debounce } from '../dom.js';
import { nodeApi, qs } from '../api.js';
import {
  button, card, copyText, segmented, toggle,
} from '../ui.js';
import {
  FOLLOW_MS, LogBuffer, filterLines, linesToText, nextQuery, shouldPoll, splitMatches,
} from '../loglib.js';
import { unsupported } from '../statuslib.js';
import { createPoller } from '../poller.js';

const LEVEL_FILTERS = [
  ['all', 'All levels', null],
  ['warn', 'Warnings and errors', ['warn', 'error']],
  ['error', 'Errors only', ['error']],
];

function lineEl(l, search) {
  const text = h('span', { class: 'log-text' }, splitMatches(l.text, search).map((p) => (p.hit ? h('mark', {}, p.text) : p.text)));
  return h('div', { class: `log-line lvl-${l.level}`, 'data-id': String(l.id) },
    l.ts ? h('time', { class: 'log-ts' }, l.ts.replace('T', ' ').replace(/\.\d+Z?$|Z$/, '')) : null, text);
}

// New lines are appended one by one so a long log never forces a full redraw.
export function logsPanel({ node, site }) {
  const buf = new LogBuffer();
  let source = 'manager';
  let slot = '';
  let follow = true;
  let search = '';
  let levels = null;
  let loaded = false;
  let pinned = true;

  const view = h('div', { class: 'log-view mono', role: 'log', 'aria-live': 'off', tabindex: '0', 'aria-label': 'Site logs' });
  const note = h('p', { class: 'muted', role: 'status', 'aria-live': 'polite', hidden: true });
  const count = h('span', { class: 'muted', role: 'status' });

  const tabs = segmented({
    label: 'Log source',
    value: source,
    options: [{ value: 'manager', label: 'Manager (build)' }, { value: 'executor', label: 'Executor (running site)' }],
    onChange: (v) => {
      source = v;
      restart();
    },
  });
  const slotSelect = h('select', { class: 'select', 'aria-label': 'Slot' },
    h('option', { value: '' }, 'Live slot'), h('option', { value: 'blue' }, 'Blue'), h('option', { value: 'green' }, 'Green'));
  slotSelect.addEventListener('change', () => {
    slot = slotSelect.value;
    restart();
  });
  const follower = toggle({
    checked: follow,
    label: 'Follow new lines',
    onChange: (v) => {
      follow = v;
      if (v) poller.now();
    },
  });
  const searchBox = h('input', { class: 'input', type: 'search', placeholder: 'Search the log', 'aria-label': 'Search the log', autocomplete: 'off', spellcheck: 'false' });
  const filter = h('select', { class: 'select', 'aria-label': 'Level' }, LEVEL_FILTERS.map(([v, label]) => h('option', { value: v }, label)));

  const visible = () => filterLines(buf.lines, { search, levels });

  function updateCount() {
    const shown = visible().length;
    count.textContent = `${shown} of ${buf.lines.length} lines${buf.dropped ? `, ${buf.dropped} older dropped` : ''}${buf.truncated ? ', the node cut the oldest' : ''}`;
  }

  function scrollDown() {
    if (pinned) view.scrollTop = view.scrollHeight;
  }

  // Rebuilds the visible lines; only needed when the search, the level filter or the source changes
  function redraw() {
    view.replaceChildren(...visible().map((l) => lineEl(l, search)));
    updateCount();
    scrollDown();
  }

  // Adds just the new lines and drops the ones that fell out of the buffer
  function append(added) {
    const fresh = filterLines(buf.lines.slice(buf.lines.length - added), { search, levels });
    const frag = document.createDocumentFragment();
    for (const l of fresh) frag.append(lineEl(l, search));
    view.append(frag);
    const oldest = buf.lines.length ? buf.lines[0].id : 0;
    while (view.firstChild && Number(view.firstChild.dataset.id) < oldest) view.firstChild.remove();
    updateCount();
    scrollDown();
  }

  view.addEventListener('scroll', () => {
    pinned = view.scrollTop + view.clientHeight >= view.scrollHeight - 24;
  });

  async function load() {
    try {
      const res = await nodeApi(node).get(`/sites/${encodeURIComponent(site.id)}/logs${qs(nextQuery({ source, slot, cursor: buf.cursor }))}`);
      note.hidden = true;
      const wasEmpty = buf.lines.length === 0;
      const added = buf.push(res);
      loaded = true;
      if (wasEmpty && !added) {
        view.replaceChildren(h('p', { class: 'muted log-empty' }, 'No log lines yet.'));
        updateCount();
      } else if (added) {
        if (wasEmpty) view.replaceChildren();
        append(added);
      }
    } catch (ex) {
      if (unsupported(ex)) {
        note.textContent = 'This node does not serve logs. Update the connector to see them.';
        poller.stop();
      } else {
        note.textContent = `Logs are not available right now: ${ex && ex.message ? ex.message : 'the node did not answer'}`;
      }
      note.hidden = false;
    }
  }

  function restart() {
    buf.reset();
    loaded = false;
    pinned = true;
    view.replaceChildren();
    updateCount();
    poller.now();
  }

  const applyFilters = debounce(() => {
    search = searchBox.value;
    levels = (LEVEL_FILTERS.find(([v]) => v === filter.value) || LEVEL_FILTERS[0])[2];
    redraw();
  }, 150);
  searchBox.addEventListener('input', applyFilters);
  filter.addEventListener('change', applyFilters);

  const copy = button('Copy', { size: 'sm', iconName: 'copy', onClick: () => copyText(linesToText(visible()), 'Log copied') });
  const clear = button('Clear', { size: 'sm', onClick: () => { buf.lines = []; redraw(); } });

  const el = card({
    title: 'Logs',
    subtitle: 'Manager logs show fetching, installing and building. Executor logs show what the running site prints. Secrets are masked by the node.',
    body: h('div', { class: 'stack-sm' },
      h('div', { class: 'log-tools' }, tabs, slotSelect, h('label', { class: 'check-row' }, follower, h('span', {}, 'Follow')), searchBox, filter, copy, clear),
      note, view, count),
  });

  const poller = createPoller({
    load,
    delay: () => FOLLOW_MS,
    active: () => shouldPoll({ follow, hidden: false, loaded }),
    alive: () => el.isConnected,
  });
  requestAnimationFrame(() => poller.start());
  updateCount();
  return { el, stop: () => poller.stop() };
}
