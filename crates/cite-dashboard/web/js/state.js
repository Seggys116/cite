import { api } from './api.js';

export const bus = new EventTarget();

export const state = { authed: false, user: '', nodes: [], node: 'all' };

export const storage = {
  get(key, fallback = null) {
    try {
      const value = localStorage.getItem('cite.' + key);
      return value === null ? fallback : value;
    } catch (err) {
      return fallback;
    }
  },
  set(key, value) {
    try {
      localStorage.setItem('cite.' + key, value);
    } catch (err) {
      return;
    }
  },
};

state.node = storage.get('node', 'all');

export function themeMode() {
  return storage.get('theme', 'system');
}

export function effectiveTheme() {
  const mode = themeMode();
  if (mode === 'light' || mode === 'dark') return mode;
  return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

export function applyTheme() {
  const mode = themeMode();
  const root = document.documentElement;
  if (mode === 'light' || mode === 'dark') root.dataset.theme = mode;
  else delete root.dataset.theme;
  bus.dispatchEvent(new Event('theme'));
}

export function setTheme(mode) {
  storage.set('theme', mode);
  applyTheme();
}

export function toggleTheme() {
  setTheme(effectiveTheme() === 'dark' ? 'light' : 'dark');
}

window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', () => {
  if (themeMode() === 'system') applyTheme();
});

export async function loadNodes() {
  const list = await api.get('/nodes');
  state.nodes = Array.isArray(list) ? list : (list && list.nodes) || [];
  if (state.node !== 'all' && !state.nodes.some((n) => n.name === state.node)) state.node = 'all';
  bus.dispatchEvent(new Event('nodes'));
  return state.nodes;
}

export function selectNode(name) {
  state.node = name;
  storage.set('node', name);
  bus.dispatchEvent(new Event('node'));
}

// The node a single-node screen should operate on; null when none are configured
export function currentNode() {
  if (state.node !== 'all') return state.node;
  const first = state.nodes.find((n) => n.online) || state.nodes[0];
  return first ? first.name : null;
}
