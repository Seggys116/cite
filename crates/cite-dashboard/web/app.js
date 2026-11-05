import { h, icon, clear } from './js/dom.js';
import { api, apiEvents, initApi, isMock } from './js/api.js';
import {
  state, bus, loadNodes, selectNode, applyTheme, toggleTheme, effectiveTheme,
} from './js/state.js';
import { toast, closeAllLayers, errorState, emptyState, formatError } from './js/ui.js';
import { startDither } from './js/dither.js';
import { openPalette } from './js/palette.js';
import { loginScreen, onboardingScreen } from './js/views/auth.js';
import { overviewView } from './js/views/overview.js';
import { nodesView, openAddNode } from './js/views/nodes.js';
import { sitesView } from './js/views/sites.js';
import { newSiteView } from './js/views/siteForm.js';
import { siteDetailView } from './js/views/siteDetail.js';
import { trafficView } from './js/views/traffic.js';
import { firewallView } from './js/views/firewall.js';
import { maintenanceView } from './js/views/maintenance.js';
import { settingsView } from './js/views/settings.js';

const NAV = [
  { id: 'overview', label: 'Overview', icon: 'home' },
  { id: 'nodes', label: 'Nodes', icon: 'server' },
  { id: 'sites', label: 'Sites', icon: 'globe' },
  { id: 'traffic', label: 'Traffic', icon: 'chart' },
  { id: 'firewall', label: 'Firewall', icon: 'shield' },
  { id: 'maintenance', label: 'Maintenance', navLabel: 'Pages', icon: 'wrench' },
  { id: 'settings', label: 'Settings', icon: 'settings' },
];

const VIEWS = {
  overview: overviewView,
  nodes: nodesView,
  traffic: trafficView,
  firewall: firewallView,
  maintenance: maintenanceView,
  settings: settingsView,
  sites: (ctx) => {
    if (ctx.params[0] === 'new') return newSiteView(ctx);
    return ctx.params.length >= 2 ? siteDetailView(ctx) : sitesView(ctx);
  },
};

const app = document.getElementById('app');
let shell = null;
let authKind = '';
let authStop = null;
let viewCleanup = null;
let palette = null;

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, '');
  const parts = raw.split('/').filter(Boolean).map((p) => {
    try {
      return decodeURIComponent(p);
    } catch (err) {
      return p;
    }
  });
  return { name: parts[0] || '', params: parts.slice(1) };
}

// Assigning an identical hash fires no event, so re-run the router by hand in that case
function go(hash) {
  if (location.hash === hash) route();
  else location.hash = hash;
}

async function signOut() {
  try {
    await api.del('/session');
  } catch (err) {
    toast('Could not reach the server to end the session', 'error');
  }
  state.authed = false;
  state.user = '';
  closeAllLayers();
  go('#/login');
}

function teardownShell() {
  if (viewCleanup) viewCleanup();
  viewCleanup = null;
  if (shell) shell.stop();
  shell = null;
}

function teardownAuth() {
  if (authStop) authStop();
  authStop = null;
  authKind = '';
}

function showAuth(kind) {
  if (authKind === kind) return;
  teardownShell();
  teardownAuth();
  clear(app);
  const screen = kind === 'setup'
    ? onboardingScreen({
      onDone: () => {
        state.needsSetup = false;
        go('#/login');
      },
    })
    : loginScreen({ onSuccess: onLoggedIn });
  app.appendChild(screen.el);
  authStop = screen.cleanup;
  authKind = kind;
}

async function onLoggedIn(username) {
  state.authed = true;
  state.user = username || state.user;
  try {
    await loadNodes();
  } catch (err) {
    toast(formatError(err), 'error');
  }
  const { name } = parseHash();
  go(!name || name === 'login' || name === 'setup' ? '#/overview' : location.hash);
}

function setCrumbs(list) {
  if (!shell) return;
  clear(shell.crumbs);
  const items = [{ label: 'Console', href: '#/overview' }, ...list];
  items.forEach((item, i) => {
    if (i) shell.crumbs.appendChild(icon('chevron-right', 'crumb-sep'));
    const last = i === items.length - 1;
    shell.crumbs.appendChild(item.href && !last
      ? h('a', { class: 'crumb', href: item.href }, item.label)
      : h('span', { class: 'crumb' + (last ? ' current' : ''), 'aria-current': last ? 'page' : null }, item.label));
  });
  document.title = `${items[items.length - 1].label} - Cite Console`;
}

function fillNodeSelect() {
  if (!shell) return;
  const select = shell.nodeSelect;
  clear(select);
  select.appendChild(h('option', { value: 'all' }, 'All nodes'));
  for (const n of state.nodes) select.appendChild(h('option', { value: n.name }, n.online ? n.name : `${n.name} (offline)`));
  select.value = state.node;
}

function commands() {
  const list = NAV.map((n) => ({ label: 'Go to ' + n.label, hint: 'navigate', icon: n.icon, run: () => go('#/' + n.id) }));
  list.push(
    { label: 'Create site', hint: 'new', icon: 'plus', run: () => go('#/sites/new') },
    { label: 'Add firewall rule', hint: 'new', icon: 'shield', run: () => go('#/firewall/new') },
    { label: 'Add node', hint: 'new', icon: 'server', run: () => openAddNode(() => { if (parseHash().name === 'nodes') route(); }) },
    { label: 'Switch to All nodes', hint: 'node', icon: 'layers', run: () => selectNode('all') },
  );
  for (const n of state.nodes) list.push({ label: 'Switch to node ' + n.name, hint: 'node', icon: 'server', run: () => selectNode(n.name) });
  list.push(
    { label: 'Toggle light and dark theme', hint: 'appearance', icon: 'sun', run: toggleTheme },
    { label: 'Reload this view', hint: 'refresh', icon: 'refresh', run: () => route() },
    { label: 'Sign out', hint: 'session', icon: 'logout', run: signOut },
  );
  return list;
}

function togglePalette() {
  if (palette) {
    palette.close();
    return;
  }
  if (!state.authed) return;
  palette = openPalette(commands(), () => { palette = null; });
}

function buildShell() {
  const canvas = h('canvas', { class: 'dither-canvas header-dither', 'aria-hidden': 'true' });
  const crumbs = h('nav', { class: 'crumbs', 'aria-label': 'Breadcrumb' });
  const nodeSelect = h('select', { class: 'select node-select', 'aria-label': 'Active node' });
  nodeSelect.addEventListener('change', () => selectNode(nodeSelect.value));
  const themeBtn = h('button', { class: 'btn-icon', type: 'button', 'aria-label': 'Toggle theme', title: 'Toggle theme', onClick: toggleTheme });
  const syncTheme = () => {
    clear(themeBtn);
    themeBtn.appendChild(icon(effectiveTheme() === 'dark' ? 'sun' : 'moon'));
  };
  syncTheme();
  const searchBtn = h('button', { class: 'search-btn', type: 'button', 'aria-label': 'Open command palette', onClick: togglePalette },
    icon('search'), h('span', { class: 'search-text' }, 'Search or jump to'), h('kbd', {}, navigator.platform.includes('Mac') ? '⌘K' : 'Ctrl K'));
  const content = h('main', { class: 'content', id: 'main', tabindex: '-1' });
  const nav = h('nav', { class: 'nav', 'aria-label': 'Primary' }, NAV.map((n) => h('a', { class: 'nav-item', href: '#/' + n.id, 'data-nav': n.id, 'aria-label': n.label, title: n.label }, icon(n.icon),
    h('span', { class: 'nav-label' + (n.navLabel ? ' nav-long' : '') }, n.label), n.navLabel ? h('span', { class: 'nav-label nav-short', 'aria-hidden': 'true' }, n.navLabel) : null)));
  const sidebar = h('aside', { class: 'sidebar' },
    h('a', { class: 'brand', href: '#/overview', 'aria-label': 'Cite console home' }, h('img', { src: '/assets/logo.svg', alt: 'Cite', width: '90', height: '30' })),
    nav,
    h('div', { class: 'sidebar-foot' }, isMock ? h('span', { class: 'mock-tag' }, 'mock data') : null, h('span', { class: 'muted' }, 'v0.2')));
  const topbar = h('header', { class: 'topbar' }, canvas, crumbs,
    h('div', { class: 'top-actions' }, h('div', { class: 'node-switch' }, icon('server'), nodeSelect), searchBtn, themeBtn,
      h('button', { class: 'btn-icon', type: 'button', 'aria-label': 'Sign out', title: 'Sign out', onClick: signOut }, icon('logout'))));
  const root = h('div', { class: 'shell' }, sidebar, h('div', { class: 'main-col' }, topbar, content));

  const stopDither = startDither(canvas, { cell: 3, alpha: 0.09 });
  const onNodes = () => fillNodeSelect();
  // Changing node on a site detail page makes no sense, so fall back to the list
  const onNode = () => {
    const { name, params } = parseHash();
    if (name === 'sites' && params.length > 1) go('#/sites');
    else route();
    fillNodeSelect();
  };
  bus.addEventListener('nodes', onNodes);
  bus.addEventListener('node', onNode);
  bus.addEventListener('theme', syncTheme);

  shell = {
    root, content, crumbs, nodeSelect, nav,
    stop() {
      stopDither();
      bus.removeEventListener('nodes', onNodes);
      bus.removeEventListener('node', onNode);
      bus.removeEventListener('theme', syncTheme);
    },
  };
  teardownAuth();
  clear(app);
  app.appendChild(root);
  fillNodeSelect();
}

function renderView(name, params) {
  if (viewCleanup) viewCleanup();
  viewCleanup = null;
  const root = h('div', { class: 'view view-enter' });
  clear(shell.content);
  shell.content.appendChild(root);
  for (const link of shell.nav.children) {
    const on = link.dataset.nav === name;
    if (on) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  }
  const view = VIEWS[name];
  const ctx = { root, params, setCrumbs, signOut };
  if (!view) {
    setCrumbs([{ label: 'Not found' }]);
    root.appendChild(emptyState({ iconName: 'search', title: 'Page not found', text: 'That address does not exist in this console.', action: h('a', { class: 'btn btn-primary', href: '#/overview' }, 'Back to overview') }));
    return;
  }
  try {
    viewCleanup = view(ctx) || null;
  } catch (err) {
    root.appendChild(errorState(err, route));
  }
  window.scrollTo(0, 0);
}

// Auth state picks between the auth screens and the shell; the hash then picks the view
function route() {
  const { name, params } = parseHash();
  if (state.needsSetup) {
    showAuth('setup');
    return;
  }
  if (!state.authed) {
    showAuth('login');
    return;
  }
  if (!shell) buildShell();
  if (!name || name === 'login' || name === 'setup') {
    go('#/overview');
    return;
  }
  renderView(name, params);
}

function onKey(e) {
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault();
    togglePalette();
  }
}

// Order matters: onboarding status first, then the session, then the first route
async function boot() {
  applyTheme();
  await initApi();
  apiEvents.addEventListener('unauthorized', () => {
    if (!state.authed) return;
    state.authed = false;
    closeAllLayers();
    toast('Your session has ended. Sign in again.', 'info');
    route();
  });
  window.addEventListener('hashchange', route);
  window.addEventListener('keydown', onKey);
  try {
    const setup = await api.get('/setup');
    state.needsSetup = Boolean(setup && setup.needs_onboarding);
  } catch (err) {
    state.needsSetup = false;
  }
  if (!state.needsSetup) {
    try {
      const session = await api.get('/session');
      state.authed = true;
      state.user = (session && session.username) || '';
      await loadNodes().catch((err) => toast(formatError(err), 'error'));
    } catch (err) {
      state.authed = false;
    }
  }
  route();
}

boot();
