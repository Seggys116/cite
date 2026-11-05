import { h, debounce } from '../dom.js';
import { api, nodeApi, isMock } from '../api.js';
import { currentNode, state } from '../state.js';
import {
  pageHeader, button, loadInto, pill, emptyState, field, openDrawer, confirmDialog, toast, withBusy,
  formatError, slugify, newId, skeletonCards,
} from '../ui.js';
import { noNodes, nodeNotice } from './common.js';

const PAGE_WIDTH = 1280;

const STARTER_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Back soon</title>
<style>
body { margin: 0; min-height: 100vh; display: grid; place-items: center; font-family: system-ui, sans-serif; background: #0d1117; color: #e6edf3; }
main { max-width: 32rem; padding: 2rem; text-align: center; }
h1 { color: #ffd23f; }
</style>
</head>
<body>
<main>
<h1>Back soon</h1>
<p>We are making improvements and will be back in a few minutes.</p>
</main>
</body>
</html>
`;

// Renders page html in a fully sandboxed frame (no scripts, no same-origin access) scaled to fit its box.
// The server hosts the html under its own strict policy so inline styles work; mock mode has no server
// and falls back to srcdoc.
export function pagePreview(page) {
  const frame = h('iframe', { class: 'preview-frame', sandbox: '', title: `Preview of ${page.name || 'page'}`, tabindex: '-1' });
  const box = h('div', { class: 'preview' }, frame);
  const fit = () => frame.style.setProperty('transform', `scale(${(box.clientWidth / PAGE_WIDTH).toFixed(4)})`);
  new ResizeObserver(fit).observe(box);
  let latest = 0;
  box.update = async (html) => {
    if (isMock) {
      frame.setAttribute('srcdoc', html);
      return;
    }
    const ticket = ++latest;
    try {
      const res = await api.post('/preview', { html });
      if (ticket === latest && res && res.id) frame.setAttribute('src', '/preview/' + encodeURIComponent(res.id));
    } catch (ex) {
      if (ticket === latest) toast(formatError(ex), 'error');
    }
  };
  const first = () => box.update(page.html || '');
  if (typeof IntersectionObserver === 'function' && !isMock) {
    const watcher = new IntersectionObserver((entries) => {
      if (!entries.some((e) => e.isIntersecting)) return;
      watcher.disconnect();
      first();
    });
    watcher.observe(box);
  } else {
    first();
  }
  return box;
}

function openEditor(node, existing, onSaved) {
  const name = h('input', { class: 'input', type: 'text', value: existing ? existing.name : '', placeholder: 'Scheduled maintenance', 'aria-label': 'Page name' });
  const status = h('input', { class: 'input mono', type: 'number', min: '100', max: '599', value: String(existing ? existing.status : 503), 'aria-label': 'Status code' });
  const html = h('textarea', { class: 'textarea mono', rows: '14', spellcheck: 'false', 'aria-label': 'Page HTML', value: existing ? existing.html : STARTER_HTML });
  const preview = pagePreview({ name: name.value, html: html.value });
  html.addEventListener('input', debounce(() => preview.update(html.value), 250));
  const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const save = button(existing ? 'Save page' : 'Create page', { kind: 'primary', iconName: 'check' });
  let drawer = null;
  const fail = (message) => {
    err.textContent = message;
    err.hidden = false;
  };
  save.addEventListener('click', async () => {
    const code = Number(status.value);
    if (!name.value.trim()) return fail('Give the page a name.');
    if (!Number.isInteger(code) || code < 100 || code > 599) return fail('The status code must be between 100 and 599.');
    if (!html.value.trim()) return fail('The page needs some HTML.');
    const body = { id: existing ? existing.id : slugify(name.value) || newId('page'), name: name.value.trim(), html: html.value, status: code };
    try {
      await withBusy(save, () => (existing ? nodeApi(node).put('/pages/' + encodeURIComponent(existing.id), body) : nodeApi(node).post('/pages', body)));
      toast(`Page ${body.name} saved`, 'success');
      drawer.close();
      onSaved();
    } catch (ex) {
      fail(formatError(ex));
    }
  });
  drawer = openDrawer({
    title: existing ? 'Edit page' : 'New maintenance page',
    subtitle: 'Shown in place of a site while maintenance mode is on.',
    wide: true,
    content: h('div', { class: 'form' },
      h('div', { class: 'two-col narrow' }, field('Name', name), field('Status code', status, '503 tells crawlers to retry later.')),
      field('HTML', html, 'Plain HTML and CSS. Scripts are blocked in the preview.'),
      h('div', { class: 'field' }, h('span', { class: 'field-label' }, 'Live preview'), preview), err),
    footer: [button('Cancel', { onClick: () => drawer.close() }), save],
  });
}

function render({ pages, sites }, reload, node) {
  const newBtn = () => button('New page', { kind: 'primary', iconName: 'plus', onClick: () => openEditor(node, null, reload) });
  if (!pages.length) {
    return emptyState({ iconName: 'wrench', title: 'No maintenance pages', text: 'Create a page to show visitors while a site is under maintenance.', action: newBtn() });
  }
  const cards = pages.map((page) => {
    const users = sites.filter((x) => x.maintenance && x.maintenance.page_id === page.id);
    return h('article', { class: 'page-card' },
      pagePreview(page),
      h('div', { class: 'page-card-body' },
        h('header', {}, h('h3', {}, page.name), pill(String(page.status), page.status >= 500 ? 'warn' : 'info')),
        h('div', { class: 'chips' }, users.length
          ? users.map((x) => h('span', { class: 'chip chip-static' }, x.name, x.maintenance.enabled ? pill('live', 'warn') : null))
          : h('span', { class: 'muted' }, 'Not used by any site')),
        h('footer', {},
          button('Edit', { size: 'sm', iconName: 'edit', onClick: () => openEditor(node, page, reload) }),
          button('Delete', {
            size: 'sm',
            kind: 'ghost-danger',
            iconName: 'trash',
            onClick: async () => {
              const ok = await confirmDialog({ title: 'Delete page', message: `Delete ${page.name}? A page that a site still uses cannot be removed.`, confirmLabel: 'Delete page', danger: true });
              if (!ok) return;
              try {
                await nodeApi(node).del('/pages/' + encodeURIComponent(page.id));
                toast('Page deleted', 'success');
                reload();
              } catch (ex) {
                toast(formatError(ex), 'error');
              }
            },
          }))));
  });
  return h('div', { class: 'stack' }, h('div', { class: 'grid-pages' }, cards));
}

export function maintenanceView(ctx) {
  ctx.setCrumbs([{ label: 'Maintenance' }]);
  const node = currentNode();
  const body = h('div', {});
  let reload = null;
  const add = button('New page', { kind: 'primary', iconName: 'plus', onClick: () => openEditor(node, null, () => reload()) });
  const head = pageHeader({ title: 'Maintenance pages', subtitle: node ? 'Pages served by ' + node : 'Pages shown during maintenance', actions: state.nodes.length ? add : null });
  ctx.root.append(...[head, nodeNotice(node), body].filter(Boolean));
  if (!node) {
    body.appendChild(noNodes());
    return;
  }
  const n = nodeApi(node);
  reload = loadInto(body, async () => {
    const [pages, sites] = await Promise.all([n.get('/pages'), n.get('/sites')]);
    return { pages, sites };
  }, (data, again) => render(data, again, node), { skeleton: () => skeletonCards(3) });
}
