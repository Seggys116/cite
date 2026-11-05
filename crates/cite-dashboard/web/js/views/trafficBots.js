import { h, icon } from '../dom.js';
import { nodeApi, qs, isMock } from '../api.js';
import { donut, hbars, histogram } from '../charts.js';
import {
  button, card, dataTable, field, kvList, loadInto, openModal, pill, segmented, skeletonBlock, skeletonCards, toast, withBusy,
  fmtBytes, fmtDate, fmtInt, fmtMs, fmtNum,
} from '../ui.js';
import {
  BOT_CLASSES, BOT_METHOD_HELP, DEFAULT_EXPORT_ROWS, EXPORT_FORMATS, EXPORT_KINDS, METHODS, TOP_KINDS,
  botClass, buildExportParams, classBreakdown, exportFileName, exportPath, fmtSharePct, hasBotData, parseSignals,
  retentionText, scoreBandClass, scoreBuckets, signalHelp, signalLabel, toQuery,
} from '../botlib.js';

const mono = (value) => h('span', { class: 'mono wrap-any' }, value === undefined || value === null || value === '' ? '-' : String(value));

// A button that reveals a plain-language note; the text is also the hover title for pointer users
function helpToggle(text, label) {
  const note = h('p', { class: 'help-note', role: 'note', hidden: true }, text);
  const btn = h('button', { class: 'btn-icon', type: 'button', 'aria-label': label, 'aria-expanded': 'false', title: text }, icon('info'));
  btn.addEventListener('click', () => {
    note.hidden = !note.hidden;
    btn.setAttribute('aria-expanded', String(!note.hidden));
  });
  return { btn, note };
}

export function classBadge(key) {
  const info = botClass(key);
  return h('span', { class: 'pill bc-pill ' + info.cls, title: info.help }, info.label);
}

export function scoreValue(score) {
  const has = score !== undefined && score !== null && score !== '';
  if (!has) return h('span', { class: 'mono muted' }, '-');
  return h('span', { class: 'mono score ' + scoreBandClass(score), title: 'Bot score from 0 (human-like) to 100 (automated)' }, String(score));
}

export function signalChips(csv) {
  const keys = parseSignals(csv);
  if (!keys.length) return h('span', { class: 'muted' }, 'No signals raised');
  return h('div', { class: 'chips' }, keys.map((k) => h('span', { class: 'chip mono', title: signalHelp(k) }, signalLabel(k))));
}

export function botCells(ev) {
  return {
    badge: ev.bot_class ? classBadge(ev.bot_class) : h('span', { class: 'muted' }, '-'),
    score: scoreValue(ev.bot_score),
  };
}

// Everything the edge captured for one request, as label and value pairs for a definition list
export function captureRows(ev) {
  return [
    ['HTTP version', mono(ev.http_version)], ['TLS version', mono(ev.tls_version)],
    ['Accept', mono(ev.accept)], ['Accept-Language', mono(ev.accept_language)], ['Accept-Encoding', mono(ev.accept_encoding)],
    ['Sec-Fetch-Site', mono(ev.sec_fetch_site)], ['Sec-Fetch-Mode', mono(ev.sec_fetch_mode)], ['Sec-Fetch-Dest', mono(ev.sec_fetch_dest)],
    ['Sec-CH-UA', mono(ev.sec_ch_ua)],
    ['Backend time', mono(ev.resp_ms === undefined || ev.resp_ms === null ? '' : fmtMs(ev.resp_ms))],
  ];
}

export function botDetail(ev) {
  if (!hasBotData(ev)) return h('p', { class: 'muted' }, 'This request was recorded without bot analysis.');
  return h('div', { class: 'stack-sm' },
    h('div', { class: 'pill-row' }, classBadge(ev.bot_class), h('span', { class: 'muted' }, 'score'), scoreValue(ev.bot_score)),
    signalChips(ev.bot_signals),
    h('p', { class: 'hint' }, BOT_METHOD_HELP));
}

function ranked(items, emptyText) {
  return dataTable({
    columns: [
      { label: 'Key', cls: 'cell-clip', render: (r) => h('span', { class: 'mono clip', title: r.key }, r.key) },
      { label: 'Requests', align: 'right', render: (r) => h('span', { class: 'mono' }, fmtInt(r.count)) },
    ],
    rows: items || [],
    empty: h('p', { class: 'muted pad' }, emptyText),
  });
}

function signalTable(items) {
  return dataTable({
    columns: [
      { label: 'Signal', cls: 'cell-clip', render: (r) => h('span', { class: 'chip mono', title: signalHelp(r.key) }, signalLabel(r.key)) },
      { label: 'Requests', align: 'right', render: (r) => h('span', { class: 'mono' }, fmtInt(r.count)) },
    ],
    rows: items || [],
    empty: h('p', { class: 'muted pad' }, 'No signals were raised in this window.'),
  });
}

function legend(classes) {
  return h('ul', { class: 'legend-list' }, classes.map((c) => h('li', { title: c.help },
    h('i', { class: 'swatch bc-fill ' + c.cls }), h('span', {}, c.label), h('b', { class: 'mono' }, fmtNum(c.value)))));
}

export function botsPanel(sm) {
  const classes = classBreakdown(sm.classes);
  const help = helpToggle(BOT_METHOD_HELP, 'How bot detection works');
  const segs = classes.map((c) => ({ label: c.label, value: c.value, cls: 'bc-seg ' + c.cls }));
  const share = h('div', { class: 'donut-wrap' },
    donut(segs, { centerTop: fmtSharePct(sm.bot_share_pct), centerBottom: 'bot share' }),
    h('div', { class: 'stack-sm' },
      h('div', { class: 'muted' }, `${fmtInt(sm.bot_requests)} of ${fmtInt(sm.total_requests)} requests were not classed human`)));
  const buckets = scoreBuckets(sm.score_buckets);
  return h('div', { class: 'stack', 'data-panel': 'bots' },
    h('div', { class: 'section-row' }, h('h2', { class: 'section-title' }, 'Bot traffic'), help.btn),
    help.note,
    h('div', { class: 'grid-cards' },
      card({ title: 'Bot share', subtitle: 'Requests not classed human', body: sm.total_requests ? share : h('p', { class: 'muted' }, 'No requests in this window.') }),
      card({
        title: 'Classes',
        subtitle: 'Hover a class to see what it means',
        body: h('div', { class: 'stack' },
          hbars(classes.map((c) => ({ label: c.label, value: c.value, cls: 'bc-fill ' + c.cls }))), legend(classes)),
      }),
      card({
        title: 'Score distribution',
        subtitle: '0 looks human, 100 looks automated',
        body: buckets.some((b) => b.value) ? histogram(buckets) : h('p', { class: 'muted' }, 'No scored requests in this window.'),
      })),
    h('div', { class: 'grid-cards wide' },
      card({ title: 'Top signals', subtitle: 'Why requests were flagged. Hover a signal for its meaning.', flush: true, body: signalTable(sm.signals) }),
      card({ title: 'Top bot agents', subtitle: 'User agents behind the flagged requests', flush: true, body: ranked(sm.agents, 'No bot agents seen in this window.') })));
}

export function botsSkeleton() {
  return h('div', { class: 'stack' }, skeletonCards(3), skeletonBlock(180));
}

function topTable(items) {
  return dataTable({
    columns: [
      { label: 'Value', cls: 'cell-clip', render: (r) => h('span', { class: 'mono clip', title: r.key }, r.key === '' ? '(empty)' : r.key) },
      { label: 'Requests', align: 'right', render: (r) => h('span', { class: 'mono' }, fmtInt(r.count)) },
      { label: 'Bytes', align: 'right', cls: 'hide-sm', render: (r) => h('span', { class: 'mono muted' }, fmtBytes(r.bytes || 0)) },
    ],
    rows: items,
    empty: h('p', { class: 'muted pad' }, 'Nothing recorded for this field in the window.'),
  });
}

export function topExplorer(node, getQuery) {
  const n = nodeApi(node);
  const kindSel = h('select', { class: 'select', 'aria-label': 'Field to rank' }, TOP_KINDS.map((k) => h('option', { value: k.value }, k.label)));
  const limitSel = h('select', { class: 'select', 'aria-label': 'Number of rows' }, [10, 25, 50, 100].map((v) => h('option', { value: String(v) }, 'Top ' + v)));
  limitSel.value = '10';
  const host = h('div', {});
  const live = h('p', { class: 'sr-only', role: 'status', 'aria-live': 'polite' });
  const run = loadInto(host, async () => {
    const q = getQuery();
    const data = await n.get('/analytics/top' + qs({ kind: kindSel.value, window: q.window, site: q.site, limit: limitSel.value }));
    return Array.isArray(data) ? data : (data && data.items) || [];
  }, (items) => {
    const label = TOP_KINDS.find((k) => k.value === kindSel.value).label.toLowerCase();
    live.textContent = `${items.length} ${label} loaded`;
    return topTable(items);
  });
  kindSel.addEventListener('change', run);
  limitSel.addEventListener('change', run);
  const el = card({
    title: 'Top explorer',
    subtitle: 'Rank any recorded field over the selected window',
    actions: [kindSel, limitSel],
    flush: true,
    body: h('div', {}, live, host),
  });
  return { el, refresh: run };
}

function storageBody({ stats, settings, unsupported }) {
  if (unsupported) return h('p', { class: 'muted' }, 'This node does not report storage statistics yet. Update the node to see them.');
  const span = stats.oldest_ts_ms && stats.newest_ts_ms
    ? `${fmtDate(stats.oldest_ts_ms)} to ${fmtDate(stats.newest_ts_ms)}`
    : 'No requests stored yet';
  const writes = [mono(`${fmtInt(stats.write_batches)} batches`)];
  if (stats.write_errors) writes.push(' ', pill(`${fmtInt(stats.write_errors)} write errors`, 'bad', 'alert'));
  return kvList([
    ['Stored rows', mono(fmtInt(stats.rows))],
    ['Database size', mono(fmtBytes(stats.db_bytes))],
    ['Oldest request', mono(stats.oldest_ts_ms ? fmtDate(stats.oldest_ts_ms) : 'none')],
    ['Newest request', mono(stats.newest_ts_ms ? fmtDate(stats.newest_ts_ms) : 'none')],
    ['Covers', h('span', { class: 'muted' }, span)],
    ['Retention', h('span', {}, retentionText(settings))],
    ['Writes', h('span', {}, writes)],
  ]);
}

export function storageCard(node) {
  const n = nodeApi(node);
  const host = h('div', {});
  const run = loadInto(host, async () => {
    const settings = await n.get('/settings').catch(() => null);
    try {
      return { stats: await n.get('/analytics/stats'), settings };
    } catch (ex) {
      if (ex && ex.status === 404) return { unsupported: true };
      throw ex;
    }
  }, storageBody, { skeleton: () => skeletonBlock(120) });
  const el = card({ title: 'Analytics storage', subtitle: 'What this node keeps on disk for analytics', body: host });
  return { el, refresh: run };
}

function downloadHref(node, params) {
  return '/api/v1' + exportPath(node, params);
}

// A same-origin navigation lets the browser stream the file to disk with the session cookie, so nothing is held in page memory
function startNavigation(href) {
  const a = h('a', { href, download: '', class: 'sr-only', rel: 'noopener' });
  document.body.appendChild(a);
  a.click();
  a.remove();
}

function saveText(text, name, mime) {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = h('a', { href: url, download: name, class: 'sr-only' });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

export function openExportDialog({ node, win, sites = [], site = '' }) {
  const form = {
    kind: 'requests', top: 'paths', format: 'csv', rangeMode: 'window', window: win, from: '', to: '', site,
    statusMin: '', statusMax: '', botClass: '', minScore: '', host: '', pathPrefix: '', clientIp: '', method: '',
    limit: String(DEFAULT_EXPORT_ROWS),
  };
  const selectFor = (key, label, options, onChange) => {
    const el = h('select', { class: 'select', 'aria-label': label }, options.map((o) => h('option', { value: o.value }, o.label)));
    el.value = form[key];
    el.addEventListener('change', () => {
      form[key] = el.value;
      if (onChange) onChange();
    });
    return el;
  };
  const inputFor = (key, props) => {
    const el = h('input', { class: 'input', autocomplete: 'off', ...props });
    el.value = form[key];
    el.addEventListener('input', () => { form[key] = el.value; });
    return el;
  };

  const kindHint = h('span', { class: 'hint' });
  const topField = field('Top list field', selectFor('top', 'Top list field', TOP_KINDS));
  const customRow = h('div', { class: 'two-col' },
    field('From', inputFor('from', { type: 'datetime-local' })),
    field('To', inputFor('to', { type: 'datetime-local' })));
  const filters = h('details', { class: 'filter-box' },
    h('summary', {}, 'Filters'),
    h('div', { class: 'stack' },
      h('div', { class: 'two-col' },
        field('Status from', inputFor('statusMin', { type: 'number', min: '100', max: '599', placeholder: '400', inputmode: 'numeric' })),
        field('Status to', inputFor('statusMax', { type: 'number', min: '100', max: '599', placeholder: '599', inputmode: 'numeric' }))),
      h('div', { class: 'two-col' },
        field('Bot class', selectFor('botClass', 'Bot class', [{ value: '', label: 'Any class' }, ...BOT_CLASSES.map((c) => ({ value: c.key, label: c.label }))])),
        field('Minimum bot score', inputFor('minScore', { type: 'number', min: '0', max: '100', placeholder: '0', inputmode: 'numeric' }))),
      h('div', { class: 'two-col' },
        field('Host', inputFor('host', { type: 'text', class: 'input mono', placeholder: 'example.com', spellcheck: 'false' })),
        field('Path prefix', inputFor('pathPrefix', { type: 'text', class: 'input mono', placeholder: '/api/', spellcheck: 'false' }))),
      h('div', { class: 'two-col' },
        field('Client IP', inputFor('clientIp', { type: 'text', class: 'input mono', placeholder: '203.0.113.7', spellcheck: 'false' })),
        field('Method', selectFor('method', 'Method', [{ value: '', label: 'Any method' }, ...METHODS.map((m) => ({ value: m, label: m }))])))));

  const sync = () => {
    topField.hidden = form.kind !== 'top';
    customRow.hidden = form.rangeMode !== 'custom';
    const filtered = form.kind === 'requests' || form.kind === 'bots';
    filters.hidden = !filtered;
    const info = EXPORT_KINDS.find((k) => k.value === form.kind);
    kindHint.textContent = info.help + (filtered ? '' : ' Request filters do not apply to this export.');
  };
  const rangeSeg = segmented({
    label: 'Time range',
    options: [{ value: 'window', label: `Current window (${win})` }, { value: 'custom', label: 'Custom range' }],
    value: form.rangeMode,
    onChange: (v) => { form.rangeMode = v; sync(); },
  });
  const formatSeg = segmented({
    label: 'File format',
    options: EXPORT_FORMATS,
    value: form.format,
    onChange: (v) => { form.format = v; },
  });
  const siteOptions = [{ value: '', label: 'All sites' }, ...sites];
  if (form.site && !siteOptions.some((s) => s.value === form.site)) siteOptions.push({ value: form.site, label: form.site });

  const errorBox = h('div', { class: 'form-error', role: 'alert', hidden: true });
  const status = h('p', { class: 'muted', role: 'status', 'aria-live': 'polite' });
  const fail = (message) => {
    errorBox.textContent = message;
    errorBox.hidden = !message;
  };

  const content = h('div', { class: 'form' },
    h('div', { class: 'two-col' },
      field('What to export', selectFor('kind', 'What to export', EXPORT_KINDS, sync), kindHint),
      field('Format', formatSeg, null, { group: true })),
    topField,
    field('Time range', rangeSeg, null, { group: true }),
    customRow,
    h('div', { class: 'two-col' },
      field('Site', selectFor('site', 'Site', siteOptions)),
      field('Row limit', inputFor('limit', { type: 'number', min: '1', placeholder: 'No limit', inputmode: 'numeric' }), 'Large exports stream straight to a file; a limit keeps them quick.')),
    filters, errorBox, status);

  const cancel = button('Cancel', { onClick: () => modal.close() });
  const go = button('Download', {
    kind: 'primary',
    iconName: 'download',
    onClick: () => withBusy(go, async () => {
      fail('');
      const built = buildExportParams(form);
      if (built.error) {
        fail(built.error);
        return;
      }
      const { params } = built;
      status.textContent = 'Checking the export...';
      try {
        // A one-row probe surfaces auth and validation errors here instead of as a failed browser download
        const probe = { ...params, limit: 1 };
        await nodeApi(node).get('/analytics/export' + toQuery(probe));
        if (isMock) {
          const full = await nodeApi(node).get('/analytics/export' + toQuery(params));
          saveText(full, exportFileName(params), params.format === 'ndjson' ? 'application/x-ndjson' : 'text/csv');
        } else {
          startNavigation(downloadHref(node, params));
        }
        status.textContent = '';
        toast('Export started. Your browser saves the file to its downloads folder.', 'success');
        modal.close();
      } catch (ex) {
        status.textContent = '';
        fail(ex && ex.message ? ex.message : String(ex));
      }
    }),
  });
  const modal = openModal({ title: 'Export analytics', wide: true, content, actions: [cancel, go] });
  sync();
  return modal;
}
