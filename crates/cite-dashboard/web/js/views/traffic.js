import { h, icon, clear } from '../dom.js';
import { nodeApi, qs } from '../api.js';
import { currentNode, storage, state } from '../state.js';
import { timeSeriesChart, donut, hbars, histogram } from '../charts.js';
import {
  pageHeader, button, loadInto, card, pill, dataTable, emptyState, errorState, segmented, kvList, openDrawer,
  toast, withBusy, formatError, newId, escapeRegex, fmtNum, fmtInt, fmtBytes, fmtMs, fmtPct, fmtDate, fmtTime,
  skeletonCards, skeletonBlock, toMs,
} from '../ui.js';
import { noNodes, nodeNotice } from './common.js';
import { perBucketSizes } from '../sizes.js';
import {
  botsPanel, botsSkeleton, topExplorer, storageCard, openExportDialog, botDetail, captureRows, botCells,
} from './trafficBots.js';

const WINDOWS = ['15m', '1h', '24h', '7d', '30d'];
const SERIES = [
  { key: 'requests', label: 'Requests', cls: 's-req' },
  { key: 'errors', label: 'Errors', cls: 's-err' },
  { key: 'blocked', label: 'Blocked', cls: 's-blk' },
];
const STATUS_ORDER = ['2xx', '3xx', '4xx', '5xx'];

function statusKind(code) {
  if (!code) return 'muted';
  if (code >= 500) return 'bad';
  if (code >= 400) return 'warn';
  if (code >= 300) return 'info';
  return 'ok';
}

function topTable(items, { bytes = false } = {}) {
  return dataTable({
    columns: [
      { label: 'Key', cls: 'cell-clip', render: (r) => h('span', { class: 'mono clip', title: r.key }, r.key) },
      { label: 'Requests', align: 'right', render: (r) => h('span', { class: 'mono' }, fmtInt(r.count)) },
      bytes ? { label: 'Bytes', align: 'right', render: (r) => h('span', { class: 'mono muted' }, fmtBytes(r.bytes || 0)) } : null,
    ].filter(Boolean),
    rows: items || [],
    empty: h('p', { class: 'muted pad' }, 'Nothing recorded in this window.'),
  });
}

function statTile(label, value, sub) {
  return h('div', { class: 'stat' }, h('div', { class: 'stat-top' }, h('span', {}, label)),
    h('div', { class: 'stat-value mono' }, value), h('div', { class: 'stat-sub muted' }, sub));
}

function renderAnalytics({ summary: sm, series }) {
  const errors = (sm.errors_4xx || 0) + (sm.errors_5xx || 0);
  const statusKeys = Object.keys(sm.status || {}).sort((a, b) => (STATUS_ORDER.indexOf(a) + 1 || 9) - (STATUS_ORDER.indexOf(b) + 1 || 9));
  const donutSegs = statusKeys.map((k) => ({ label: k, value: sm.status[k], cls: 'seg-' + (STATUS_ORDER.includes(k) ? k : 'other') }));
  const methodItems = Object.entries(sm.methods || {}).sort((a, b) => b[1] - a[1]).map(([label, value]) => ({ label, value }));
  const typeItems = Object.entries(sm.content_types || {}).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([label, value]) => ({ label, value }));
  const sizeBuckets = perBucketSizes(sm.sizes).map((b) => ({
    label: typeof b.le === 'number' ? fmtBytes(b.le).replace(/\.0 /, ' ').replace(/ B$/, '').replace(/ ([KMGT])B$/, '$1') : 'more',
    title: typeof b.le === 'number' ? 'Up to ' + fmtBytes(b.le) : 'Larger than the last bound',
    value: b.count,
  }));
  const latency = [
    { label: 'Average', value: sm.avg_ms || 0 }, { label: 'p50', value: sm.p50_ms || 0 },
    { label: 'p95', value: sm.p95_ms || 0 }, { label: 'p99', value: sm.p99_ms || 0 },
  ];
  const totalStatus = donutSegs.reduce((t, x) => t + x.value, 0);

  return h('div', { class: 'stack' },
    h('div', { class: 'grid-stats' },
      statTile('Requests', fmtNum(sm.requests), fmtInt(sm.requests) + ' in this window'),
      statTile('Bandwidth out', fmtBytes(sm.bytes_out), fmtBytes(sm.bytes_in) + ' received'),
      statTile('Errors', fmtNum(errors), sm.requests ? fmtPct(errors / sm.requests, 2) + ' of requests' : 'no traffic'),
      statTile('Blocked', fmtNum(sm.blocked), 'stopped by the firewall')),
    card({ title: 'Requests over time', subtitle: 'Hover the chart for exact values', body: timeSeriesChart(series.points || [], { series: SERIES }) }),
    h('div', { class: 'grid-cards' },
      card({
        title: 'Status classes',
        body: h('div', { class: 'donut-wrap' },
          donut(donutSegs, { centerTop: fmtNum(totalStatus), centerBottom: 'responses' }),
          h('ul', { class: 'legend-list' }, donutSegs.map((x) => h('li', {}, h('i', { class: 'swatch ' + x.cls }), h('span', {}, x.label), h('b', { class: 'mono' }, fmtNum(x.value)))))),
      }),
      card({ title: 'Methods', body: hbars(methodItems) }),
      card({ title: 'Latency', subtitle: 'Total time per request', body: hbars(latency, { format: fmtMs }) }),
      card({ title: 'Response sizes', body: sizeBuckets.length ? histogram(sizeBuckets) : h('p', { class: 'muted' }, 'No data in this window.') }),
      card({ title: 'Content types', body: hbars(typeItems) })),
    h('div', { class: 'grid-cards wide' },
      card({ title: 'Top paths', flush: true, body: topTable(sm.top_paths, { bytes: true }) }),
      card({ title: 'Top client IPs', flush: true, body: topTable(sm.top_ips) }),
      card({ title: 'Top user agents', flush: true, body: topTable(sm.top_user_agents) }),
      card({ title: 'Top hosts', flush: true, body: topTable(sm.top_hosts, { bytes: true }) }),
      card({ title: 'Blocked by rule', flush: true, body: topTable(sm.top_blocked) })));
}

// Block actions create a plain deny rule so the effect is visible on the Firewall screen
function openEventSheet(node, ev) {
  const block = async (btn, rule, label) => {
    try {
      await withBusy(btn, () => nodeApi(node).post('/firewall/rules', rule));
      toast(`${label} blocked. See Firewall for the new rule.`, 'success');
      sheet.close();
    } catch (ex) {
      toast(formatError(ex), 'error');
    }
  };
  const blockPath = button('Block this path', {
    iconName: 'ban',
    onClick: () => block(blockPath, {
      id: newId('rule'), name: 'Block path ' + ev.path, enabled: true, action: 'deny', site: null,
      matchers: { path_regexes: ['^' + escapeRegex(ev.path) + '$'] },
    }, 'Path'),
  });
  const blockIp = button('Block this IP', {
    iconName: 'ban',
    disabled: !ev.client_ip,
    onClick: () => block(blockIp, {
      id: newId('rule'), name: 'Block IP ' + ev.client_ip, enabled: true, action: 'deny', site: null,
      matchers: { cidrs: [ev.client_ip + (ev.client_ip.includes(':') ? '/128' : '/32')] },
    }, 'Address'),
  });
  const mono = (v) => h('span', { class: 'mono wrap-any' }, v || '-');
  const sheet = openDrawer({
    title: `${ev.method} ${ev.path.length > 40 ? ev.path.slice(0, 40) + '...' : ev.path}`,
    subtitle: fmtDate(ev.ts_ms) + ':' + String(new Date(toMs(ev.ts_ms)).getSeconds()).padStart(2, '0'),
    content: h('div', { class: 'stack' },
      h('div', { class: 'pill-row' }, pill(String(ev.status), statusKind(ev.status)), ev.blocked ? pill('Blocked: ' + ev.blocked, 'bad', 'ban') : pill('Allowed', 'ok')),
      kvList([
        ['Path', mono(ev.path)], ['Query length', mono(String(ev.query_len))], ['Host', mono(ev.host)], ['Client IP', mono(ev.client_ip)],
        ['Total time', mono(fmtMs(ev.total_ms))], ['Bytes in', mono(fmtBytes(ev.bytes_in))], ['Bytes out', mono(fmtBytes(ev.bytes_out))],
        ['Content type', mono(ev.content_type)], ['User agent', mono(ev.user_agent)], ['Referer', mono(ev.referer)],
        ['Site', mono(ev.site)], ['Backend', mono(ev.backend)], ['Server', mono(ev.server)],
      ]),
      h('h3', { class: 'section-title' }, 'Bot analysis'), botDetail(ev),
      h('h3', { class: 'section-title' }, 'Captured headers'), kvList(captureRows(ev))),
    footer: [blockPath, blockIp],
  });
}

function liveLog(node, getSite) {
  const n = nodeApi(node);
  const statusIn = h('input', { class: 'input mono', type: 'text', placeholder: 'Status', 'aria-label': 'Filter by status', size: '6' });
  const methodIn = h('select', { class: 'select', 'aria-label': 'Filter by method' }, h('option', { value: '' }, 'Any method'),
    ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].map((m) => h('option', { value: m }, m)));
  const pathIn = h('input', { class: 'input mono', type: 'search', placeholder: 'Path contains', 'aria-label': 'Filter by path' });
  const ipIn = h('input', { class: 'input mono', type: 'search', placeholder: 'Client IP', 'aria-label': 'Filter by IP' });
  const blockedIn = h('input', { type: 'checkbox', 'aria-label': 'Blocked only' });
  const tableHost = h('div', {});
  const stamp = h('span', { class: 'muted' }, 'waiting for data');
  const live = h('span', { class: 'live-badge' }, h('i', { class: 'dot dot-ok pulse' }), 'Live');
  let paused = false;
  let inflight = false;
  let signature = '';
  const pauseBtn = button('Pause', { iconName: 'pause', size: 'sm' });

  const columns = [
    { label: 'Time', render: (e) => h('span', { class: 'mono muted' }, fmtTime(e.ts_ms)) },
    { label: 'Status', render: (e) => pill(String(e.status), statusKind(e.status)) },
    { label: 'Method', render: (e) => h('span', { class: 'mono' }, e.method) },
    { label: 'Host', cls: 'hide-sm', render: (e) => h('span', { class: 'mono muted' }, e.host) },
    { label: 'Path', cls: 'cell-clip', render: (e) => h('span', { class: 'mono clip', title: e.path }, e.path) },
    { label: 'Client', cls: 'hide-sm', render: (e) => h('span', { class: 'mono' }, e.client_ip || '-') },
    { label: 'Bot', render: (e) => botCells(e).badge },
    { label: 'Score', align: 'right', cls: 'hide-sm', render: (e) => botCells(e).score },
    { label: 'Duration', align: 'right', render: (e) => h('span', { class: 'mono' }, fmtMs(e.total_ms)) },
    { label: 'Size', align: 'right', cls: 'hide-sm', render: (e) => h('span', { class: 'mono muted' }, fmtBytes(e.bytes_out)) },
    { label: '', render: (e) => (e.blocked ? pill('blocked', 'bad') : null) },
  ];

  // Skips a tick while paused, hidden or when the previous request is still running
  const poll = async (force = false) => {
    if (inflight || (!force && (paused || document.hidden))) return;
    inflight = true;
    try {
      const events = await n.get('/analytics/requests' + qs({
        limit: 100, status: statusIn.value.trim(), method: methodIn.value, path: pathIn.value.trim(), ip: ipIn.value.trim(),
        blocked: blockedIn.checked ? 'true' : '', site: getSite(),
      }));
      // A cheap fingerprint avoids rebuilding the table when nothing changed
      const sig = events.length + ':' + (events[0] ? events[0].ts_ms : 0) + ':' + (events.length ? events[events.length - 1].ts_ms : 0);
      stamp.textContent = 'updated ' + fmtTime(Date.now());
      if (sig !== signature) {
        signature = sig;
        clear(tableHost);
        tableHost.appendChild(dataTable({
          columns,
          rows: events,
          onRowClick: (e) => openEventSheet(node, e),
          rowLabel: (e) => `Open request ${e.method} ${e.path}`,
          empty: emptyState({ iconName: 'activity', title: 'No matching requests', text: 'Requests appear here as they arrive. Loosen the filters if you expect more.' }),
        }));
      }
    } catch (ex) {
      signature = '';
      clear(tableHost);
      tableHost.appendChild(errorState(ex, () => poll(true)));
    } finally {
      inflight = false;
    }
  };

  const refilter = () => {
    signature = '';
    poll(true);
  };
  let typing = 0;
  for (const el of [statusIn, pathIn, ipIn]) {
    el.addEventListener('input', () => {
      clearTimeout(typing);
      typing = setTimeout(refilter, 300);
    });
  }
  methodIn.addEventListener('change', refilter);
  blockedIn.addEventListener('change', refilter);
  pauseBtn.addEventListener('click', () => {
    paused = !paused;
    clear(pauseBtn);
    pauseBtn.append(icon(paused ? 'play' : 'pause'), h('span', {}, paused ? 'Resume' : 'Pause'));
    live.classList.toggle('paused', paused);
    live.lastChild.textContent = paused ? 'Paused' : 'Live';
  });

  tableHost.appendChild(skeletonBlock(220));
  poll(true);
  const timer = setInterval(poll, 3000);

  const el = card({
    title: 'Live requests',
    subtitle: 'Newest first, refreshed every 3 seconds',
    actions: [live, stamp, pauseBtn],
    body: h('div', { class: 'stack' },
      h('div', { class: 'filters' }, statusIn, methodIn, pathIn, ipIn, h('label', { class: 'check-row' }, blockedIn, h('span', {}, 'Blocked only'))),
      h('div', { class: 'card flush inner' }, tableHost)),
  });
  return { el, stop: () => clearInterval(timer), refresh: refilter };
}

export function trafficView(ctx) {
  ctx.setCrumbs([{ label: 'Traffic' }]);
  const node = currentNode();
  const body = h('div', { class: 'stack' });
  const analytics = h('div', {});
  const sitePick = h('select', { class: 'select', 'aria-label': 'Filter by site' }, h('option', { value: '' }, 'All sites'));
  let win = storage.get('window', '24h');
  if (!WINDOWS.includes(win)) win = '24h';
  let reload = null;
  let log = null;
  let reloadBots = null;
  let topEx = null;
  let storageBox = null;
  const reloadPanels = () => {
    reload();
    reloadBots();
    topEx.refresh();
  };

  const siteChoices = () => Array.from(sitePick.options).filter((o) => o.value).map((o) => ({ value: o.value, label: o.textContent }));
  const controls = h('div', { class: 'controls' },
    segmented({ label: 'Time window', options: WINDOWS.map((w) => ({ value: w, label: w })), value: win, onChange: (v) => { win = v; storage.set('window', v); reloadPanels(); } }),
    sitePick,
    button('', { iconName: 'refresh', title: 'Refresh', onClick: () => { reloadPanels(); storageBox.refresh(); if (log) log.refresh(); } }),
    button('Export', { iconName: 'download', title: 'Export analytics', onClick: () => openExportDialog({ node, win, sites: siteChoices(), site: sitePick.value }) }));
  const head = pageHeader({ title: 'Traffic', subtitle: node ? 'Analytics from ' + node : 'Requests, errors and blocked traffic', actions: node ? controls : null });
  ctx.root.append(...[head, nodeNotice(node), body].filter(Boolean));
  if (!node || !state.nodes.length) {
    body.appendChild(noNodes());
    return undefined;
  }

  const n = nodeApi(node);
  n.get('/sites').then((sites) => {
    for (const site of sites) sitePick.appendChild(h('option', { value: site.id }, site.name));
  }, () => {});
  const siteId = () => sitePick.value;

  body.append(analytics);
  reload = loadInto(analytics, async () => {
    const q = { window: win, site: siteId() };
    const [summary, series] = await Promise.all([n.get('/analytics/summary' + qs(q)), n.get('/analytics/timeseries' + qs(q))]);
    return { summary, series };
  }, renderAnalytics, { skeleton: () => h('div', { class: 'stack' }, skeletonCards(4), skeletonBlock(300)) });

  const botsHost = h('div', {});
  body.append(botsHost);
  reloadBots = loadInto(botsHost, () => n.get('/analytics/bots' + qs({ window: win, site: siteId() })), botsPanel, { skeleton: botsSkeleton });
  topEx = topExplorer(node, () => ({ window: win, site: siteId() }));
  storageBox = storageCard(node);
  body.append(topEx.el, storageBox.el);

  log = liveLog(node, siteId);
  body.append(log.el);
  sitePick.addEventListener('change', () => {
    reloadPanels();
    log.refresh();
  });
  return () => log.stop();
}
