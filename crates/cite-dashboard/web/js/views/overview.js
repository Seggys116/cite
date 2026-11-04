import { h, icon } from '../dom.js';
import { api, nodeApi, qs } from '../api.js';
import { selectNode } from '../state.js';
import { sparkline } from '../charts.js';
import {
  pageHeader, button, loadInto, skeletonCards, skeletonBlock, card, pill, dataTable, emptyState,
  fmtNum, fmtPct, fmtUptime, relTime,
} from '../ui.js';
import { actionPill, slotPill, settledValue, listOf } from './common.js';

const count = (v) => (Array.isArray(v) ? v.length : Number(v) || 0);

// A summary row may wrap the node info or carry it flat, so accept both shapes
function normalize(entry) {
  const info = entry.node || entry.info || entry;
  return {
    name: entry.name || info.name,
    online: entry.online ?? entry.ok ?? !entry.error,
    error: entry.error || '',
    version: info.version || '',
    uptime: info.uptime_secs,
    haproxy: info.haproxy || null,
    sites: count(info.sites),
    rules: count(info.firewall_rules),
  };
}

async function load() {
  const entries = listOf(await api.get('/nodes/summary')).map(normalize);
  const extra = await Promise.all(entries.filter((e) => e.online).map(async (e) => {
    const n = nodeApi(e.name);
    const [sum, series, sites] = await Promise.allSettled([
      n.get('/analytics/summary' + qs({ window: '15m' })),
      n.get('/analytics/timeseries' + qs({ window: '1h' })),
      n.get('/sites'),
    ]);
    return { name: e.name, summary: settledValue(sum), series: settledValue(series), sites: settledValue(sites) || [] };
  }));
  return { entries, extra };
}

function statCard(iconName, label, value, sub, tone = '') {
  return h('div', { class: ('stat ' + tone).trim() },
    h('div', { class: 'stat-top' }, icon(iconName), h('span', {}, label)),
    h('div', { class: 'stat-value mono' }, value),
    h('div', { class: 'stat-sub muted' }, sub));
}

function render({ entries, extra }) {
  const online = entries.filter((e) => e.online).length;
  const sum = (pick) => extra.reduce((total, e) => total + (e.summary ? Number(pick(e.summary)) || 0 : 0), 0);
  const requests = sum((s) => s.requests);
  const errors = sum((s) => (s.errors_4xx || 0) + (s.errors_5xx || 0));
  const blocked = sum((s) => s.blocked);
  const totalSites = entries.reduce((total, e) => total + e.sites, 0);

  const stats = h('div', { class: 'grid-stats' },
    statCard('server', 'Nodes online', `${online}/${entries.length}`, online === entries.length ? 'All nodes reachable' : `${entries.length - online} unreachable`, online < entries.length ? 'warn' : ''),
    statCard('globe', 'Sites', fmtNum(totalSites), 'Across all nodes'),
    statCard('activity', 'Requests / min', fmtNum(requests / 15), 'Averaged over 15 minutes'),
    statCard('alert', 'Error rate', requests ? fmtPct(errors / requests, 2) : '0.00%', `${fmtNum(errors)} 4xx and 5xx responses`, requests && errors / requests > 0.05 ? 'bad' : ''),
    statCard('ban', 'Blocked', fmtNum(blocked), 'Stopped by the firewall'));

  const healthCards = entries.length ? h('div', { class: 'grid-nodes' }, entries.map((e) => {
    const ex = extra.find((x) => x.name === e.name);
    const points = ex && ex.series ? ex.series.points || [] : [];
    const hap = e.haproxy;
    return h('article', { class: 'node-card' + (e.online ? '' : ' offline') },
      h('header', { class: 'node-card-head' },
        h('div', {}, h('h3', {}, e.name), h('p', { class: 'muted mono' }, e.version ? 'v' + e.version : 'version unknown')),
        e.online ? pill('Online', 'ok') : pill('Offline', 'bad')),
      e.online
        ? h('div', { class: 'node-metrics' },
          h('div', {}, h('span', { class: 'muted' }, 'Uptime'), h('b', { class: 'mono' }, fmtUptime(e.uptime))),
          h('div', {}, h('span', { class: 'muted' }, 'Sites'), h('b', { class: 'mono' }, String(e.sites))),
          h('div', {}, h('span', { class: 'muted' }, 'Rules'), h('b', { class: 'mono' }, String(e.rules))),
          h('div', {}, h('span', { class: 'muted' }, 'HAProxy'), hap ? pill(hap.running ? 'running' : 'stopped', hap.running ? 'ok' : 'bad') : pill('unknown', 'muted')))
        : h('p', { class: 'muted' }, e.error || 'The connector did not respond.'),
      e.online ? h('div', { class: 'node-spark' }, sparkline(points.map((p) => p.requests || 0), { width: 280, height: 40 }), h('span', { class: 'muted' }, 'requests, last hour')) : null,
      h('footer', {}, h('a', {
        class: 'link',
        href: '#/sites',
        onClick: () => selectNode(e.name),
      }, 'Open sites')));
  })) : emptyState({ iconName: 'server', title: 'No nodes yet', text: 'Add a node to start managing sites.', action: h('a', { class: 'btn btn-primary', href: '#/nodes' }, 'Add a node') });

  const deployments = extra.flatMap((e) => e.sites.flatMap((site) => (site.history || []).map((d) => ({ ...d, node: e.name, site: site.name }))))
    .sort((a, b) => String(b.at).localeCompare(String(a.at))).slice(0, 8);

  const recent = card({
    title: 'Recent deployments',
    subtitle: 'Latest activity across nodes',
    flush: true,
    body: dataTable({
      columns: [
        { label: 'When', render: (d) => relTime(d.at) },
        { label: 'Node', render: (d) => h('span', { class: 'mono' }, d.node) },
        { label: 'Site', render: (d) => d.site },
        { label: 'Action', render: (d) => actionPill(d.action) },
        { label: 'Slot', render: (d) => slotPill(d.slot) },
        { label: 'Note', render: (d) => h('span', { class: 'muted' }, d.note || '-') },
      ],
      rows: deployments,
      empty: emptyState({ iconName: 'rocket', title: 'No deployments yet', text: 'Deploys, switches and rollbacks are listed here.' }),
    }),
  });

  return h('div', { class: 'stack' }, stats, h('h2', { class: 'section-title' }, 'Node health'), healthCards, recent);
}

export function overviewView(ctx) {
  ctx.setCrumbs([{ label: 'Overview' }]);
  const body = h('div', {});
  let reload = null;
  const refresh = button('Refresh', { iconName: 'refresh', onClick: () => reload && reload() });
  ctx.root.append(pageHeader({ title: 'Overview', subtitle: 'Health and traffic across every connected node', actions: refresh }), body);
  reload = loadInto(body, load, render, { skeleton: () => h('div', { class: 'stack' }, skeletonCards(5), skeletonBlock(180), skeletonBlock(220)) });
}
