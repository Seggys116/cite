import { h } from '../dom.js';
import { nodeApi } from '../api.js';
import { currentNode, state, themeMode, setTheme } from '../state.js';
import {
  pageHeader, button, iconButton, loadInto, card, pill, dataTable, emptyState, field, toggle, segmented, routeTabs,
  openModal, confirmDialog, toast, withBusy, formatError, copyText, kvList, fmtInt, fmtBytes, fmtDate, relTime, skeletonRows,
} from '../ui.js';
import { noNodes, nodeNotice, healthKind, healthDots } from './common.js';

const TABS = [
  { id: 'retention', label: 'Retention', icon: 'clock' },
  { id: 'limits', label: 'Limits', icon: 'bolt' },
  { id: 'tokens', label: 'API tokens', icon: 'key' },
  { id: 'audit', label: 'Audit log', icon: 'file' },
  { id: 'haproxy', label: 'HAProxy', icon: 'terminal' },
  { id: 'dashboard', label: 'Dashboard', icon: 'user' },
];

function numberField(label, value, { hint, nullable = false, min = 0 } = {}) {
  const input = h('input', { class: 'input mono', type: 'number', min: String(min), value: value === null || value === undefined ? '' : String(value), placeholder: nullable ? 'No limit' : '', 'aria-label': label });
  return {
    el: field(label, input, hint),
    read() {
      if (input.value === '' && nullable) return null;
      return Math.max(min, Math.floor(Number(input.value) || 0));
    },
  };
}

// Loads the current settings, lets the panel edit a copy and writes the whole object back
function settingsForm(node, { title, subtitle, build }) {
  const body = h('div', {});
  loadInto(body, () => nodeApi(node).get('/settings'), (settings) => {
    const { fields, collect } = build(settings);
    const save = button('Save changes', { kind: 'primary', iconName: 'check' });
    save.addEventListener('click', async () => {
      try {
        await withBusy(save, () => nodeApi(node).put('/settings', collect(settings)));
        toast('Settings saved', 'success');
      } catch (ex) {
        toast(formatError(ex), 'error');
      }
    });
    return card({ title, subtitle, body: h('div', { class: 'form' }, fields, h('div', { class: 'form-actions' }, save)) });
  });
  return body;
}

function retentionPanel(node) {
  return settingsForm(node, {
    title: 'Data retention',
    subtitle: 'How much traffic history the node keeps, and what each event records.',
    build(settings) {
      const r = settings.retention;
      const recent = numberField('Recent events kept in memory', r.recent_events, { hint: 'Powers the live request log.', min: 100 });
      const minutes = numberField('Minute buckets (hours)', r.minute_buckets_hours, { hint: 'Fine-grained history for short windows.', min: 1 });
      const hours = numberField('Hour buckets (days)', r.hour_buckets_days, { hint: 'Coarse history for 7 and 30 day windows.', min: 1 });
      const audit = numberField('Audit log (days)', r.audit_days, { min: 1 });
      const persist = numberField('Persist interval (seconds)', r.persist_interval_secs, { hint: 'How often analytics are written to disk.', min: 1 });
      const ua = toggle({ checked: r.store_user_agents, label: 'Store user agents' });
      const ip = toggle({ checked: r.store_client_ips, label: 'Store client IPs' });
      const fields = [
        h('div', { class: 'two-col narrow' }, recent.el, persist.el),
        h('div', { class: 'three-col' }, minutes.el, hours.el, audit.el),
        h('div', { class: 'switch-row' }, ua, h('div', {}, h('b', {}, 'Store user agents'), h('p', { class: 'muted' }, 'Needed for the user agent report and rules built from it.'))),
        h('div', { class: 'switch-row' }, ip, h('div', {}, h('b', {}, 'Store client IPs'), h('p', { class: 'muted' }, 'Needed for the top IP report and one-click IP blocking. Turn off to keep visitors anonymous.'))),
      ];
      const collect = (current) => ({
        ...current,
        retention: {
          ...current.retention,
          recent_events: recent.read(),
          minute_buckets_hours: minutes.read(),
          hour_buckets_days: hours.read(),
          audit_days: audit.read(),
          persist_interval_secs: persist.read(),
          store_user_agents: ua.isChecked(),
          store_client_ips: ip.isChecked(),
        },
      });
      return { fields, collect };
    },
  });
}

function limitsPanel(node) {
  return settingsForm(node, {
    title: 'Connection limits',
    subtitle: 'Protect the edge from overload. Changes apply on the next HAProxy reload.',
    build(settings) {
      const maxConn = numberField('Max connections', settings.max_conn, { min: 1 });
      const rate = numberField('Per-IP rate limit', settings.per_ip_rate_limit, { nullable: true, hint: 'Requests allowed per client address before throttling.' });
      const client = numberField('Client timeout (ms)', settings.client_timeout_ms, { min: 1 });
      const server = numberField('Server timeout (ms)', settings.server_timeout_ms, { min: 1 });
      const connect = numberField('Connect timeout (ms)', settings.connect_timeout_ms, { min: 1 });
      const body = numberField('Max body size (bytes)', settings.max_body_bytes, { nullable: true, hint: 'Larger uploads are rejected.' });
      const fields = [
        h('div', { class: 'two-col narrow' }, maxConn.el, rate.el),
        h('div', { class: 'three-col' }, client.el, server.el, connect.el),
        body.el,
        kvList([['HTTP port', h('span', { class: 'mono' }, String(settings.http_port))], ['HTTPS port', h('span', { class: 'mono' }, settings.https_port ? String(settings.https_port) : 'disabled')]]),
      ];
      const collect = (current) => ({
        ...current,
        max_conn: maxConn.read(),
        per_ip_rate_limit: rate.read(),
        client_timeout_ms: client.read(),
        server_timeout_ms: server.read(),
        connect_timeout_ms: connect.read(),
        max_body_bytes: body.read(),
      });
      return { fields, collect };
    },
  });
}

// The connector returns the token value once, so it is shown in a modal with a copy button
function showNewToken(token) {
  const modal = openModal({
    title: 'Copy your new token',
    content: h('div', { class: 'stack-sm' },
      h('p', { class: 'muted' }, 'This is the only time the token is shown. Store it somewhere safe.'),
      h('div', { class: 'secret' }, h('code', { class: 'mono wrap-any' }, token.token),
        iconButton('copy', 'Copy token', () => copyText(token.token, 'Token copied')))),
    actions: [button('Done', { kind: 'primary', onClick: () => modal.close() })],
  });
}

function tokensPanel(node) {
  const body = h('div', {});
  const nameIn = h('input', { class: 'input', type: 'text', placeholder: 'Token name, for example ci-deploy', 'aria-label': 'Token name' });
  let reload = null;
  const create = button('Create token', { kind: 'primary', iconName: 'plus' });
  create.addEventListener('click', async () => {
    if (!nameIn.value.trim()) {
      toast('Give the token a name first', 'error');
      nameIn.focus();
      return;
    }
    try {
      const token = await withBusy(create, () => nodeApi(node).post('/tokens', { name: nameIn.value.trim() }));
      nameIn.value = '';
      showNewToken(token);
      reload();
    } catch (ex) {
      toast(formatError(ex), 'error');
    }
  });
  const createCard = card({ title: 'Create a token', body: h('div', { class: 'inline-form' }, nameIn, create) });
  // The connector refuses token management to API tokens, which is how the dashboard authenticates, so a 403 means the node owner must do it there.
  const load = async () => {
    try {
      createCard.hidden = false;
      return await nodeApi(node).get('/tokens');
    } catch (ex) {
      if (ex && ex.status === 403) return null;
      throw ex;
    }
  };
  reload = loadInto(body, load, (tokens, again) => (tokens === null ? restrictedTokens(createCard) : dataTable({
    columns: [
      { label: 'Name', render: (t) => h('b', { class: 'cell-strong' }, t.name) },
      { label: 'Id', render: (t) => h('span', { class: 'mono muted' }, t.id) },
      { label: 'Created', render: (t) => fmtDate(t.created_at) },
      { label: 'Last used', render: (t) => (t.last_used_at ? relTime(t.last_used_at) : h('span', { class: 'muted' }, 'never')) },
      {
        label: '',
        align: 'right',
        render: (t) => iconButton('trash', 'Revoke token ' + t.name, async () => {
          const ok = await confirmDialog({ title: 'Revoke token', message: `Revoke ${t.name}? Anything using it stops working immediately.`, confirmLabel: 'Revoke', danger: true });
          if (!ok) return;
          try {
            await nodeApi(node).del('/tokens/' + encodeURIComponent(t.id));
            toast('Token revoked', 'success');
            again();
          } catch (ex) {
            toast(formatError(ex), 'error');
          }
        }),
      },
    ],
    rows: tokens,
    empty: emptyState({ iconName: 'key', title: 'No API tokens', text: 'Create a long-lived token for scripts and CI pipelines.' }),
  })));
  return h('div', { class: 'stack' }, createCard, card({ title: 'Tokens', flush: true, body }));
}

function restrictedTokens(createCard) {
  createCard.hidden = true;
  return emptyState({
    iconName: 'key',
    title: 'Tokens are managed on the node',
    text: 'This console signs in to the node with an API token, and the connector does not let an API token create or revoke tokens. Sign in to the node itself to manage them.',
  });
}

function auditPanel(node) {
  const body = h('div', {});
  loadInto(body, () => nodeApi(node).get('/audit?limit=200'), (rows) => dataTable({
    columns: [
      { label: 'When', render: (r) => h('span', { class: 'mono muted', title: fmtDate(r.at) }, relTime(r.at)) },
      { label: 'Actor', render: (r) => h('span', { class: 'mono' }, r.actor) },
      { label: 'Action', render: (r) => pill(r.action, 'muted') },
      { label: 'Detail', render: (r) => r.detail },
    ],
    rows,
    empty: emptyState({ iconName: 'file', title: 'Audit log is empty', text: 'Changes made through the API are recorded here.' }),
  }), { skeleton: () => skeletonRows(8) });
  return card({ title: 'Audit log', subtitle: 'Most recent 200 entries', flush: true, body });
}

// Combines /node (process state) and /haproxy/stats (per backend health) with reload and config actions
function haproxyPanel(node) {
  const n = nodeApi(node);
  const body = h('div', {});
  let reload = null;
  const viewConfig = async () => {
    try {
      const text = await n.get('/haproxy/config');
      const modal = openModal({
        title: 'Rendered haproxy.cfg',
        wide: true,
        content: h('pre', { class: 'code-block' }, String(text)),
        actions: [button('Copy', { iconName: 'copy', onClick: () => copyText(String(text), 'Config copied') }), button('Close', { kind: 'primary', onClick: () => modal.close() })],
      });
    } catch (ex) {
      toast(formatError(ex), 'error');
    }
  };
  const reloadBtn = button('Reload HAProxy', { kind: 'primary', iconName: 'refresh' });
  reloadBtn.addEventListener('click', async () => {
    try {
      const res = await withBusy(reloadBtn, () => n.post('/haproxy/reload'));
      toast(res && res.ok === false ? 'Reload reported a problem' : 'HAProxy reloaded', res && res.ok === false ? 'error' : 'success');
      reload();
    } catch (ex) {
      toast(formatError(ex), 'error');
    }
  });
  reload = loadInto(body, async () => {
    const [info, stats] = await Promise.all([n.get('/node'), n.get('/haproxy/stats').catch(() => ({ backends: [] }))]);
    return { info, stats };
  }, ({ info, stats }) => {
    const hap = info.haproxy || {};
    const backends = stats.backends || [];
    return h('div', { class: 'stack' },
      card({
        title: 'Process',
        actions: [button('View config', { iconName: 'file', onClick: viewConfig }), reloadBtn],
        body: kvList([
          ['State', hap.running ? pill('Running', 'ok') : pill('Stopped', 'bad')],
          ['Config hash', h('code', { class: 'mono' }, hap.config_hash || '-')],
          ['Last reload', hap.last_reload_at ? `${fmtDate(hap.last_reload_at)} (${relTime(hap.last_reload_at)})` : 'never'],
          ['Reload result', hap.last_reload_ok === false ? pill('Failed', 'bad') : pill('OK', 'ok')],
          hap.last_error ? ['Last error', h('code', { class: 'mono bad-text wrap-any' }, hap.last_error)] : null,
        ].filter(Boolean)),
      }),
      card({
        title: 'Backends',
        flush: true,
        body: dataTable({
          columns: [
            { label: 'Backend', render: (b) => h('b', { class: 'mono cell-strong' }, b.name) },
            { label: 'Status', render: (b) => pill(b.status, healthKind(b.status) === 'ok' ? 'ok' : healthKind(b.status) === 'bad' ? 'bad' : 'warn') },
            { label: 'Servers', render: (b) => healthDots((b.servers || []).map((sv) => ({ addr: sv.name, status: sv.status }))) },
            { label: 'Sessions', align: 'right', render: (b) => h('span', { class: 'mono' }, fmtInt(b.sessions)) },
            { label: 'In', align: 'right', render: (b) => h('span', { class: 'mono muted' }, fmtBytes(b.bytes_in)) },
            { label: 'Out', align: 'right', render: (b) => h('span', { class: 'mono muted' }, fmtBytes(b.bytes_out)) },
          ],
          rows: backends,
          empty: emptyState({ iconName: 'terminal', title: 'No backends reported', text: 'Backends appear once a site exists and HAProxy is running.' }),
        }),
      }));
  });
  return body;
}

function dashboardPanel(ctx) {
  const theme = segmented({
    label: 'Theme',
    value: themeMode(),
    options: [{ value: 'system', label: 'System' }, { value: 'light', label: 'Light' }, { value: 'dark', label: 'Dark' }],
    onChange: setTheme,
  });
  return h('div', { class: 'stack' },
    card({ title: 'Appearance', body: h('div', { class: 'form' }, field('Theme', theme, 'System follows your operating system setting.', { group: true })) }),
    card({
      title: 'Session',
      body: h('div', { class: 'danger-row' }, h('div', {}, h('b', {}, 'Signed in as ' + (state.user || 'admin')), h('p', { class: 'muted' }, 'Signing out ends this browser session only.')),
        button('Sign out', { iconName: 'logout', onClick: ctx.signOut })),
    }));
}

export function settingsView(ctx) {
  const tab = TABS.some((t) => t.id === ctx.params[0]) ? ctx.params[0] : 'retention';
  ctx.setCrumbs([{ label: 'Settings' }, { label: TABS.find((t) => t.id === tab).label }]);
  const node = currentNode();
  const perNode = tab !== 'dashboard';
  const holder = h('div', { class: 'tab-panel' });
  ctx.root.append(...[
    pageHeader({ title: 'Settings', subtitle: perNode && node ? 'Configuration of ' + node : 'Console preferences' }),
    routeTabs(TABS, tab, (t) => '#/settings/' + t),
    perNode ? nodeNotice(node) : null,
    holder,
  ].filter(Boolean));
  if (!perNode) {
    holder.appendChild(dashboardPanel(ctx));
    return;
  }
  if (!node) {
    holder.appendChild(noNodes());
    return;
  }
  const panels = { retention: retentionPanel, limits: limitsPanel, tokens: tokensPanel, audit: auditPanel, haproxy: haproxyPanel };
  holder.appendChild(panels[tab](node));
}
