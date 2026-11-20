import { h } from '../dom.js';
import { api, nodeApi } from '../api.js';
import { state } from '../state.js';
import {
  button, card, confirmDialog, dataTable, emptyState, kvList, loadInto, pageHeader, pill, skeletonBlock, startNavigation, toast, withBusy,
  formatError, fmtBytes, fmtDate, relTime,
} from '../ui.js';
import { nodeInfoCached } from '../caplib.js';
import { noNodes } from './common.js';
import { chooseNodeNotice, nodeScopeBar, rememberScope, scopeFor } from './nodeScope.js';
import {
  checkRow, formDialog, jobRunner, jobStrip, note, progressBar, selectInput, textInput, tradeoffTable,
} from './siteData.js';
import {
  anyRunning, pollUntil, transferRows,
  DEFAULT_MAJOR, KEY_BACKUP_NOTE, PG_MAJORS, WRITE_ONLY_CREDENTIALS,
  cpusOf, dataFeatures, healthKind, orphanText, sharedBody, sharedDeleteText, sharedProblem, sharedToForm, sharedUpdateText, showsDatabasesPage,
  statusKind, statusText, targetBody, targetProblem, targetTestText, targetToForm, tenantRows,
} from '../datalib.js';

const enc = encodeURIComponent;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// The node-level Databases page: the shared instance, its tenants and backups, S3 backup targets and leftovers of deleted sites.
// Route shape: #/databases
export function databasesView(ctx) {
  ctx.setCrumbs([{ label: 'Databases' }]);
  let node = scopeFor('databases', state);
  let mounted = 0;
  const holder = h('div', { class: 'stack' });
  const scope = state.nodes.length
    ? nodeScopeBar({
      nodes: state.nodes,
      selected: node,
      onChange: (name) => {
        node = name;
        rememberScope('databases', state, name);
        mount();
      },
    })
    : null;
  ctx.root.append(...[
    pageHeader({ title: 'Databases', subtitle: 'The shared Postgres instance of a node, its backups and the data left behind by deleted sites' }),
    scope,
    holder,
  ].filter(Boolean));

  function mount() {
    mounted += 1;
    const ticket = mounted;
    holder.replaceChildren();
    if (!node) {
      holder.append(state.nodes.length ? chooseNodeNotice() : noNodes());
      return;
    }
    const target = node;
    holder.append(skeletonBlock(160));
    nodeInfoCached(target, () => nodeApi(target).get('/node')).then((info) => info, () => null).then((info) => {
      if (ticket !== mounted) return;
      if (!showsDatabasesPage(info)) {
        holder.replaceChildren(emptyState({
          iconName: 'layers', title: 'Databases are not available on this node', text: 'Update the connector to use the data services.',
        }));
        return;
      }
      holder.replaceChildren(databasesPanel(target, info));
    });
  }
  mount();
  // Leaving the page ends any job being followed, because the progress line is no longer on screen
  return () => { mounted += 1; };
}

function databasesPanel(node, info) {
  const n = nodeApi(node);
  const f = dataFeatures(info);
  const strip = jobStrip(node);
  const body = h('div', { class: 'stack' });
  const root = h('div', { class: 'stack' }, strip.el, body);

  loadInto(body, async () => {
    const nodeData = await n.get('/data');
    if (nodeData && nodeData.enabled === false) return { disabled: true };
    const [shared, backups, targets, orphans, transfers] = await Promise.all([
      f.shared ? n.get('/data/shared').catch(() => null) : null,
      f.shared ? n.get('/data/shared/backups').catch(() => []) : [],
      n.get('/data/targets').catch(() => []),
      n.get('/data/orphans').catch(() => []),
      f.transfer ? api.get('/transfers').catch(() => []) : [],
    ]);
    return {
      disabled: false,
      nodeData: nodeData || {},
      shared,
      backups: Array.isArray(backups) ? backups : [],
      targets: Array.isArray(targets) ? targets : [],
      orphans: Array.isArray(orphans) ? orphans : [],
      transfers: Array.isArray(transfers) ? transfers : [],
    };
  }, (model, again) => {
    if (model.disabled) {
      return emptyState({
        iconName: 'layers', title: 'Data services are not enabled on this node', text: 'The node was started without the data services. Enable them in the node configuration, then reload.',
      });
    }
    const runner = jobRunner({ strip, refresh: again, offerRedeploy: null });
    const ctx = {
      n, node, f, model, refresh: again, ...runner,
    };
    return [
      keyCard(ctx),
      f.shared ? sharedCard(ctx) : null,
      f.shared && model.shared && model.shared.enabled ? tenantsCard(ctx) : null,
      f.shared && model.shared && model.shared.enabled ? instanceBackupsCard(ctx) : null,
      f.transfer ? transfersCard(ctx) : null,
      targetsCard(ctx),
      orphansCard(ctx),
    ].filter(Boolean);
  }, { skeleton: () => skeletonBlock(180) });
  return root;
}

// ---- Secrets key ----

function keyCard(ctx) {
  const { nodeData } = ctx.model;
  const key = nodeData.key || {};
  const rows = [
    ['Key id', key.kid ? h('code', { class: 'mono' }, key.kid) : h('span', { class: 'muted' }, 'unknown')],
    ['Key source', key.source === 'managed' ? 'Managed by the node, on its own volume' : key.source === 'file' ? 'A key file' : key.source === 'env' ? 'An environment variable' : h('span', { class: 'muted' }, 'unknown')],
    ['Backup volume', nodeData.backup_volume_ok === false ? pill('not mounted', 'bad') : pill('ready', 'ok')],
  ];
  return card({
    title: 'Encryption key and backup volume',
    subtitle: 'Backups and the secrets file are encrypted with the node key.',
    body: h('div', { class: 'stack-sm' }, kvList(rows), note(KEY_BACKUP_NOTE),
      key.source === 'managed' ? note('The managed key sits on the same volume as the data. It protects single copied files and S3 dumps, not theft of the whole volume. Use a key file on a separate mount for that.') : null),
  });
}

// ---- Shared instance ----

function sharedFormFields(initial, creating) {
  const major = selectInput({
    label: 'Postgres major',
    options: PG_MAJORS.map((m) => ({ value: String(m), label: m === DEFAULT_MAJOR ? `PostgreSQL ${m} (default)` : `PostgreSQL ${m}` })),
    value: initial.major,
    hint: 'Fixed once the instance exists. Upgrading means moving every tenant.',
  });
  const memory = textInput({ label: 'Memory limit (MiB)', mono: true, type: 'number', value: initial.memoryMb, hint: '256 to 65536.' });
  const cpus = textInput({ label: 'CPUs', mono: true, type: 'number', value: initial.cpus, hint: '0.25 to 64.' });
  const conns = textInput({ label: 'Max connections', mono: true, type: 'number', value: initial.maxConnections, hint: '10 to 1000, shared by every tenant.' });
  const read = () => ({
    major: major.input.value, memoryMb: memory.input.value, cpus: cpus.input.value, maxConnections: conns.input.value,
  });
  const el = h('div', { class: 'stack-sm' }, creating ? major.el : null, h('div', { class: 'three-col data-limits' }, memory.el, cpus.el, conns.el));
  return { el, read };
}

function sharedCard(ctx) {
  const view = ctx.model.shared;
  return card({
    title: 'Shared instance',
    subtitle: 'One Postgres for every site that chooses a shared database on this node.',
    actions: view && view.enabled ? sharedActions(ctx, view) : null,
    body: view && view.enabled ? sharedDetails(view) : sharedOff(ctx),
  });
}

function sharedOff(ctx) {
  const fields = sharedFormFields(sharedToForm(null), true);
  const enable = button('Enable the shared instance', { kind: 'primary', iconName: 'check' });
  const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
  enable.addEventListener('click', async () => {
    err.hidden = true;
    const form = fields.read();
    const problem = sharedProblem(form, { creating: true });
    if (problem) {
      err.textContent = problem;
      err.hidden = false;
      return;
    }
    await ctx.go(enable, 'Enabling the shared instance', () => ctx.n.put('/data/shared', sharedBody(form, { creating: true })));
  });
  return h('div', { class: 'stack' },
    note('The shared instance is not enabled. Enable it so sites can pick a shared database.'),
    tradeoffTable(''), fields.el, err, h('div', { class: 'form-actions' }, enable));
}

function sharedDetails(view) {
  const tenants = tenantRows(view);
  const rows = [
    ['Health', view.health ? pill(view.health, healthKind(view.health)) : h('span', { class: 'muted' }, 'unknown')],
    ['Postgres major', `PostgreSQL ${view.major}`],
    ['Size on disk', view.size_bytes ? fmtBytes(view.size_bytes) : h('span', { class: 'muted' }, 'not measured yet')],
    ['Memory', `${view.memory_mb} MiB`],
    ['CPUs', String(cpusOf(view.nano_cpus))],
    ['Max connections', String(view.max_connections)],
    ['Tenants', `${tenants.length} ${tenants.length === 1 ? 'site' : 'sites'}`],
  ];
  return h('div', { class: 'stack' }, kvList(rows), tradeoffTable(''));
}

function sharedActions(ctx, view) {
  const tenants = tenantRows(view);
  const edit = button('Edit limits', { size: 'sm', iconName: 'edit', onClick: () => editShared(ctx, view) });
  const restart = button('Restart', {
    size: 'sm', iconName: 'refresh', title: 'Restart the shared instance',
    onClick: async () => {
      const ok = await confirmDialog({
        title: 'Restart the shared instance',
        message: `Restarting interrupts every tenant (${tenants.length} ${tenants.length === 1 ? 'site' : 'sites'}) while Postgres comes back. Connections drop and apps see errors for a moment.`,
        confirmLabel: 'Restart', danger: true,
      });
      if (ok) await ctx.go(restart, 'Restarting the shared instance', () => ctx.n.post('/data/shared/restart'));
    },
  });
  const del = button('Delete', { size: 'sm', kind: 'danger', iconName: 'trash', title: 'Delete the shared instance', onClick: () => deleteShared(ctx, view) });
  if (tenants.length) {
    del.disabled = true;
    del.title = `${tenants.length} ${tenants.length === 1 ? 'site still uses' : 'sites still use'} this instance. Turn Postgres off on them or move them first.`;
  }
  return h('div', { class: 'pill-row' }, edit, restart, del);
}

function editShared(ctx, view) {
  const fields = sharedFormFields(sharedToForm(view), false);
  formDialog({
    title: 'Edit the shared instance',
    submitLabel: 'Save and restart',
    wide: true,
    body: h('div', { class: 'stack-sm' }, note(sharedUpdateText()), fields.el),
    validate: () => sharedProblem(fields.read(), { creating: false }),
    onSubmit: async () => {
      const accepted = await ctx.n.put('/data/shared', sharedBody(fields.read(), { creating: false }));
      return () => ctx.follow(accepted, 'Updating the shared instance');
    },
  });
}

function deleteShared(ctx, view) {
  const purge = h('input', { type: 'checkbox' });
  formDialog({
    title: 'Delete the shared instance',
    submitLabel: 'Delete instance',
    kind: 'danger',
    body: h('div', { class: 'stack-sm' },
      h('p', { class: 'dialog-text' }, sharedDeleteText(view)),
      checkRow(purge, 'Also delete the data volumes and the stored superuser password (cannot be undone)')),
    onSubmit: async () => {
      const accepted = await ctx.n.del(`/data/shared${purge.checked ? '?purge=true' : ''}`);
      return () => ctx.follow(accepted, 'Deleting the shared instance');
    },
  });
}

// ---- Tenants ----

function tenantsCard(ctx) {
  const rows = tenantRows(ctx.model.shared);
  return card({
    title: 'Tenants',
    subtitle: 'Sites that use the shared instance, with the size of each database.',
    flush: rows.length > 0,
    body: dataTable({
      columns: [
        { label: 'Site', render: (t) => h('a', { class: 'mono', href: `#/sites/${enc(ctx.node)}/${enc(t.site)}/data` }, t.site) },
        {
          label: 'Databases',
          render: (t) => h('span', { class: 'wrap-any' }, t.databases.length
            ? t.databases.map((d) => `${d.name} (${fmtBytes(d.size_bytes)})`).join(', ')
            : h('span', { class: 'muted' }, 'none')),
        },
        { label: 'Total', align: 'right', render: (t) => fmtBytes(t.size) },
      ],
      rows,
      empty: h('p', { class: 'muted' }, 'No site uses the shared instance yet.'),
    }),
  });
}

// ---- Whole-instance backups ----

function instanceBackupsCard(ctx) {
  const list = [...ctx.model.backups].sort((a, b) => (a.created_at < b.created_at ? 1 : -1));
  const create = button('Back up the instance', { size: 'sm', iconName: 'download', onClick: async () => {
    await ctx.go(create, 'Backing up the shared instance', () => ctx.n.post('/data/shared/backups'));
  } });
  return card({
    title: 'Instance backups',
    subtitle: 'Every tenant database in one archive.',
    actions: create,
    body: h('div', { class: 'stack-sm' },
      dataTable({
        columns: [
          { label: 'Created', render: (b) => h('span', { title: fmtDate(b.created_at) }, relTime(b.created_at)) },
          { label: 'Databases', render: (b) => String((b.parts || []).length) },
          { label: 'Size', align: 'right', render: (b) => fmtBytes((b.parts || []).reduce((total, p) => total + (p.size_bytes || 0), 0)) },
          { label: 'Status', render: (b) => pill(statusText(b.status), statusKind(b.status)) },
          { label: '', align: 'right', render: (b) => instanceBackupActions(ctx, b) },
        ],
        rows: list,
        empty: h('p', { class: 'muted' }, 'No instance backups yet.'),
      }),
      note('Restoring a whole-instance backup is manual in this release: download it and restore the part you need. Restoring a version from a site Data tab covers a single tenant.')),
  });
}

function instanceBackupActions(ctx, b) {
  const download = button('Download', {
    size: 'sm', iconName: 'download', title: `Download the instance backup of ${fmtDate(b.created_at)}`,
    onClick: () => {
      startNavigation(`/api/v1/nodes/${enc(ctx.node)}/data/shared/backups/${enc(b.id)}/download`);
      toast('Download started', 'info');
    },
  });
  download.disabled = b.status !== 'ok';
  const del = button('Delete', {
    size: 'sm', kind: 'danger', iconName: 'trash', title: `Delete the instance backup of ${fmtDate(b.created_at)}`,
    onClick: async () => {
      const ok = await confirmDialog({ title: 'Delete the instance backup', message: `Delete the backup of ${fmtDate(b.created_at)}. This cannot be undone.`, confirmLabel: 'Delete', danger: true });
      if (!ok) return;
      await withBusy(del, async () => {
        try {
          await ctx.n.del(`/data/shared/backups/${enc(b.id)}`);
          toast('Instance backup deleted', 'success');
          ctx.refresh();
        } catch (ex) {
          toast(formatError(ex), 'error', 15000);
        }
      });
    },
  });
  return h('div', { class: 'row-actions' }, download, del);
}

// ---- Transfers between nodes ----

// Every transfer the console knows about, across nodes. The list is read again while one is running, and a site's Data tab holds the controls.
function transfersCard(ctx) {
  const host = h('div', {});
  let list = ctx.model.transfers;
  const draw = () => host.replaceChildren(dataTable({
    columns: [
      { label: 'Site', render: (t) => h('a', { class: 'mono', href: `#/sites/${enc(t.source)}/${enc(t.site)}/data` }, t.site) },
      { label: 'Database', render: (t) => h('span', { class: 'mono' }, t.database) },
      {
        label: 'Move',
        render: (t) => h('span', { class: 'wrap-any' },
          h('a', { href: `#/sites/${enc(t.source)}/${enc(t.site)}/data` }, t.source), ' to ',
          h('a', { href: `#/sites/${enc(t.target)}/${enc(t.site)}/data` }, t.target)),
      },
      {
        label: 'Phase',
        render: (t) => h('span', { class: 'pill-row' }, pill(t.label, t.kind), t.awaiting ? pill('needs your decision', 'warn') : null,
          t.error ? h('span', { class: 'error-text wrap-any', title: t.error }, t.error) : null),
      },
      { label: 'Progress', render: (t) => h('span', { class: 'data-bar-cell' }, progressBar(t.percent, `Progress of the move of ${t.site}`), `${t.percent}%`) },
      { label: 'Updated', render: (t) => h('span', { title: fmtDate(t.updatedAt) }, relTime(t.updatedAt)) },
    ],
    rows: transferRows(list),
    empty: h('p', { class: 'muted' }, 'No transfers yet. Start one from the Data tab of a site.'),
  }));
  async function watch() {
    try {
      await pollUntil({
        get: () => api.get('/transfers'),
        finished: (next) => !anyRunning(next),
        sleep,
        alive: () => host.isConnected,
        hidden: () => document.hidden,
        onUpdate: (next) => { list = Array.isArray(next) ? next : []; draw(); },
      });
    } catch (ex) {
      toast(`Transfers: ${formatError(ex)}`, 'error', 15000);
    }
  }
  draw();
  if (anyRunning(list)) setTimeout(watch, 0);
  return card({
    title: 'Transfers between nodes',
    subtitle: 'Running and recently finished moves of a database from one node to another. A transfer never deletes the source database.',
    body: host,
  });
}

// ---- S3 backup targets ----

function targetsCard(ctx) {
  const list = ctx.model.targets;
  const result = h('p', { class: 'muted', role: 'status', 'aria-live': 'polite' });
  const add = button('Add target', { size: 'sm', iconName: 'plus', onClick: () => targetDialog(ctx, null) });
  return card({
    title: 'Backup targets',
    subtitle: 'S3 buckets that hold copies of backups. They are separate from the buckets a site uses, so an app cannot delete its own backups.',
    actions: add,
    body: h('div', { class: 'stack-sm' },
      dataTable({
        columns: [
          { label: 'Name', render: (t) => h('span', { class: 'cell-strong' }, t.name) },
          { label: 'Endpoint', render: (t) => h('span', { class: 'mono wrap-any' }, t.endpoint) },
          { label: 'Bucket', render: (t) => h('span', { class: 'mono' }, t.bucket) },
          { label: 'Region', render: (t) => t.region },
          { label: 'Prefix', render: (t) => (t.prefix ? h('span', { class: 'mono' }, t.prefix) : h('span', { class: 'muted' }, '-')) },
          { label: 'Encrypted', render: (t) => (t.encrypt ? pill('yes', 'ok') : pill('no', 'warn')) },
          { label: '', align: 'right', render: (t) => targetActions(ctx, t, result) },
        ],
        rows: list,
        empty: h('p', { class: 'muted' }, 'No targets yet. Add one to keep backup copies off the node.'),
      }),
      result),
  });
}

function targetActions(ctx, t, result) {
  const test = button('Test', {
    size: 'sm', iconName: 'bolt', title: `Test ${t.name}`,
    onClick: () => withBusy(test, async () => {
      result.textContent = `Testing ${t.name}...`;
      try {
        const res = await ctx.n.post(`/data/targets/${enc(t.id)}/test`);
        result.textContent = `${t.name}: ${targetTestText(res)}`;
        result.className = res && res.ok ? 'muted' : 'error-text';
      } catch (ex) {
        result.textContent = `${t.name}: ${formatError(ex)}`;
        result.className = 'error-text';
      }
    }),
  });
  const edit = button('Edit', { size: 'sm', iconName: 'edit', title: `Edit ${t.name}`, onClick: () => targetDialog(ctx, t) });
  const del = button('Delete', {
    size: 'sm', kind: 'danger', iconName: 'trash', title: `Delete ${t.name}`,
    onClick: async () => {
      const ok = await confirmDialog({
        title: `Delete ${t.name}`,
        message: 'The node forgets the keys. Copies already in the bucket stay there. The node refuses while a backup policy still uses this target.',
        confirmLabel: 'Delete target', danger: true,
      });
      if (!ok) return;
      await withBusy(del, async () => {
        try {
          await ctx.n.del(`/data/targets/${enc(t.id)}`);
          toast(`${t.name} deleted`, 'success');
          ctx.refresh();
        } catch (ex) {
          toast(formatError(ex), 'error', 15000);
        }
      });
    },
  });
  return h('div', { class: 'row-actions' }, test, edit, del);
}

function targetDialog(ctx, existing) {
  const init = targetToForm(existing);
  const name = textInput({ label: 'Name', value: init.name, placeholder: 'offsite' });
  const endpoint = textInput({ label: 'Endpoint', mono: true, value: init.endpoint, placeholder: 'https://s3.eu-west-1.amazonaws.com', hint: 'Must be https.' });
  const bucket = textInput({ label: 'Bucket', mono: true, value: init.bucket });
  const region = textInput({ label: 'Region', mono: true, value: init.region, placeholder: 'eu-west-1' });
  const prefix = textInput({ label: 'Key prefix (optional)', mono: true, value: init.prefix, placeholder: 'cite/', hint: 'Copies are stored under this prefix.' });
  const pathStyle = h('input', { type: 'checkbox', checked: init.pathStyle });
  const encrypt = h('input', { type: 'checkbox', checked: init.encrypt });
  const keyId = textInput({ label: 'Access key id', mono: true, secret: true, hint: existing ? 'Leave both keys blank to keep the stored ones.' : WRITE_ONLY_CREDENTIALS });
  const secret = textInput({ label: 'Secret access key', mono: true, secret: true, hint: WRITE_ONLY_CREDENTIALS });
  const form = () => ({
    name: name.input.value, endpoint: endpoint.input.value, bucket: bucket.input.value, region: region.input.value, prefix: prefix.input.value,
    pathStyle: pathStyle.checked, encrypt: encrypt.checked, accessKeyId: keyId.input.value, secretAccessKey: secret.input.value,
  });
  formDialog({
    title: existing ? `Edit ${existing.name}` : 'Add a backup target',
    submitLabel: existing ? 'Save' : 'Add target',
    wide: true,
    body: h('div', { class: 'stack-sm' }, name.el, endpoint.el, h('div', { class: 'two-col' }, bucket.el, region.el), prefix.el,
      checkRow(pathStyle, 'Path style addressing (MinIO and similar)'),
      checkRow(encrypt, 'Encrypt copies before they leave the node'),
      h('div', { class: 'two-col' }, keyId.el, secret.el)),
    validate: () => targetProblem(form(), { hasKeys: Boolean(existing) }),
    onSubmit: async () => {
      const body = targetBody(form());
      if (existing) await ctx.n.put(`/data/targets/${enc(existing.id)}`, body);
      else await ctx.n.post('/data/targets', body);
      keyId.input.value = '';
      secret.input.value = '';
      return () => {
        toast('Backup target saved', 'success');
        ctx.refresh();
      };
    },
  });
}

// ---- Orphans ----

function orphansCard(ctx) {
  const list = ctx.model.orphans;
  return card({
    title: 'Left behind by deleted sites',
    subtitle: 'Data kept when a site was deleted without deleting its data. A new site with the same id picks it up again; purge removes it for good.',
    flush: list.length > 0,
    body: dataTable({
      columns: [
        { label: 'Site id', render: (o) => h('code', { class: 'mono cell-strong' }, o.site) },
        { label: 'What is left', render: (o) => h('span', { class: 'wrap-any' }, orphanText(o)) },
        {
          label: '',
          align: 'right',
          render: (o) => {
            const purge = button('Purge', {
              size: 'sm', kind: 'danger', iconName: 'trash', title: `Purge the data of ${o.site}`,
              onClick: async () => {
                const ok = await confirmDialog({
                  title: `Purge ${o.site}`,
                  message: `Delete ${orphanText(o)} for good. This cannot be undone.`,
                  confirmLabel: 'Purge', danger: true, requireText: o.site,
                });
                if (ok) await ctx.go(purge, `Purging ${o.site}`, () => ctx.n.del(`/data/orphans/${enc(o.site)}`));
              },
            });
            return purge;
          },
        },
      ],
      rows: list,
      empty: h('p', { class: 'muted' }, 'Nothing is left behind.'),
    }),
  });
}
