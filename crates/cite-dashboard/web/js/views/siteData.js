import { h } from '../dom.js';
import { api, nodeApi, isMock } from '../api.js';
import { state } from '../state.js';
import {
  button, card, confirmDialog, dataTable, emptyState, field, kvList, loadInto, openModal, pill, segmented, skeletonBlock, startNavigation,
  toast, withBusy, formatError, fmtBytes, fmtDate, fmtMs, relTime,
} from '../ui.js';
import { siteFeatures } from '../caplib.js';
import { deployWithToasts } from './deployFlow.js';
import {
  BUCKET_EXPLANATION, DEFAULT_MAJOR, EXTERNAL_BACKUP_NOTE, EXTERNAL_EGRESS_NOTE, KEY_BACKUP_NOTE, LEVELS, LINK_TARGETS,
  PG_MAJORS, PG_MODES, PRESETS, PRESET_DEFAULTS, ROTATE_TEXT, SECRET_ENCODINGS, SOURCE_KINDS, TRADEOFFS, WRITE_ONLY_CREDENTIALS,
  WRITE_ONLY_PASSWORDS, BACKUP_EVERY_HOURS, RETENTION_LIMITS,
  backupRows, canDownload, canOverride, canPush, canRestore, conflictLines, conflictSummary, conflictsFromError, dataFeatures,
  databaseKey, databaseName, deleteBackupBlock, deleteBackupText, deleteBlockedReason, externalUrlProblem, fieldsFor, healthKind, isExternalKey,
  jobStepText, labelBody, labelProblem, levelLabel, levelText, linkDraftProblem, linkLabel, linkRequest, linkRows, linkedByText,
  majorProblem, manualConflicts, modeLabel, pgNameProblem, pgResourceProblem, pollJob, policyFromForm, policyProblem, policyToForm,
  presetBody, presetOptionsProblem, presetPreview, prunePlanRows, pruneSummary, resourceNameProblem, restoreText, retentionText,
  rotateSecretText, s3Body, s3Problem, scheduleText, secretBytesProblem, secretCreateBody, sourceFromDraft, suggestedVar, userCreateBody,
  userFormProblem, userPatchBody, userState,
  CONVERT_NOTE, FREEZE_OPTIONS, LIVE_TRANSFER_NOTE, TRANSFER_SOURCE_NOTE,
  convertActions, convertKind, convertLabel, convertSettled, convertTarget, convertText, freezeText, mismatchRows, phaseKind, phaseLabel,
  pollUntil, transferActions, transferPercent, transferPlanBody, transferProblem, transferSettled, transferTitle, transfersOfSite, verifyText,
  OTHER_SESSIONS_NOTE, unmanagedSessions,
} from '../datalib.js';

const enc = encodeURIComponent;

// An earlier build kept the id of an open conversion in the browser. The node reports it now, so the old keys are dropped.
try {
  for (const key of Object.keys(localStorage)) if (key.startsWith('cite.convert.')) localStorage.removeItem(key);
} catch (ex) {
  // Storage is unavailable, so there is nothing to drop
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const noAutofill = {
  autocomplete: 'new-password', spellcheck: 'false', autocapitalize: 'off', 'data-lpignore': 'true', 'data-1p-ignore': 'true', 'data-bwignore': 'true', 'data-form-type': 'other',
};

// ---- small form pieces, shared with the Databases page ----

// A labelled text box; the label wraps the control, so it is its accessible name
export function textInput({ label, value = '', mono = false, placeholder = '', hint, type = 'text', secret = false, disabled = false }) {
  const input = h('input', {
    class: 'input' + (mono ? ' mono' : ''), type: secret ? 'password' : type, placeholder, value, disabled, spellcheck: 'false', autocomplete: 'off', ...(secret ? noAutofill : {}),
  });
  return { el: field(label, input, hint), input };
}

export function selectInput({ label, options, value, hint }) {
  const input = h('select', { class: 'select', value },
    options.map((o) => h('option', { value: o.value }, o.label)));
  return { el: field(label, input, hint), input };
}

export function checkRow(input, text) {
  return h('label', { class: 'check-row' }, input, h('span', {}, text));
}

export function note(text, kind = '') {
  return h('p', { class: 'notice data-notice' + (kind ? ' ' + kind : ''), role: 'note' }, text);
}

// A dialog with a body, an error line and Cancel/submit. onSubmit may return a function that runs after the dialog has closed,
// so a long job is followed from the page rather than from inside the dialog.
export function formDialog({
  title, body, submitLabel, kind = 'primary', validate, onSubmit, onError, wide = false,
}) {
  const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const show = (message) => {
    err.textContent = message;
    err.hidden = !message;
  };
  const submit = button(submitLabel, { kind });
  const cancel = button('Cancel', { onClick: () => modal.close() });
  const form = h('div', { class: 'form' }, body, err);
  form.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' || e.target.tagName !== 'INPUT' || ['checkbox', 'radio'].includes(e.target.type)) return;
    e.preventDefault();
    submit.click();
  });
  submit.addEventListener('click', async () => {
    show('');
    const problem = validate ? validate() : '';
    if (problem) {
      show(problem);
      return;
    }
    let after;
    try {
      after = await withBusy(submit, onSubmit);
    } catch (ex) {
      if (!(onError && onError(ex, show))) show(formatError(ex));
      return;
    }
    modal.close();
    if (typeof after === 'function') after();
  });
  const modal = openModal({
    title, wide, content: form, actions: [cancel, submit],
  });
  return modal;
}

// One progress line for every data job running from a page. Polls the node job until it ends, slowing down as it goes.
export function jobStrip(node) {
  const text = h('span', {});
  const el = h('div', { class: 'progress-box data-job', role: 'status', 'aria-live': 'polite', hidden: true },
    h('div', { class: 'progress' }, h('i', {})), text);
  let running = 0;
  const get = (id) => nodeApi(node).get(`/data/jobs/${enc(id)}`);
  async function track(jobId, label) {
    running += 1;
    el.hidden = false;
    text.textContent = `${label}...`;
    try {
      return await pollJob({
        jobId,
        get,
        sleep,
        alive: () => el.isConnected,
        hidden: () => document.hidden,
        onUpdate: (job) => { text.textContent = `${label}: ${jobStepText(job)}`; },
      });
    } finally {
      running -= 1;
      if (!running) el.hidden = true;
    }
  }
  return { el, track };
}

// Starts a request, follows the job it returns and reports the result. Returns null when the page was left while the job ran.
export function jobRunner({ strip, refresh, offerRedeploy }) {
  async function follow(accepted, label, { redeploy = false } = {}) {
    try {
      if (accepted && accepted.job_id) {
        const done = await strip.track(accepted.job_id, label);
        if (done === null) return null;
      }
      toast(`${label}: done`, 'success');
    } catch (ex) {
      toast(`${label}: ${formatError(ex)}`, 'error', 15000);
      refresh();
      return null;
    }
    refresh();
    if (accepted && accepted.redeploy_needed) {
      if (redeploy && offerRedeploy) offerRedeploy();
      else toast('Redeploy the site to apply this to the running containers.', 'info', 9000);
    }
    return accepted;
  }
  // For a button on the page: the button stays busy for the request and the whole job
  function go(btn, label, request, opts) {
    return withBusy(btn, async () => {
      let accepted;
      try {
        accepted = await request();
      } catch (ex) {
        toast(formatError(ex), 'error', 15000);
        return null;
      }
      return follow(accepted, label, opts);
    });
  }
  return { follow, go };
}

export function tradeoffTable(selected) {
  const pick = (mode) => (selected === mode ? 'data-pick' : '');
  return h('div', { class: 'table-wrap' }, h('table', { class: 't data-tradeoff' },
    h('caption', { class: 'sr-only' }, 'Dedicated compared with shared Postgres'),
    h('thead', {}, h('tr', {},
      h('th', { scope: 'col' }, 'Compared'),
      h('th', { scope: 'col', class: pick('dedicated') }, 'Dedicated'),
      h('th', { scope: 'col', class: pick('shared') }, 'Shared'))),
    h('tbody', {}, TRADEOFFS.map((r) => h('tr', {},
      h('th', { scope: 'row' }, r.aspect),
      h('td', { class: pick('dedicated') }, r.dedicated),
      h('td', { class: pick('shared') }, r.shared))))));
}

const numberBox = (label, value, hint) => textInput({ label, value: String(value), mono: true, type: 'number', hint });

// ---- loading ----

const names = (res) => (res && Array.isArray(res.names) ? res.names : []);

async function loadModel({ n, site, info, f, base }) {
  const nodeData = await n.get('/data').catch(() => null);
  if (nodeData && nodeData.enabled === false) return { disabled: true, nodeData };
  const caps = siteFeatures(info);
  const hasRuntime = caps.runtimeEnv;
  const hasBuild = caps.buildEnv;
  const envUrl = (which) => `/sites/${enc(site.id)}/${which}`;
  const [data, runtime, build, backups, targets, transfers] = await Promise.all([
    n.get(base),
    hasRuntime ? n.get(envUrl('runtime-env')).catch(() => null) : null,
    hasBuild ? n.get(envUrl('build-env')).catch(() => null) : null,
    f.backups ? n.get(`${base}/backups`).catch(() => []) : [],
    f.backups ? n.get('/data/targets').catch(() => []) : [],
    f.transfer ? api.get('/transfers').catch(() => []) : [],
  ]);
  return {
    disabled: false,
    nodeData,
    data: data || {},
    manual: { runtime: names(runtime), build: names(build) },
    backups: Array.isArray(backups) ? backups : [],
    targets: Array.isArray(targets) ? targets : [],
    transfers: Array.isArray(transfers) ? transfers : [],
  };
}

const picks = new Map();

// The Data tab of a site. Route shape #/sites/{node}/{site}/data
export function dataPanel({ node, site, info }) {
  const n = nodeApi(node);
  const f = dataFeatures(info);
  const base = `/sites/${enc(site.id)}/data`;
  const strip = jobStrip(node);
  const body = h('div', { class: 'stack' });
  const root = h('div', { class: 'stack' }, strip.el, body);

  loadInto(body, () => loadModel({ n, site, info, f, base }), (model, again) => {
    const offerRedeploy = async () => {
      const ok = await confirmDialog({
        title: `Redeploy ${site.name}`,
        message: 'The running containers keep the credentials they started with. Redeploying switches them to the new ones without downtime: the old login keeps working until the new version is serving.',
        confirmLabel: 'Redeploy now',
      });
      if (ok) await deployWithToasts({ node, siteId: site.id, info }, { onAfter: () => again() });
    };
    const runner = jobRunner({ strip, refresh: again, offerRedeploy });
    const ctx = {
      n, node, site, info, f, base, model, refresh: again, offerRedeploy, ...runner,
    };
    if (model.disabled) {
      return emptyState({
        iconName: 'layers', title: 'Data services are not enabled on this node', text: 'The node was started without the data services. Enable them in the node configuration, then reload.',
      });
    }
    const data = model.data;
    return [
      model.nodeData && model.nodeData.backup_volume_ok === false
        ? note('The backup volume is not mounted on this node, so backups cannot be written.', 'warn') : null,
      data.redeploy_needed ? redeployBanner(ctx) : null,
      f.postgres ? pgCard(ctx) : null,
      data.postgres ? databasesCard(ctx) : null,
      f.links ? linksCard(ctx) : null,
      f.links ? secretsCard(ctx) : null,
      f.external ? externalCard(ctx) : null,
      f.s3 ? s3Card(ctx) : null,
      f.backups && (data.postgres || (data.external || []).length) ? backupsCard(ctx) : null,
      f.transfer && data.postgres ? convertCard(ctx) : null,
      f.transfer && data.postgres ? transferCard(ctx) : null,
    ].filter(Boolean);
  }, { skeleton: () => skeletonBlock(180) });
  return root;
}

function redeployBanner(ctx) {
  const btn = button('Redeploy now', {
    kind: 'primary', iconName: 'rocket', title: `Redeploy ${ctx.site.name} on ${ctx.node}`, onClick: () => ctx.offerRedeploy(),
  });
  return h('div', { class: 'notice warn data-banner', role: 'status' },
    h('span', {}, 'A change here is not in the running containers yet. Redeploy to apply it.'), btn);
}

// ---- Postgres ----

function pgCard(ctx) {
  return ctx.model.data.postgres ? pgActiveCard(ctx) : pgOffCard(ctx);
}

function pgOffCard(ctx) {
  const { f, n, base, model } = ctx;
  const sharedInfo = model.nodeData && model.nodeData.shared;
  const sharedReady = Boolean(sharedInfo && sharedInfo.enabled);
  const options = PG_MODES.filter((m) => m.value === 'dedicated' || f.shared);
  let mode = 'dedicated';
  const summary = h('p', { class: 'muted' });
  const tableHost = h('div', {});
  const sharedNote = h('p', { class: 'notice warn data-notice', role: 'note', hidden: true },
    'The shared instance is not enabled on this node. Enable it on the ', h('a', { href: '#/databases' }, 'Databases page'), ' first.');
  const major = selectInput({
    label: 'Postgres major',
    options: PG_MAJORS.map((m) => ({ value: String(m), label: m === DEFAULT_MAJOR ? `PostgreSQL ${m} (default)` : `PostgreSQL ${m}` })),
    value: String(DEFAULT_MAJOR),
    hint: 'Fixed once created. A major upgrade means a dump and restore into a new database.',
  });
  const memory = numberBox('Memory limit (MiB)', 512, '256 to 65536. Shared by every database of this site.');
  const conns = numberBox('Max connections', 100, '10 to 1000.');
  const preset = h('input', { type: 'checkbox', checked: true });
  const dedicatedOnly = h('div', { class: 'two-col' }, major.el, h('div', { class: 'stack-sm' }, memory.el, conns.el));
  const enable = button('Turn on Postgres', { kind: 'primary', iconName: 'check' });
  const err = h('p', { class: 'form-error', role: 'alert', hidden: true });

  const sync = () => {
    const picked = PG_MODES.find((m) => m.value === mode);
    summary.textContent = picked.summary;
    tableHost.replaceChildren(tradeoffTable(mode));
    dedicatedOnly.hidden = mode !== 'dedicated';
    sharedNote.hidden = !(mode === 'shared' && !sharedReady);
    enable.disabled = mode === 'shared' && !sharedReady;
  };
  const seg = segmented({
    label: 'Where the database runs', options: options.map((m) => ({ value: m.value, label: m.label })), value: mode, onChange: (v) => { mode = v; sync(); },
  });

  enable.addEventListener('click', async () => {
    err.hidden = true;
    const problem = mode === 'dedicated'
      ? majorProblem(major.input.value) || pgResourceProblem(memory.input.value, conns.input.value)
      : '';
    if (problem) {
      err.textContent = problem;
      err.hidden = false;
      return;
    }
    const req = { mode };
    if (mode === 'dedicated') {
      req.major = Number(major.input.value);
      req.memory_mb = Number(memory.input.value);
      req.max_connections = Number(conns.input.value);
    }
    if (preset.checked) req.preset = 'generic';
    await ctx.go(enable, 'Turning on Postgres', () => n.put(`${base}/postgres`, req), { redeploy: false });
  });
  sync();
  return card({
    title: 'Postgres',
    subtitle: 'Not turned on for this site.',
    body: h('div', { class: 'stack' },
      field('Where it runs', seg, null, { group: true }), summary, sharedNote, tableHost, dedicatedOnly,
      checkRow(preset, 'Create a database called app with users app (read and write) and migrate (owner), and link DATABASE_URL and MIGRATION_DATABASE_URL'),
      err, h('div', { class: 'form-actions' }, enable)),
  });
}

function pgActiveCard(ctx) {
  const { site } = ctx;
  const pg = ctx.model.data.postgres;
  const size = (pg.databases || []).reduce((total, d) => total + (d.size_bytes || 0), 0);
  const dedicated = pg.mode === 'dedicated';
  const edit = button('Edit resources', { iconName: 'edit', size: 'sm', title: `Edit the resources of the Postgres of ${site.name}`, onClick: () => editResources(ctx, pg) });
  const off = button('Turn off', { iconName: 'trash', size: 'sm', kind: 'danger', title: `Turn off Postgres for ${site.name}`, onClick: () => turnOff(ctx) });
  const rows = [
    ['Where', h('span', { class: 'pill-row' }, pill(modeLabel(pg.mode), 'info'))],
    ['Postgres major', `PostgreSQL ${pg.major}`],
    ['Health', pg.health ? pill(pg.health, healthKind(pg.health)) : h('span', { class: 'muted' }, 'unknown')],
    ['Size', size ? fmtBytes(size) : h('span', { class: 'muted' }, 'not measured yet')],
    ['Memory', dedicated ? `${pg.memory_mb} MiB` : h('span', { class: 'muted' }, 'set by the shared instance')],
    ['Connections', dedicated ? `up to ${pg.max_connections}` : h('span', { class: 'muted' }, 'set by the shared instance')],
  ];
  const retired = pg.retired ? retiredNotice(ctx, pg.retired) : null;
  return card({
    title: 'Postgres',
    subtitle: dedicated ? 'A dedicated database for this site.' : 'A database on the shared instance of this node.',
    actions: h('div', { class: 'pill-row' }, dedicated ? edit : null, off),
    body: h('div', { class: 'stack' }, kvList(rows), retired),
  });
}

function retiredNotice(ctx, retired) {
  const del = button('Delete the old database', {
    size: 'sm', kind: 'danger', iconName: 'trash',
    onClick: async () => {
      const ok = await confirmDialog({
        title: 'Delete the old database',
        message: `Delete the frozen ${modeLabel(retired.mode).toLowerCase()} (PostgreSQL ${retired.major}) kept since ${fmtDate(retired.since)}. Its data is removed for good.`,
        confirmLabel: 'Delete', danger: true, requireText: ctx.site.id,
      });
      if (ok) await ctx.go(del, 'Deleting the old database', () => ctx.n.del(`${ctx.base}/postgres/retired`));
    },
  });
  return h('div', { class: 'notice warn data-notice', role: 'note' },
    h('span', {}, `The previous ${modeLabel(retired.mode).toLowerCase()} (PostgreSQL ${retired.major}) is kept frozen since ${fmtDate(retired.since)}. It stays until you delete it.`), del);
}

function editResources(ctx, pg) {
  const memory = numberBox('Memory limit (MiB)', pg.memory_mb, '256 to 65536.');
  const conns = numberBox('Max connections', pg.max_connections, '10 to 1000.');
  formDialog({
    title: 'Edit database resources',
    submitLabel: 'Save and restart',
    body: h('div', { class: 'stack-sm' },
      note('Applying new limits recreates the database container. The site loses its connections for a moment.'), memory.el, conns.el),
    validate: () => pgResourceProblem(memory.input.value, conns.input.value),
    onSubmit: async () => {
      const accepted = await ctx.n.put(`${ctx.base}/postgres`, {
        mode: pg.mode, memory_mb: Number(memory.input.value), max_connections: Number(conns.input.value),
      });
      return () => ctx.follow(accepted, 'Updating the database resources');
    },
  });
}

function turnOff(ctx) {
  const purge = h('input', { type: 'checkbox' });
  const typed = textInput({ label: `Type ${ctx.site.id} to delete the data`, mono: true });
  const typedBox = h('div', { hidden: true }, typed.el);
  purge.addEventListener('change', () => { typedBox.hidden = !purge.checked; });
  formDialog({
    title: 'Turn off Postgres',
    submitLabel: 'Turn off',
    kind: 'danger',
    body: h('div', { class: 'stack-sm' },
      h('p', { class: 'dialog-text' }, 'The site stops getting its database. Links to it are removed and the site needs a redeploy. The data stays on the node unless you delete it too, and can be found again under Orphans if the site is removed.'),
      checkRow(purge, 'Also delete the data and every user (cannot be undone)'), typedBox),
    validate: () => (purge.checked && typed.input.value !== ctx.site.id ? `Type ${ctx.site.id} to delete the data.` : ''),
    onSubmit: async () => {
      const accepted = await ctx.n.del(`${ctx.base}/postgres${purge.checked ? '?purge=true' : ''}`);
      return () => ctx.follow(accepted, 'Turning off Postgres', { redeploy: true });
    },
  });
}

// ---- Databases and users ----

function databasesCard(ctx) {
  const pg = ctx.model.data.postgres;
  const dbs = pg.databases || [];
  const add = button('Add database', { iconName: 'plus', size: 'sm', onClick: () => addDatabase(ctx) });
  return card({
    title: 'Databases and users',
    subtitle: 'Each database has its own users. Pick the lowest level that works for each one.',
    actions: add,
    body: h('div', { class: 'stack' },
      note(WRITE_ONLY_PASSWORDS),
      dbs.length ? dbs.map((db) => databaseSection(ctx, db, dbs.length)) : h('p', { class: 'muted' }, 'No databases yet.')),
  });
}

function addDatabase(ctx) {
  const name = textInput({ label: 'Database name', mono: true, placeholder: 'auth', hint: '1 to 16 lowercase letters and digits, starting with a letter.' });
  formDialog({
    title: 'Add a database',
    submitLabel: 'Add database',
    body: name.el,
    validate: () => pgNameProblem(name.input.value.trim(), 'database'),
    onSubmit: async () => {
      const accepted = await ctx.n.post(`${ctx.base}/postgres/databases`, { name: name.input.value.trim() });
      return () => ctx.follow(accepted, `Adding database ${name.input.value.trim()}`);
    },
  });
}

function databaseSection(ctx, db, total) {
  const users = db.users || [];
  const addUserBtn = button('Add user', { iconName: 'plus', size: 'sm', title: `Add a user to ${db.name}`, onClick: () => userDialog(ctx, db, null) });
  const delBtn = button('Delete database', {
    iconName: 'trash', size: 'sm', kind: 'danger', title: `Delete database ${db.name}`, onClick: () => deleteDatabase(ctx, db),
  });
  if (total === 1) {
    delBtn.disabled = true;
    delBtn.title = 'A site with Postgres needs at least one database. Turn Postgres off instead.';
  }
  const table = dataTable({
    columns: [
      { label: 'User', render: (u) => h('span', { class: 'mono cell-strong' }, u.name) },
      { label: 'Level', render: (u) => h('span', { title: levelText(u.level) }, pill(levelLabel(u.level), u.level === 'owner' ? 'warn' : 'muted')) },
      { label: 'Connections', align: 'right', render: (u) => String(u.connection_limit) },
      {
        label: 'Timeouts',
        render: (u) => h('span', { class: 'muted' }, `query ${u.statement_timeout_ms ? fmtMs(u.statement_timeout_ms) : 'none'}, idle ${fmtMs(u.idle_in_transaction_timeout_ms)}`),
      },
      {
        label: 'State',
        render: (u) => {
          const s = userState(u);
          return pill(s.text, s.kind);
        },
      },
      { label: 'Password rotated', render: (u) => (u.rotated_at ? h('span', { title: fmtDate(u.rotated_at) }, relTime(u.rotated_at)) : h('span', { class: 'muted' }, 'never')) },
      { label: 'Linked by', render: (u) => (u.linked_by && u.linked_by.length ? h('span', { class: 'mono wrap-any' }, linkedByText(u.linked_by)) : h('span', { class: 'muted' }, '-')) },
      { label: '', align: 'right', render: (u) => userActions(ctx, db, u) },
    ],
    rows: users,
    empty: h('p', { class: 'muted' }, 'No users yet. Add one to connect.'),
  });
  return h('section', { class: 'data-db', 'aria-label': `Database ${db.name}` },
    h('div', { class: 'section-row' },
      h('h4', { class: 'section-title mono' }, db.name, db.size_bytes ? h('span', { class: 'muted data-db-size' }, fmtBytes(db.size_bytes)) : null),
      h('div', { class: 'pill-row' }, addUserBtn, delBtn)),
    table);
}

function userActions(ctx, db, u) {
  const id = `${db.name}/${u.name}`;
  const path = `${ctx.base}/postgres/databases/${enc(db.name)}/users/${enc(u.name)}`;
  const rotate = button('Rotate password', {
    size: 'sm', iconName: 'refresh', title: `Rotate the password of ${id}`,
    onClick: async () => {
      const ok = await confirmDialog({ title: `Rotate password of ${id}`, message: ROTATE_TEXT, confirmLabel: 'Rotate' });
      if (ok) await ctx.go(rotate, `Rotating the password of ${id}`, () => ctx.n.post(`${path}/rotate`), { redeploy: true });
    },
  });
  const edit = button('Edit', { size: 'sm', iconName: 'edit', title: `Edit ${id}`, onClick: () => userDialog(ctx, db, u) });
  const toggle = button(u.disabled ? 'Enable' : 'Disable', {
    size: 'sm', title: `${u.disabled ? 'Enable' : 'Disable'} ${id}`,
    onClick: async () => {
      if (!u.disabled) {
        const ok = await confirmDialog({
          title: `Disable ${id}`,
          message: 'Open sessions of this user end now. Links keep rendering its credentials, so anything still using them gets authentication errors until you enable it again.',
          confirmLabel: 'Disable', danger: true,
        });
        if (!ok) return;
      }
      await ctx.go(toggle, `${u.disabled ? 'Enabling' : 'Disabling'} ${id}`, () => ctx.n.patch(path, { disabled: !u.disabled }));
    },
  });
  const del = button('Delete', {
    size: 'sm', kind: 'danger', iconName: 'trash', title: `Delete ${id}`,
    onClick: async () => {
      const ok = await confirmDialog({ title: `Delete ${id}`, message: 'The user and its logins are dropped. Objects it created are owned by the database owner role, so they stay.', confirmLabel: 'Delete user', danger: true });
      if (ok) await ctx.go(del, `Deleting ${id}`, () => ctx.n.del(path));
    },
  });
  const blocked = deleteBlockedReason(u);
  if (blocked) {
    del.disabled = true;
    del.title = blocked;
  }
  return h('div', { class: 'row-actions' }, rotate, edit, toggle, del);
}

function userDialog(ctx, db, existing) {
  const creating = !existing;
  const name = textInput({ label: 'User name', mono: true, placeholder: 'reporting', value: existing ? existing.name : '', disabled: !creating, hint: creating ? '1 to 16 lowercase letters and digits.' : '' });
  const level = selectInput({ label: 'Level', options: LEVELS.map((l) => ({ value: l.value, label: l.label })), value: existing ? existing.level : 'readwrite' });
  const levelHelp = h('p', { class: 'hint' });
  const syncLevel = () => { levelHelp.textContent = levelText(level.input.value); };
  level.input.addEventListener('change', syncLevel);
  syncLevel();
  const limit = textInput({ label: 'Connection limit', mono: true, type: 'number', value: existing ? String(existing.connection_limit) : '', placeholder: '20', hint: '1 to 500. Blank uses 20.' });
  const stmt = textInput({ label: 'Statement timeout (ms)', mono: true, type: 'number', value: existing ? String(existing.statement_timeout_ms) : '', placeholder: 'default', hint: '0 means none. Blank uses 30 s for read and write and read only, none for owner.' });
  const idle = textInput({ label: 'Idle in transaction timeout (ms)', mono: true, type: 'number', value: existing ? String(existing.idle_in_transaction_timeout_ms) : '', placeholder: '60000', hint: '1000 to 3600000.' });
  const siblings = (ctx.model.data.postgres.databases.find((d) => d.name === db.name) || { users: [] }).users.map((u) => u.name);
  const form = () => ({
    name: name.input.value, level: level.input.value, connectionLimit: limit.input.value, statementTimeoutMs: stmt.input.value, idleTimeoutMs: idle.input.value,
  });
  formDialog({
    title: creating ? `Add a user to ${db.name}` : `Edit ${db.name}/${existing.name}`,
    submitLabel: creating ? 'Add user' : 'Save',
    wide: true,
    body: h('div', { class: 'stack-sm' },
      creating ? note(WRITE_ONLY_PASSWORDS) : null,
      name.el, h('div', { class: 'stack-sm' }, level.el, levelHelp), h('div', { class: 'two-col' }, limit.el, stmt.el), idle.el),
    validate: () => userFormProblem(form(), { existing: siblings, creating })
      || (!creating && !Object.keys(userPatchBody(existing, form())).length ? 'Nothing changed.' : ''),
    onSubmit: async () => {
      const path = `${ctx.base}/postgres/databases/${enc(db.name)}/users`;
      const accepted = creating
        ? await ctx.n.post(path, userCreateBody(form()))
        : await ctx.n.patch(`${path}/${enc(existing.name)}`, userPatchBody(existing, form()));
      return () => ctx.follow(accepted, creating ? `Adding ${db.name}/${name.input.value.trim()}` : `Updating ${db.name}/${existing.name}`);
    },
  });
}

function deleteDatabase(ctx, db) {
  const purge = h('input', { type: 'checkbox' });
  const typed = textInput({ label: `Type ${db.name} to confirm`, mono: true });
  formDialog({
    title: `Delete database ${db.name}`,
    submitLabel: 'Delete database',
    kind: 'danger',
    body: h('div', { class: 'stack-sm' },
      h('p', { class: 'dialog-text' }, `The database ${db.name}, its data and its users are dropped for good. The node refuses while links or pinned backups use it.`),
      checkRow(purge, 'Delete it anyway: also remove the links that use it and its pinned backups'), typed.el),
    validate: () => (typed.input.value !== db.name ? `Type ${db.name} to confirm.` : ''),
    onSubmit: async () => {
      const accepted = await ctx.n.del(`${ctx.base}/postgres/databases/${enc(db.name)}${purge.checked ? '?purge=true' : ''}`);
      return () => ctx.follow(accepted, `Deleting database ${db.name}`, { redeploy: true });
    },
  });
}

// ---- Env links ----

function linksCard(ctx) {
  const { data } = ctx.model;
  const links = linkRows(data.links);
  const presets = button('Presets', { iconName: 'bolt', size: 'sm', title: 'Apply a preset for a framework', disabled: !data.postgres, onClick: () => presetDialog(ctx) });
  if (!data.postgres) presets.title = 'Presets need Postgres turned on';
  const add = button('Add link', { iconName: 'plus', size: 'sm', onClick: () => linkDialog(ctx, null) });
  const shadowed = data.shadowed || [];
  return card({
    title: 'Environment links',
    subtitle: 'Each variable is set from a resource when the site is built or started. Values are never shown.',
    actions: h('div', { class: 'pill-row' }, presets, add),
    body: h('div', { class: 'stack-sm' },
      dataTable({
        columns: [
          { label: 'Variable', render: (l) => h('code', { class: 'mono cell-strong' }, l.var) },
          { label: 'Target', render: (l) => pill(l.target === 'build' ? 'Build' : 'Runtime', l.target === 'build' ? 'info' : 'muted') },
          { label: 'Source', render: (l) => h('span', { class: 'wrap-any' }, `linked from ${linkLabel(l)}`) },
          { label: '', render: (l) => (l.shadows_doppler ? pill('shadows Doppler', 'warn') : null) },
          {
            label: '',
            align: 'right',
            render: (l) => {
              const rm = button('Remove', {
                size: 'sm', kind: 'danger', title: `Remove the link for ${l.var} (${l.target})`,
                onClick: async () => {
                  const ok = await confirmDialog({
                    title: `Remove ${l.var}`,
                    message: `${l.var} stops being set for ${l.target === 'build' ? 'builds' : 'the running site'} from the next ${l.target === 'build' ? 'build' : 'deploy'}.`,
                    confirmLabel: 'Remove link', danger: true,
                  });
                  if (!ok) return;
                  await withBusy(rm, async () => {
                    try {
                      await ctx.n.del(`${ctx.base}/links/${l.target}/${enc(l.var)}`);
                      toast(`Link ${l.var} removed`, 'success');
                      ctx.refresh();
                    } catch (ex) {
                      toast(formatError(ex), 'error', 15000);
                    }
                  });
                },
              });
              return rm;
            },
          },
        ],
        rows: links,
        empty: h('p', { class: 'muted' }, 'No links. Add one, or apply a preset.'),
      }),
      shadowed.length ? note(`Doppler variables shadowed by these links: ${shadowed.map((s) => `${s.var}${s.target ? ` (${s.target})` : ''}`).join(', ')}.`) : null),
  });
}

function sourceChoices(data) {
  const kinds = [];
  if (data.postgres) kinds.push('postgres');
  if ((data.external || []).length) kinds.push('external');
  if ((data.s3 || []).length) kinds.push('s3');
  if ((data.secrets || []).length) kinds.push('secret');
  kinds.push('site_url');
  return SOURCE_KINDS.filter((k) => kinds.includes(k.value));
}

function linkDialog(ctx, start) {
  const { data, manual } = ctx.model;
  const kinds = sourceChoices(data);
  const kind = selectInput({ label: 'Link what', options: kinds, value: start ? start.kind : kinds[0].value });
  const dbList = data.postgres ? data.postgres.databases || [] : [];
  const dbSel = selectInput({ label: 'Database', options: dbList.map((d) => ({ value: d.name, label: d.name })), value: dbList[0] ? dbList[0].name : '' });
  const userSel = selectInput({ label: 'User', options: [], value: '' });
  const nameSel = selectInput({ label: 'Resource', options: [], value: '' });
  const fieldSel = selectInput({ label: 'Field', options: [], value: '' });
  const varIn = textInput({ label: 'Variable name', mono: true, placeholder: 'DATABASE_URL', hint: 'Capital letters, digits and underscores.' });
  const target = selectInput({ label: 'Set it for', options: LINK_TARGETS, value: 'runtime' });
  const override = h('input', { type: 'checkbox' });
  const overrideRow = checkRow(override, '');
  const overrideText = overrideRow.querySelector('span');
  const status = h('p', { class: 'notice warn data-notice', role: 'status', 'aria-live': 'polite', hidden: true });
  let varTouched = Boolean(start && start.var);
  let serverConflicts = null;

  const fill = (select, items, keep) => {
    select.replaceChildren(...items.map((o) => h('option', { value: o.value }, o.label)));
    if (keep && items.some((o) => o.value === keep)) select.value = keep;
  };
  const draft = () => ({
    var: varIn.input.value, target: target.input.value, kind: kind.input.value, database: dbSel.input.value, user: userSel.input.value, name: nameSel.input.value, field: fieldSel.input.value,
  });
  const rebuild = () => {
    const k = kind.input.value;
    const isPg = k === 'postgres';
    dbSel.el.hidden = !isPg;
    userSel.el.hidden = !isPg;
    nameSel.el.hidden = isPg || k === 'site_url';
    fieldSel.el.hidden = k === 'secret' || k === 'site_url';
    if (isPg) {
      const db = (data.postgres.databases || []).find((d) => d.name === dbSel.input.value) || (data.postgres.databases || [])[0];
      fill(userSel.input, ((db && db.users) || []).map((u) => ({ value: u.name, label: `${u.name} (${levelLabel(u.level)})` })), userSel.input.value);
    } else if (k === 'external') {
      fill(nameSel.input, (data.external || []).map((e) => ({ value: e.name, label: e.name })), nameSel.input.value);
    } else if (k === 's3') {
      fill(nameSel.input, (data.s3 || []).map((s) => ({ value: s.name, label: s.name })), nameSel.input.value);
    } else if (k === 'secret') {
      fill(nameSel.input, (data.secrets || []).map((s) => ({ value: s.name, label: s.name })), nameSel.input.value);
      nameSel.el.hidden = false;
    }
    fill(fieldSel.input, fieldsFor(k).map((x) => ({ value: x, label: x })), fieldSel.input.value);
    if (k === 'site_url') nameSel.el.hidden = true;
    suggest();
    check();
  };
  const suggest = () => {
    if (varTouched) return;
    varIn.input.value = suggestedVar(sourceFromDraft(draft()));
  };
  // Live check: the node would refuse a clash with a manual variable unless the override is ticked
  const conflicts = () => {
    const d = draft();
    if (!d.var.trim()) return [];
    return serverConflicts || manualConflicts([{ var: d.var.trim(), target: d.target }], manual, data.links);
  };
  function check() {
    const d = draft();
    const found = conflicts();
    status.hidden = !found.length;
    overrideRow.hidden = !found.length || !canOverride(found);
    if (found.length) {
      status.textContent = `${conflictLines(found).join('; ')}. ${conflictSummary(found)}`;
      overrideText.textContent = `Replace the manual value${found.length === 1 ? '' : 's'} of ${found.map((c) => `${c.var} (${c.target})`).join(', ')}. It is deleted.`;
    } else {
      override.checked = false;
    }
    return linkDraftProblem(d, data) || '';
  }
  kind.input.addEventListener('change', () => { serverConflicts = null; rebuild(); });
  dbSel.input.addEventListener('change', () => { rebuild(); });
  for (const el of [userSel.input, nameSel.input, fieldSel.input]) el.addEventListener('change', () => { serverConflicts = null; suggest(); check(); });
  varIn.input.addEventListener('input', () => { varTouched = true; serverConflicts = null; check(); });
  target.input.addEventListener('change', () => { serverConflicts = null; check(); });

  rebuild();
  if (start && start.kind === 'secret') {
    nameSel.input.value = start.name;
    suggest();
    check();
  }

  formDialog({
    title: 'Add an environment link',
    submitLabel: 'Add link',
    wide: true,
    body: h('div', { class: 'stack-sm' },
      kind.el, h('div', { class: 'two-col' }, dbSel.el, userSel.el), h('div', { class: 'two-col' }, nameSel.el, fieldSel.el),
      h('div', { class: 'two-col' }, varIn.el, target.el), status, overrideRow),
    validate: () => {
      const problem = check();
      if (problem) return problem;
      const found = conflicts();
      if (found.length && !(canOverride(found) && override.checked)) {
        return canOverride(found) ? 'This name is already set by hand. Tick the box to replace it, or pick another name.' : 'This name is already linked. Remove that link first or pick another name.';
      }
      return '';
    },
    onSubmit: async () => {
      await ctx.n.post(`${ctx.base}/links`, { links: [linkRequest(draft())], override: override.checked });
      return () => {
        toast(`Link ${varIn.input.value.trim()} added. It applies on the next ${draft().target === 'runtime' ? 'deploy' : 'build'}.`, 'success');
        ctx.refresh();
      };
    },
    onError: (ex, show) => {
      const found = conflictsFromError(ex);
      if (!found) return false;
      serverConflicts = found;
      check();
      show('The node found a clash. Review it above.');
      return true;
    },
  });
}

function presetDialog(ctx) {
  const { data, manual } = ctx.model;
  const kind = selectInput({ label: 'Preset', options: PRESETS.map((p) => ({ value: p.id, label: p.label })), value: 'generic' });
  const summary = h('p', { class: 'muted' });
  const database = textInput({ label: 'Database', mono: true, value: PRESET_DEFAULTS.database });
  const runtimeUser = textInput({ label: 'Runtime user (read and write)', mono: true, value: PRESET_DEFAULTS.runtimeUser });
  const migrateUser = textInput({ label: 'Migrate user (owner)', mono: true, value: PRESET_DEFAULTS.migrateUser });
  const authDb = textInput({ label: 'Auth database', mono: true, value: PRESET_DEFAULTS.authDatabase });
  const nameBox = h('details', { class: 'filter-box' }, h('summary', {}, 'Names'),
    h('div', { class: 'stack-sm' }, h('div', { class: 'two-col' }, database.el, authDb.el), h('div', { class: 'two-col' }, runtimeUser.el, migrateUser.el)));
  const preview = h('div', { class: 'stack-sm', 'aria-live': 'polite' });
  const override = h('input', { type: 'checkbox' });
  const overrideRow = checkRow(override, '');
  let last = null;

  const opts = () => ({
    database: database.input.value.trim(), runtimeUser: runtimeUser.input.value.trim(), migrateUser: migrateUser.input.value.trim(), authDatabase: authDb.input.value.trim(),
  });
  const draw = () => {
    const id = kind.input.value;
    summary.textContent = PRESETS.find((p) => p.id === id).summary;
    authDb.el.hidden = id !== 'authjs';
    const bad = presetOptionsProblem(id, opts());
    if (bad) {
      last = null;
      preview.replaceChildren(h('p', { class: 'error-text', role: 'status' }, bad));
      return;
    }
    last = presetPreview(id, opts(), data, manual);
    const creates = [
      ...last.databases.map((d) => `database ${d}`),
      ...last.users.map((u) => `user ${u.database}/${u.user} (${levelLabel(u.level)})`),
      ...last.secrets.map((s) => `generated secret ${s}`),
    ];
    overrideRow.hidden = !last.needsOverride;
    overrideRow.querySelector('span').textContent = `Replace the manual value${last.conflicts.length === 1 ? '' : 's'} of ${last.conflicts.map((c) => `${c.var} (${c.target})`).join(', ')}. It is deleted.`;
    if (!last.needsOverride) override.checked = false;
    preview.replaceChildren(
      h('p', {}, creates.length ? `Will create: ${creates.join(', ')}.` : 'Nothing new to create: every user and secret exists.'),
      dataTable({
        columns: [
          { label: 'Variable', render: (l) => h('code', { class: 'mono' }, l.var) },
          { label: 'Target', render: (l) => (l.target === 'build' ? 'Build' : 'Runtime') },
          { label: 'Linked from', render: (l) => h('span', { class: 'wrap-any' }, linkLabel(l)) },
          {
            label: 'State',
            render: (l) => (l.state === 'exists' ? pill('Already linked', 'muted') : l.state === 'blocked' ? pill('Blocked', 'bad') : pill('New', 'info')),
          },
        ],
        rows: last.links,
      }),
      last.problem ? h('p', { class: 'error-text', role: 'status' }, last.problem) : null);
  };
  kind.input.addEventListener('change', draw);
  for (const t of [database, runtimeUser, migrateUser, authDb]) t.input.addEventListener('input', draw);
  draw();

  formDialog({
    title: 'Apply a preset',
    submitLabel: 'Apply preset',
    wide: true,
    body: h('div', { class: 'stack-sm' }, kind.el, summary, nameBox, preview, overrideRow),
    validate: () => {
      if (!last) return presetOptionsProblem(kind.input.value, opts());
      if (last.problem) return last.problem;
      if (last.needsOverride && !override.checked) return 'A variable is already set by hand. Tick the box to replace it.';
      return '';
    },
    onSubmit: async () => {
      const res = await ctx.n.post(`${ctx.base}/links/preset`, presetBody(kind.input.value, opts(), override.checked));
      return () => {
        if (res && res.job_id) ctx.follow({ job_id: res.job_id }, 'Applying the preset');
        else {
          toast('Preset applied', 'success');
          ctx.refresh();
        }
      };
    },
  });
}

// ---- Generated secrets ----

function secretsCard(ctx) {
  const secrets = ctx.model.data.secrets || [];
  const create = button('Create secret', { iconName: 'plus', size: 'sm', onClick: () => secretDialog(ctx) });
  return card({
    title: 'Generated secrets',
    subtitle: 'Random values the node keeps, such as AUTH_SECRET. The value is never shown.',
    actions: create,
    flush: secrets.length > 0,
    body: dataTable({
      columns: [
        { label: 'Name', render: (s) => h('code', { class: 'mono cell-strong' }, s.name) },
        { label: 'Size', align: 'right', render: (s) => `${s.bytes} bytes` },
        { label: 'Encoding', render: (s) => s.encoding },
        { label: 'Rotated', render: (s) => (s.rotated_at ? h('span', { title: fmtDate(s.rotated_at) }, relTime(s.rotated_at)) : h('span', { class: 'muted' }, 'never')) },
        { label: 'Linked by', render: (s) => (s.linked_by && s.linked_by.length ? h('span', { class: 'mono wrap-any' }, linkedByText(s.linked_by)) : h('span', { class: 'muted' }, '-')) },
        { label: '', align: 'right', render: (s) => secretActions(ctx, s) },
      ],
      rows: secrets,
      empty: h('p', { class: 'muted' }, 'No generated secrets.'),
    }),
  });
}

function secretActions(ctx, s) {
  const link = button('Link', {
    size: 'sm', iconName: 'key', title: `Link ${s.name} to an environment variable`, onClick: () => linkDialog(ctx, { kind: 'secret', name: s.name }),
  });
  const rotate = button('Rotate', {
    size: 'sm', iconName: 'refresh', title: `Rotate ${s.name}`,
    onClick: async () => {
      const ok = await confirmDialog({ title: `Rotate ${s.name}`, message: rotateSecretText(s), confirmLabel: 'Rotate', danger: /auth/i.test(s.name) });
      if (!ok) return;
      await withBusy(rotate, async () => {
        try {
          const res = await ctx.n.post(`${ctx.base}/secrets/${enc(s.name)}/rotate`);
          toast(`${s.name} rotated`, 'success');
          ctx.refresh();
          if (res && res.redeploy_needed) ctx.offerRedeploy();
        } catch (ex) {
          toast(formatError(ex), 'error', 15000);
        }
      });
    },
  });
  const del = button('Delete', {
    size: 'sm', kind: 'danger', iconName: 'trash', title: `Delete ${s.name}`,
    onClick: async () => {
      const ok = await confirmDialog({ title: `Delete ${s.name}`, message: 'The value is destroyed and cannot be recovered.', confirmLabel: 'Delete secret', danger: true });
      if (!ok) return;
      await withBusy(del, async () => {
        try {
          await ctx.n.del(`${ctx.base}/secrets/${enc(s.name)}`);
          toast(`${s.name} deleted`, 'success');
          ctx.refresh();
        } catch (ex) {
          toast(formatError(ex), 'error', 15000);
        }
      });
    },
  });
  const blocked = deleteBlockedReason(s);
  if (blocked) {
    del.disabled = true;
    del.title = blocked;
  }
  return h('div', { class: 'row-actions' }, link, rotate, del);
}

function secretDialog(ctx) {
  const name = textInput({ label: 'Name', mono: true, placeholder: 'auth-secret', hint: 'Lowercase letters, digits and dashes.' });
  const bytes = textInput({ label: 'Size in bytes', mono: true, type: 'number', value: '32', hint: '32 to 128.' });
  const encoding = selectInput({ label: 'Encoding', options: SECRET_ENCODINGS, value: 'base64url' });
  formDialog({
    title: 'Create a generated secret',
    submitLabel: 'Create secret',
    body: h('div', { class: 'stack-sm' }, name.el, h('div', { class: 'two-col' }, bytes.el, encoding.el),
      note('The node generates the value. Link it to a variable to use it; it is never shown.')),
    validate: () => resourceNameProblem(name.input.value.trim(), 'secret name') || secretBytesProblem(bytes.input.value),
    onSubmit: async () => {
      await ctx.n.post(`${ctx.base}/secrets`, secretCreateBody({ name: name.input.value, bytes: bytes.input.value, encoding: encoding.input.value }));
      return () => {
        toast(`Secret ${name.input.value.trim()} created`, 'success');
        ctx.refresh();
      };
    },
  });
}

// ---- External Postgres ----

function usedBy(data, kind, name) {
  return (data.links || []).filter((l) => l.source && l.source.kind === kind && l.source.name === name).map((l) => l.var);
}

function externalCard(ctx) {
  const list = ctx.model.data.external || [];
  const add = button('Attach a database', { iconName: 'plus', size: 'sm', onClick: () => externalDialog(ctx, null) });
  return card({
    title: 'External Postgres',
    subtitle: 'A database outside this node. The connection URL is write-only.',
    actions: add,
    body: h('div', { class: 'stack-sm' },
      list.length ? dataTable({
        columns: [
          { label: 'Name', render: (e) => h('code', { class: 'mono cell-strong' }, e.name) },
          { label: 'Host', render: (e) => h('span', { class: 'mono wrap-any' }, `${e.host}:${e.port}`) },
          { label: 'Database', render: (e) => h('span', { class: 'mono' }, e.database) },
          { label: 'SSL mode', render: (e) => e.sslmode || h('span', { class: 'muted' }, '-') },
          { label: 'Forward', render: (e) => (e.forward_port ? h('span', { class: 'mono' }, `port ${e.forward_port}`) : h('span', { class: 'muted' }, 'direct')) },
          { label: 'Notes', render: (e) => ((e.warnings || []).length ? h('span', { class: 'wrap-any' }, e.warnings.join(' ')) : h('span', { class: 'muted' }, '-')) },
          { label: '', align: 'right', render: (e) => externalActions(ctx, e) },
        ],
        rows: list,
      }) : h('p', { class: 'muted' }, 'No external databases attached.'),
      note(EXTERNAL_EGRESS_NOTE), note(EXTERNAL_BACKUP_NOTE)),
  });
}

function externalActions(ctx, e) {
  const replace = button('Replace URL', { size: 'sm', iconName: 'edit', title: `Replace the URL of ${e.name}`, onClick: () => externalDialog(ctx, e) });
  const del = button('Detach', {
    size: 'sm', kind: 'danger', iconName: 'trash', title: `Detach ${e.name}`,
    onClick: async () => {
      const ok = await confirmDialog({ title: `Detach ${e.name}`, message: 'The node forgets the URL. The external database itself is not touched.', confirmLabel: 'Detach', danger: true });
      if (!ok) return;
      await withBusy(del, async () => {
        try {
          await ctx.n.del(`${ctx.base}/external/${enc(e.name)}`);
          toast(`${e.name} detached`, 'success');
          ctx.refresh();
        } catch (ex) {
          toast(formatError(ex), 'error', 15000);
        }
      });
    },
  });
  const links = usedBy(ctx.model.data, 'external', e.name);
  if (links.length) {
    del.disabled = true;
    del.title = `Linked by ${links.join(', ')}. Remove those links first.`;
  }
  return h('div', { class: 'row-actions' }, replace, del);
}

function externalDialog(ctx, existing) {
  const name = textInput({ label: 'Name', mono: true, placeholder: 'billing', value: existing ? existing.name : '', disabled: Boolean(existing), hint: 'Lowercase letters, digits and dashes.' });
  const url = textInput({
    label: 'Connection URL', mono: true, secret: true, placeholder: 'postgres://user:password@host:5432/database', hint: WRITE_ONLY_CREDENTIALS,
  });
  formDialog({
    title: existing ? `Replace the URL of ${existing.name}` : 'Attach an external database',
    submitLabel: existing ? 'Replace URL' : 'Attach',
    wide: true,
    body: h('div', { class: 'stack-sm' }, name.el, url.el, note(EXTERNAL_EGRESS_NOTE)),
    validate: () => (existing ? '' : resourceNameProblem(name.input.value.trim(), 'name')) || externalUrlProblem(url.input.value),
    onSubmit: async () => {
      const res = await ctx.n.put(`${ctx.base}/external/${enc(existing ? existing.name : name.input.value.trim())}`, { url: url.input.value.trim() });
      url.input.value = '';
      return () => {
        const warnings = (res && res.warnings) || [];
        toast(warnings.length ? `Saved. ${warnings.join(' ')}` : 'External database saved', warnings.length ? 'info' : 'success', warnings.length ? 12000 : 4200);
        ctx.refresh();
      };
    },
  });
}

// ---- S3 attachments ----

function s3Card(ctx) {
  const list = ctx.model.data.s3 || [];
  const add = button('Attach a bucket', { iconName: 'plus', size: 'sm', onClick: () => s3Dialog(ctx, null) });
  return card({
    title: 'S3 storage',
    subtitle: 'An S3 compatible bucket for the site to use. The keys are write-only.',
    actions: add,
    flush: list.length > 0,
    body: list.length ? dataTable({
      columns: [
        { label: 'Name', render: (s) => h('code', { class: 'mono cell-strong' }, s.name) },
        { label: 'Endpoint', render: (s) => h('span', { class: 'mono wrap-any' }, s.endpoint) },
        { label: 'Bucket', render: (s) => h('span', { class: 'mono' }, s.bucket) },
        { label: 'Region', render: (s) => s.region },
        { label: 'Addressing', render: (s) => (s.path_style ? 'path style' : 'virtual host') },
        { label: 'Keys', render: (s) => (s.has_keys ? pill('stored', 'ok') : pill('missing', 'warn')) },
        { label: 'Linked by', render: (s) => (s.linked_by && s.linked_by.length ? h('span', { class: 'mono wrap-any' }, linkedByText(s.linked_by)) : h('span', { class: 'muted' }, '-')) },
        { label: '', align: 'right', render: (s) => s3Actions(ctx, s) },
      ],
      rows: list,
    }) : h('p', { class: 'muted' }, 'No buckets attached.'),
  });
}

function s3Actions(ctx, s) {
  const edit = button('Edit', { size: 'sm', iconName: 'edit', title: `Edit ${s.name}`, onClick: () => s3Dialog(ctx, s) });
  const del = button('Detach', {
    size: 'sm', kind: 'danger', iconName: 'trash', title: `Detach ${s.name}`,
    onClick: async () => {
      const ok = await confirmDialog({ title: `Detach ${s.name}`, message: 'The node forgets the keys. The bucket and its objects are not touched.', confirmLabel: 'Detach', danger: true });
      if (!ok) return;
      await withBusy(del, async () => {
        try {
          await ctx.n.del(`${ctx.base}/s3/${enc(s.name)}`);
          toast(`${s.name} detached`, 'success');
          ctx.refresh();
        } catch (ex) {
          toast(formatError(ex), 'error', 15000);
        }
      });
    },
  });
  const blocked = deleteBlockedReason(s);
  if (blocked) {
    del.disabled = true;
    del.title = blocked;
  }
  return h('div', { class: 'row-actions' }, edit, del);
}

function s3Dialog(ctx, existing) {
  const name = textInput({ label: 'Name', mono: true, placeholder: 'media', value: existing ? existing.name : '', disabled: Boolean(existing), hint: 'Lowercase letters, digits and dashes.' });
  const endpoint = textInput({ label: 'Endpoint', mono: true, placeholder: 'https://s3.eu-west-1.amazonaws.com', value: existing ? existing.endpoint : '' });
  const bucket = textInput({ label: 'Bucket', mono: true, value: existing ? existing.bucket : '' });
  const region = textInput({ label: 'Region', mono: true, placeholder: 'eu-west-1', value: existing ? existing.region : '' });
  const pathStyle = h('input', { type: 'checkbox', checked: existing ? existing.path_style : false });
  const keyId = textInput({ label: 'Access key id', mono: true, secret: true, hint: existing ? 'Leave both keys blank to keep the stored ones.' : WRITE_ONLY_CREDENTIALS });
  const secret = textInput({ label: 'Secret access key', mono: true, secret: true, hint: WRITE_ONLY_CREDENTIALS });
  const form = () => ({
    name: name.input.value.trim(), endpoint: endpoint.input.value, bucket: bucket.input.value, region: region.input.value, pathStyle: pathStyle.checked, accessKeyId: keyId.input.value, secretAccessKey: secret.input.value,
  });
  formDialog({
    title: existing ? `Edit ${existing.name}` : 'Attach an S3 bucket',
    submitLabel: existing ? 'Save' : 'Attach',
    wide: true,
    body: h('div', { class: 'stack-sm' }, name.el, endpoint.el, h('div', { class: 'two-col' }, bucket.el, region.el),
      checkRow(pathStyle, 'Path style addressing (MinIO and similar)'), h('div', { class: 'two-col' }, keyId.el, secret.el)),
    validate: () => s3Problem(form(), { hasKeys: Boolean(existing && existing.has_keys) }),
    onSubmit: async () => {
      await ctx.n.put(`${ctx.base}/s3/${enc(form().name)}`, s3Body(form()));
      keyId.input.value = '';
      secret.input.value = '';
      return () => {
        toast('S3 attachment saved', 'success');
        ctx.refresh();
      };
    },
  });
}

// ---- Backups ----

function backupsCard(ctx) {
  const { data, targets } = ctx.model;
  const pg = data.postgres;
  const keys = [
    ...((pg && pg.databases) || []).map((d) => databaseKey(d.name)),
    ...(data.external || []).map((e) => `ext:${e.name}`),
  ];
  const memoKey = `${ctx.node}/${ctx.site.id}`;
  let key = keys.includes(picks.get(memoKey)) ? picks.get(memoKey) : keys[0];
  const select = selectInput({
    label: 'Database', options: keys.map((k) => ({ value: k, label: isExternalKey(k) ? `${databaseName(k)} (external)` : databaseName(k) })), value: key,
  });
  const listHost = h('div', {});
  const external = () => isExternalKey(key) && !pg;
  const hasTarget = Boolean(pg && pg.backup && pg.backup.s3);

  const drawList = () => {
    const rows = backupRows(ctx.model.backups, key);
    listHost.replaceChildren(dataTable({
      columns: [
        { label: 'Version', render: (r) => h('span', { class: 'mono cell-strong' }, `v${r.version}`) },
        { label: 'Created', render: (r) => h('span', { title: fmtDate(r.createdAt) }, relTime(r.createdAt)) },
        { label: 'Trigger', render: (r) => r.triggerText },
        { label: 'Label', render: (r) => (r.label ? h('span', { class: 'wrap-any' }, r.label) : h('span', { class: 'muted' }, '-')) },
        { label: 'Pinned', render: (r) => (r.pinned ? pill('Pinned', 'warn') : h('span', { class: 'muted' }, '-')) },
        { label: 'Size', align: 'right', render: (r) => fmtBytes(r.size) },
        { label: 'SHA-256', render: (r) => h('span', { class: 'mono muted', title: r.raw.sha256 || '' }, r.sha) },
        { label: 'Status', render: (r) => h('span', { title: r.error }, pill(r.statusText, r.statusKind)) },
        { label: 'Held on', render: (r) => h('span', { class: 'pill-row' }, r.locations.map((l) => pill(l === 's3' ? 'S3' : 'Node', l === 's3' ? 'info' : 'muted'))) },
        { label: '', align: 'right', render: (r) => versionActions(ctx, r, { external: external(), hasTarget }) },
      ],
      rows,
      empty: emptyState({ iconName: 'file', title: 'No backups yet', text: 'Back up now to create version 1.' }),
    }));
  };
  select.input.addEventListener('change', () => {
    key = select.input.value;
    picks.set(memoKey, key);
    drawList();
  });
  const backUp = button('Back up now', { iconName: 'download', size: 'sm', kind: 'primary', onClick: () => backupDialog(ctx, () => key, hasTarget) });
  drawList();

  return card({
    title: 'Backups',
    subtitle: 'Numbered versions of each database, encrypted at rest.',
    actions: backUp,
    body: h('div', { class: 'stack' },
      keys.length ? select.el : null,
      listHost,
      note(KEY_BACKUP_NOTE),
      isExternalKey(key) || (data.external || []).length ? note(EXTERNAL_BACKUP_NOTE) : null,
      pg ? policyEditor(ctx, pg, targets) : null),
  });
}

function backupDialog(ctx, getKey, hasTarget) {
  const label = textInput({ label: 'Label (optional)', placeholder: 'before the schema change', hint: 'Up to 100 characters.' });
  const push = h('input', { type: 'checkbox' });
  const key = getKey();
  formDialog({
    title: `Back up ${databaseName(key)}`,
    submitLabel: 'Back up now',
    body: h('div', { class: 'stack-sm' }, label.el, hasTarget && !isExternalKey(key) ? checkRow(push, 'Also push a copy to the S3 target of the backup policy') : null),
    validate: () => labelProblem(label.input.value),
    onSubmit: async () => {
      const req = { database: key };
      if (label.input.value.trim()) req.label = label.input.value.trim();
      if (push.checked) req.push_s3 = true;
      const accepted = await ctx.n.post(`${ctx.base}/backups`, req);
      return () => ctx.follow(accepted, `Backing up ${databaseName(key)}`);
    },
  });
}

function versionActions(ctx, r, { external, hasTarget }) {
  const path = `${ctx.base}/backups/${enc(r.id)}`;
  const name = `version ${r.version}`;
  const download = button('Download', {
    size: 'sm', iconName: 'download', title: `Download ${name}`,
    onClick: async () => {
      if (isMock) {
        toast('Downloads need a real node', 'info');
        return;
      }
      startNavigation(`/api/v1/nodes/${enc(ctx.node)}/sites/${enc(ctx.site.id)}/data/backups/${enc(r.id)}/download`);
      toast(`Download of ${name} started`, 'info');
    },
  });
  download.disabled = !canDownload(r);
  const restore = button('Restore', { size: 'sm', iconName: 'refresh', title: `Restore ${name}`, onClick: () => restoreDialog(ctx, r) });
  restore.disabled = !canRestore(r, { external });
  if (restore.disabled) restore.title = r.status !== 'ok' ? 'Only a complete version can be restored.' : 'Restore needs a managed database to restore into.';
  const pin = button(r.pinned ? 'Unpin' : 'Pin', {
    size: 'sm', title: `${r.pinned ? 'Unpin' : 'Pin'} ${name}`,
    onClick: () => withBusy(pin, async () => {
      try {
        await ctx.n.patch(path, { pinned: !r.pinned });
        ctx.refresh();
      } catch (ex) {
        toast(formatError(ex), 'error', 15000);
      }
    }),
  });
  const labelBtn = button('Label', { size: 'sm', iconName: 'edit', title: `Label ${name}`, onClick: () => labelDialog(ctx, r) });
  const push = button('Push to S3', {
    size: 'sm', title: `Push ${name} to S3`,
    onClick: async () => { await ctx.go(push, `Pushing ${name} to S3`, () => ctx.n.post(`${path}/push`, {})); },
  });
  const pushOk = canPush(r, { hasTarget });
  push.hidden = !pushOk;
  const del = button('Delete', { size: 'sm', kind: 'danger', iconName: 'trash', title: `Delete ${name}`, onClick: () => deleteVersionDialog(ctx, r) });
  const blocked = deleteBackupBlock(r);
  if (blocked) {
    del.disabled = true;
    del.title = blocked;
  }
  return h('div', { class: 'row-actions data-wrap' }, download, restore, push, pin, labelBtn, del);
}

function labelDialog(ctx, r) {
  const label = textInput({ label: 'Label', value: r.label, placeholder: 'none', hint: 'Up to 100 characters. Blank clears it.' });
  formDialog({
    title: `Label version ${r.version}`,
    submitLabel: 'Save label',
    body: label.el,
    validate: () => labelProblem(label.input.value),
    onSubmit: async () => {
      await ctx.n.patch(`${ctx.base}/backups/${enc(r.id)}`, labelBody(label.input.value));
      return () => ctx.refresh();
    },
  });
}

function restoreDialog(ctx, r) {
  const typed = textInput({ label: `Type ${ctx.site.id} to confirm`, mono: true });
  const managed = (ctx.model.data.postgres && ctx.model.data.postgres.databases) || [];
  const target = selectInput({ label: 'Restore into', options: managed.map((d) => ({ value: d.name, label: d.name })), value: managed[0] ? managed[0].name : '' });
  const crossRestore = isExternalKey(r.database);
  formDialog({
    title: `Restore version ${r.version}`,
    submitLabel: 'Restore',
    kind: 'danger',
    wide: true,
    body: h('div', { class: 'stack-sm' },
      h('p', { class: 'dialog-text' }, restoreText(r, ctx.site.name)),
      crossRestore ? target.el : null,
      typed.el),
    validate: () => (typed.input.value !== ctx.site.id ? `Type ${ctx.site.id} to confirm.` : ''),
    onSubmit: async () => {
      const req = { confirm: ctx.site.id };
      if (crossRestore) req.database = databaseKey(target.input.value);
      const res = await ctx.n.post(`${ctx.base}/backups/${enc(r.id)}/restore`, req);
      return () => {
        toast('A backup of the current data is being taken first, as a Before restore version.', 'info', 9000);
        ctx.follow(res, `Restoring version ${r.version}`);
      };
    },
  });
}

function deleteVersionDialog(ctx, r) {
  const where = selectInput({
    label: 'Delete from',
    options: [
      ...(r.locations.length > 1 ? [{ value: 'all', label: 'The node and S3' }] : []),
      ...(r.locations.includes('node') ? [{ value: 'local', label: 'The node only' }] : []),
      ...(r.locations.includes('s3') ? [{ value: 's3', label: 'S3 only' }] : []),
    ],
    value: r.locations.length > 1 ? 'all' : (r.locations[0] === 's3' ? 's3' : 'local'),
  });
  formDialog({
    title: `Delete version ${r.version}`,
    submitLabel: 'Delete',
    kind: 'danger',
    body: h('div', { class: 'stack-sm' }, h('p', { class: 'dialog-text' }, deleteBackupText(r)), r.locations.length ? where.el : null),
    onSubmit: async () => {
      await ctx.n.del(`${ctx.base}/backups/${enc(r.id)}?from=${enc(where.input.value)}`);
      return () => {
        toast(`Version ${r.version} deleted`, 'success');
        ctx.refresh();
      };
    },
  });
}

// ---- Retention policy ----

function retentionFields(part, onChange) {
  const boxes = {};
  const grid = h('div', { class: 'four-col data-retention' });
  const summary = h('p', { class: 'muted' });
  for (const [key, lim] of Object.entries(RETENTION_LIMITS)) {
    const box = textInput({ label: lim.label, mono: true, type: 'number', value: part[key], hint: `${lim.min} to ${lim.max}` });
    box.input.addEventListener('input', () => {
      part[key] = box.input.value;
      paint();
      onChange();
    });
    boxes[key] = box;
    grid.append(box.el);
  }
  function paint() {
    const numbers = Object.fromEntries(Object.entries(part).map(([k, v]) => [k, Number(v)]));
    summary.textContent = Object.values(part).some((v) => !/^\d+$/.test(String(v))) ? 'Enter whole numbers.' : retentionText(numbers);
  }
  paint();
  return h('div', { class: 'stack-sm' }, grid, summary);
}

function policyEditor(ctx, pg, targets) {
  const form = policyToForm(pg.backup);
  const status = h('p', { class: 'hint', role: 'status' });
  const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const previewHost = h('div', { class: 'stack-sm', 'aria-live': 'polite' });
  const dirty = () => { status.textContent = 'Unsaved changes. The prune preview uses the saved policy.'; };

  const sched = h('input', { type: 'checkbox', checked: form.scheduled });
  const every = selectInput({ label: 'Every', options: BACKUP_EVERY_HOURS.map((v) => ({ value: String(v), label: v === 1 ? 'hour' : `${v} hours` })), value: form.everyHours });
  const minute = textInput({ label: 'At minute', mono: true, type: 'number', value: form.minute, hint: '0 to 59, UTC.' });
  const schedText = h('p', { class: 'muted' });
  const paintSched = () => {
    every.el.hidden = !form.scheduled;
    minute.el.hidden = !form.scheduled;
    schedText.textContent = form.scheduled ? scheduleText({ every_hours: Number(form.everyHours), minute: Number(form.minute) }) : 'No scheduled backups. Back up by hand.';
  };
  sched.addEventListener('change', () => { form.scheduled = sched.checked; paintSched(); dirty(); });
  every.input.addEventListener('change', () => { form.everyHours = every.input.value; paintSched(); dirty(); });
  minute.input.addEventListener('input', () => { form.minute = minute.input.value; paintSched(); dirty(); });
  paintSched();

  const s3On = h('input', { type: 'checkbox', checked: form.s3On });
  const target = selectInput({
    label: 'S3 target', options: [{ value: '', label: targets.length ? 'Pick a target' : 'No targets yet' }, ...targets.map((t) => ({ value: t.id, label: `${t.name} (${t.bucket})` }))], value: form.s3Target,
  });
  const s3Box = h('div', { class: 'stack-sm' }, target.el, retentionFields(form.s3, dirty));
  const paintS3 = () => { s3Box.hidden = !form.s3On; };
  s3On.addEventListener('change', () => { form.s3On = s3On.checked; paintS3(); dirty(); });
  target.input.addEventListener('change', () => { form.s3Target = target.input.value; dirty(); });
  paintS3();

  const save = button('Save policy', { kind: 'primary', iconName: 'check' });
  const preview = button('Preview prune', { iconName: 'search' });
  const prune = button('Prune now', { kind: 'danger', iconName: 'trash' });

  save.addEventListener('click', async () => {
    err.hidden = true;
    const problem = policyProblem(form);
    if (problem) {
      err.textContent = problem;
      err.hidden = false;
      return;
    }
    try {
      await withBusy(save, () => ctx.n.put(`${ctx.base}/postgres/policy`, policyFromForm(form)));
      toast('Backup policy saved', 'success');
      ctx.refresh();
    } catch (ex) {
      err.textContent = formatError(ex);
      err.hidden = false;
    }
  });

  preview.addEventListener('click', async () => {
    err.hidden = true;
    try {
      const plans = await withBusy(preview, () => ctx.n.get(`${ctx.base}/prune-preview`));
      drawPreview(previewHost, Array.isArray(plans) ? plans : [], ctx.model.backups);
    } catch (ex) {
      err.textContent = formatError(ex);
      err.hidden = false;
    }
  });

  prune.addEventListener('click', async () => {
    const ok = await confirmDialog({
      title: 'Prune backups now',
      message: 'Deletes every version the saved policy no longer keeps, on the node and in S3. Pinned versions and the newest complete version stay. Use Preview prune first to see the list.',
      confirmLabel: 'Prune', danger: true,
    });
    if (!ok) return;
    try {
      const res = await withBusy(prune, () => ctx.n.post(`${ctx.base}/prune`, {}));
      toast(`Pruned ${res && res.deleted ? res.deleted : 0} ${res && res.deleted === 1 ? 'copy' : 'copies'}`, 'success');
      ctx.refresh();
    } catch (ex) {
      err.textContent = formatError(ex);
      err.hidden = false;
    }
  });

  return h('details', { class: 'filter-box data-policy', open: false },
    h('summary', {}, 'Backup policy and retention'),
    h('div', { class: 'stack' },
      h('div', { class: 'stack-sm' }, h('h4', { class: 'section-title' }, 'Schedule'), checkRow(sched, 'Back up on a schedule'), h('div', { class: 'two-col' }, every.el, minute.el), schedText),
      h('div', { class: 'stack-sm' }, h('h4', { class: 'section-title' }, 'Copies on the node'), retentionFields(form.local, dirty)),
      h('div', { class: 'stack-sm' }, h('h4', { class: 'section-title' }, 'Copies in S3'), checkRow(s3On, 'Also keep copies in S3'), s3Box),
      note(BUCKET_EXPLANATION),
      err, status, h('div', { class: 'form-actions' }, prune, preview, save), previewHost));
}

function drawPreview(host, plans, records) {
  host.replaceChildren(h('p', { class: 'cell-strong' }, pruneSummary(plans)));
  for (const plan of plans) {
    for (const tier of ['local', 's3']) {
      const rows = prunePlanRows(plan, tier, records);
      if (!rows.keep.length && !rows.delete.length) continue;
      host.append(h('div', { class: 'stack-sm' },
        h('h4', { class: 'section-title' }, `${databaseName(plan.database)}: ${tier === 's3' ? 'S3 copies' : 'node copies'}`),
        dataTable({
          columns: [
            { label: 'Version', render: (x) => h('span', { class: 'mono' }, x.name) },
            { label: 'Result', render: (x) => (x.reason ? pill('Keep', 'ok') : pill('Delete', 'bad')) },
            { label: 'Reason', render: (x) => x.reason || h('span', { class: 'muted' }, 'no rule keeps it') },
          ],
          rows: [...rows.keep, ...rows.delete.map((d) => ({ ...d, reason: '' }))],
        })));
    }
  }
}

// ---- Move a database to another node ----

export function progressBar(percent, label) {
  return h('div', {
    class: 'data-bar', role: 'progressbar', 'aria-label': label, 'aria-valuemin': '0', 'aria-valuemax': '100', 'aria-valuenow': String(percent),
  }, h('i', { style: { width: `${percent}%` } }));
}

// One transfer: phase, bytes, verification and the buttons that apply. It polls the dashboard server while the transfer runs
// and starts polling again after an action that restarts it.
function transferBlock(initial) {
  const el = h('section', { class: 'data-db data-transfer' });
  let view = initial;
  let polling = false;

  const act = (btn, verb) => withBusy(btn, async () => {
    try {
      view = await api.post(`/transfers/${enc(view.id)}/${verb}`);
      draw();
      watch();
    } catch (ex) {
      toast(formatError(ex), 'error', 15000);
    }
  });

  function draw() {
    const can = transferActions(view);
    const total = Number(view.bytes_total) || 0;
    const percent = transferPercent(view);
    const rows = mismatchRows(view);
    const cancel = button('Cancel', { size: 'sm', title: 'Stop at the next step. It can be resumed or rolled back.', onClick: (e) => act(e.currentTarget, 'cancel') });
    const resume = button('Resume', { size: 'sm', iconName: 'play', title: 'Continue from what the nodes report', onClick: (e) => act(e.currentTarget, 'resume') });
    const cutover = button('Cut over', {
      size: 'sm', kind: 'primary', iconName: 'check', title: 'Finish the transfer',
      onClick: async (e) => {
        const btn = e.currentTarget;
        const ok = await confirmDialog({
          title: 'Cut over',
          message: `Finish moving ${transferTitle(view)}. The target takes over the database and its links. ${TRANSFER_SOURCE_NOTE}`,
          confirmLabel: 'Cut over',
        });
        if (ok) await act(btn, 'cutover');
      },
    });
    const rollback = button('Roll back', {
      size: 'sm', kind: 'danger', iconName: 'refresh', title: 'Abandon the transfer',
      onClick: async (e) => {
        const btn = e.currentTarget;
        const ok = await confirmDialog({
          title: 'Roll back the transfer',
          message: 'The copy on the target is abandoned and the source is unfrozen. Nothing is deleted from the source.',
          confirmLabel: 'Roll back', danger: true,
        });
        if (ok) await act(btn, 'rollback');
      },
    });
    el.setAttribute('aria-label', transferTitle(view));
    el.replaceChildren(
      h('div', { class: 'section-row' },
        h('h4', { class: 'section-title' }, transferTitle(view)),
        h('span', { class: 'pill-row' }, pill(phaseLabel(view.phase), phaseKind(view.phase)), view.running ? pill('running', 'info') : null)),
      total || view.running ? progressBar(percent, 'Copy progress') : null,
      total ? h('p', { class: 'muted', role: 'status', 'aria-live': 'polite' }, `${fmtBytes(view.bytes_done)} of ${fmtBytes(total)} (${percent}%)`) : null,
      h('p', { class: 'hint' }, `While it is frozen: ${freezeText(view.plan.freeze)}`),
      view.error ? h('p', { class: 'error-text', role: 'alert' }, view.error) : null,
      verifyText(view) ? h('p', { class: view.counts_match ? 'cell-strong' : 'error-text', role: 'status' }, verifyText(view)) : null,
      rows.length ? dataTable({
        columns: [
          { label: 'Table', render: (r) => h('span', { class: 'mono' }, r.table) },
          { label: 'Rows on the source', align: 'right', render: (r) => r.source },
          { label: 'Rows on the target', align: 'right', render: (r) => r.target },
        ],
        rows,
      }) : null,
      h('div', { class: 'form-actions' },
        can.cancel ? cancel : null, can.resume ? resume : null, can.rollback ? rollback : null, can.cutover ? cutover : null));
  }

  async function watch() {
    if (polling || transferSettled(view)) return;
    polling = true;
    try {
      await pollUntil({
        get: () => api.get(`/transfers/${enc(view.id)}`),
        finished: transferSettled,
        sleep,
        alive: () => el.isConnected,
        hidden: () => document.hidden,
        onUpdate: (next) => { view = next; draw(); },
      });
    } catch (ex) {
      toast(`Transfer: ${formatError(ex)}`, 'error', 15000);
    } finally {
      polling = false;
    }
  }

  draw();
  // The block is attached by the caller first; polling stops by itself once it is detached
  setTimeout(watch, 0);
  return el;
}

function transferCard(ctx) {
  const pg = ctx.model.data.postgres;
  const peers = state.nodes.filter((x) => x.name !== ctx.node && x.online);
  const target = selectInput({
    label: 'Move to node', options: peers.map((p) => ({ value: p.name, label: p.name })), value: peers[0] ? peers[0].name : '',
    hint: peers.length ? 'The target node needs the data services enabled.' : 'No other node is online.',
  });
  const dbs = (pg.databases || []).map((d) => ({ value: d.name, label: d.name }));
  const db = selectInput({ label: 'Database', options: dbs, value: dbs[0] ? dbs[0].value : '' });
  const freeze = selectInput({ label: 'During the final copy', options: FREEZE_OPTIONS.map((o) => ({ value: o.value, label: o.label })), value: 'maintenance' });
  const freezeHelp = h('p', { class: 'hint', role: 'status', 'aria-live': 'polite' });
  const syncFreeze = () => { freezeHelp.textContent = freezeText(freeze.input.value); };
  freeze.input.addEventListener('change', syncFreeze);
  syncFreeze();
  const replace = h('input', { type: 'checkbox' });
  const override = h('input', { type: 'checkbox' });
  const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const start = button('Start the move', { kind: 'primary', iconName: 'rocket' });
  const list = h('div', { class: 'stack' });
  const mine = transfersOfSite(ctx.model.transfers, ctx.site.id, ctx.node);
  for (const t of mine) list.append(transferBlock(t));
  // Sessions open on this node that no dashboard transfer owns, such as one started from the desktop app
  const others = unmanagedSessions(ctx.model.data.transfers, ctx.model.transfers);
  const othersBox = others.length ? h('div', { class: 'stack-sm' },
    note(OTHER_SESSIONS_NOTE),
    dataTable({
      columns: [
        { label: 'Session', render: (s) => h('span', { class: 'mono' }, s.id) },
        { label: 'Kind', render: (s) => s.kind },
        { label: 'Database', render: (s) => h('span', { class: 'mono' }, s.database) },
        { label: 'State', render: (s) => pill(s.state, 'info') },
        { label: 'Updated', render: (s) => h('span', { title: fmtDate(s.updatedAt) }, relTime(s.updatedAt)) },
      ],
      rows: others,
    })) : null;

  start.addEventListener('click', async () => {
    err.hidden = true;
    const form = {
      source: ctx.node, target: target.input.value, site: ctx.site.id, database: db.input.value, freeze: freeze.input.value, replace: replace.checked, overrideManual: override.checked,
    };
    const problem = transferProblem(form);
    if (problem) {
      err.textContent = problem;
      err.hidden = false;
      return;
    }
    try {
      const view = await withBusy(start, () => api.post('/transfers', transferPlanBody(form)));
      list.prepend(transferBlock(view));
      toast('Transfer started', 'success');
    } catch (ex) {
      err.textContent = formatError(ex);
      err.hidden = false;
    }
  });

  return card({
    title: 'Move database to another node',
    subtitle: 'Copies a database to a node of this console, checks every table, then lets you cut over.',
    body: h('div', { class: 'stack' },
      h('div', { class: 'two-col' }, target.el, db.el),
      h('div', { class: 'stack-sm' }, freeze.el, freezeHelp),
      checkRow(replace, 'Replace a database of the same name on the target (a backup of it is taken first)'),
      checkRow(override, 'Replace manual variables of the same name on the target when the links are created'),
      note(TRANSFER_SOURCE_NOTE), note(LIVE_TRANSFER_NOTE),
      err, h('div', { class: 'form-actions' }, start), list, othersBox),
  });
}

// ---- Convert between dedicated and shared ----

// The node reports the open conversion in the site data, so nothing is remembered in the browser. The block follows it from there.
function convertBlock(ctx, initial) {
  const el = h('section', { class: 'data-db data-transfer', 'aria-label': 'Conversion status' });
  const path = `${ctx.base}/postgres/convert/${enc(initial.id)}`;
  let session = initial;
  let polling = false;

  const apply = (next) => {
    session = next;
    draw();
    // The page shows the new mode and the retired database only after it is loaded again
    if (next.state === 'done' || next.state === 'rolled_back') ctx.refresh();
  };
  const act = (btn, verb) => withBusy(btn, async () => {
    try {
      apply(await ctx.n.post(`${path}/${verb}`));
      watch();
    } catch (ex) {
      toast(formatError(ex), 'error', 15000);
    }
  });

  function draw() {
    const can = convertActions(session);
    const cutover = button('Cut over', {
      size: 'sm', kind: 'primary', iconName: 'check', title: 'Switch the site to the new database',
      onClick: async (e) => {
        const btn = e.currentTarget;
        const ok = await confirmDialog({
          title: 'Cut over',
          message: 'The site switches to the new database. The old one stays, frozen, as the retired database until you delete it. The site needs a redeploy afterwards.',
          confirmLabel: 'Cut over',
        });
        if (ok) await act(btn, 'cutover');
      },
    });
    const abort = button('Abort', {
      size: 'sm', kind: 'danger', title: 'Abandon the conversion',
      onClick: async (e) => {
        const btn = e.currentTarget;
        const ok = await confirmDialog({ title: 'Abort the conversion', message: 'The copy is abandoned and the site is unfrozen. The current database is untouched.', confirmLabel: 'Abort', danger: true });
        if (ok) await act(btn, 'abort');
      },
    });
    el.replaceChildren(
      h('div', { class: 'section-row' },
        h('h4', { class: 'section-title' }, `Converting to ${convertTarget(ctx.model.data.postgres) === 'shared' ? 'a shared' : 'a dedicated'} database`),
        pill(convertLabel(session.state), convertKind(session.state))),
      session.error ? h('p', { class: 'error-text', role: 'alert' }, session.error) : null,
      h('div', { class: 'form-actions' }, can.abort ? abort : null, can.cutover ? cutover : null));
  }

  async function watch() {
    if (polling || convertSettled(session)) return;
    polling = true;
    try {
      await pollUntil({
        get: () => ctx.n.get(path),
        finished: convertSettled,
        sleep,
        alive: () => el.isConnected,
        hidden: () => document.hidden,
        onUpdate: apply,
      });
    } catch (ex) {
      if (ex && ex.status === 404) ctx.refresh();
      else toast(`Conversion: ${formatError(ex)}`, 'error', 15000);
    } finally {
      polling = false;
    }
  }

  draw();
  setTimeout(watch, 0);
  return el;
}

function convertCard(ctx) {
  const pg = ctx.model.data.postgres;
  const to = convertTarget(pg);
  const sharedInfo = ctx.model.nodeData && ctx.model.nodeData.shared;
  const blocked = to === 'shared' && !(sharedInfo && sharedInfo.enabled);
  const host = h('div', { class: 'stack' });
  const freeze = selectInput({ label: 'During the final copy', options: FREEZE_OPTIONS.map((o) => ({ value: o.value, label: o.label })), value: 'maintenance' });
  const freezeHelp = h('p', { class: 'hint', role: 'status', 'aria-live': 'polite' });
  const syncFreeze = () => { freezeHelp.textContent = freezeText(freeze.input.value); };
  freeze.input.addEventListener('change', syncFreeze);
  syncFreeze();
  const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const start = button(to === 'shared' ? 'Convert to a shared database' : 'Convert to a dedicated database', { kind: 'primary', iconName: 'swap' });
  start.disabled = blocked;
  start.addEventListener('click', async () => {
    err.hidden = true;
    try {
      await withBusy(start, () => ctx.n.post(`${ctx.base}/postgres/convert`, { to, freeze: freeze.input.value }));
      toast('Conversion started', 'success');
      ctx.refresh();
    } catch (ex) {
      err.textContent = formatError(ex);
      err.hidden = false;
    }
  });
  const form = h('div', { class: 'stack' },
    h('p', { class: 'muted' }, convertText(to)),
    blocked ? h('p', { class: 'notice warn data-notice', role: 'note' }, 'The shared instance is not enabled on this node. Enable it on the ', h('a', { href: '#/databases' }, 'Databases page'), ' first.') : null,
    h('div', { class: 'stack-sm' }, freeze.el, freezeHelp), err, h('div', { class: 'form-actions' }, start));
  const open = ctx.model.data.conversion;
  host.append(open ? convertBlock(ctx, open) : form);
  return card({
    title: 'Convert between dedicated and shared',
    subtitle: `This site uses a ${pg.mode} database on ${ctx.node}.`,
    body: h('div', { class: 'stack' }, host, note(CONVERT_NOTE)),
  });
}
