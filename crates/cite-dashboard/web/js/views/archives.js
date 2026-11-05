import { h } from '../dom.js';
import { nodeApi, isMock } from '../api.js';
import {
  button, confirmDialog, dataTable, field, loadInto, openModal, pill, saveText, segmented, skeletonBlock, startNavigation, toast, withBusy,
  formatError, fmtBytes, fmtInt,
} from '../ui.js';
import {
  MAX_RETENTION_DAYS, SUPPORT_NOTE, DELETE_WARNING, archivePath, buildCutRequest, canRunCut, cutKey, describeCut, describePreview,
  entryView, isUnsupported, sortEntries,
} from '../archivelib.js';

const CUT_DEFAULT_DAYS = '90';

function checkRow(input, text) {
  return h('label', { class: 'check-row' }, input, h('span', {}, text));
}

function today() {
  const d = new Date();
  const pad = (v) => String(v).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

// Shows the node's answer for a failed archive call, naming the connector update when the routes are missing
function failureText(ex) {
  return isUnsupported(ex) ? SUPPORT_NOTE : formatError(ex);
}

export function openCutDialog({ node, onDone }) {
  const n = nodeApi(node);
  const form = { mode: 'days', days: CUT_DEFAULT_DAYS, date: '', archive: true };
  let previewKey = '';
  let previewRows = 0;
  let previewText = '';
  let acknowledged = false;

  const daysIn = h('input', { class: 'input mono', type: 'number', min: '1', max: String(MAX_RETENTION_DAYS), inputmode: 'numeric', 'aria-label': 'Cut data older than this many days' });
  daysIn.value = form.days;
  const dateIn = h('input', { class: 'input', type: 'date', max: today(), 'aria-label': 'Cut data before this date' });
  const daysField = field('Older than (days)', daysIn, `Whole days from 1 to ${MAX_RETENTION_DAYS}.`);
  const dateField = field('Before this date', dateIn, 'Data from earlier days is cut; the day itself stays.');
  const archiveIn = h('input', { type: 'checkbox', checked: true });
  const ackIn = h('input', { type: 'checkbox' });
  const warn = h('p', { class: 'notice warn', role: 'note', hidden: true }, DELETE_WARNING);
  const ackRow = checkRow(ackIn, 'I understand this deletes data permanently');
  const errorBox = h('div', { class: 'form-error', role: 'alert', hidden: true });
  const result = h('p', { class: 'muted', role: 'status', 'aria-live': 'polite' });

  const current = () => buildCutRequest({ ...form, dryRun: false });
  const sync = () => {
    daysField.hidden = form.mode !== 'days';
    dateField.hidden = form.mode !== 'date';
    warn.hidden = form.archive;
    ackRow.hidden = form.archive;
    const built = current();
    const ready = !built.error && previewRows > 0 && canRunCut({ previewKey, request: built.request, acknowledged });
    cutBtn.disabled = !ready;
    cutBtn.classList.toggle('btn-danger', !form.archive);
    cutBtn.classList.toggle('btn-primary', form.archive);
    if (previewKey) {
      const same = !built.error && previewKey === cutKey(built.request);
      result.textContent = same ? previewText : 'The settings changed. Preview again before cutting.';
    }
  };
  const fail = (message) => {
    errorBox.textContent = message;
    errorBox.hidden = !message;
  };

  const modeSeg = segmented({
    label: 'How to pick the cutoff',
    options: [{ value: 'days', label: 'Older than N days' }, { value: 'date', label: 'Before a date' }],
    value: form.mode,
    onChange: (v) => { form.mode = v; sync(); },
  });
  daysIn.addEventListener('input', () => { form.days = daysIn.value; sync(); });
  dateIn.addEventListener('input', () => { form.date = dateIn.value; sync(); });
  archiveIn.addEventListener('change', () => {
    form.archive = archiveIn.checked;
    if (form.archive) {
      acknowledged = false;
      ackIn.checked = false;
    }
    sync();
  });
  ackIn.addEventListener('change', () => { acknowledged = ackIn.checked; sync(); });

  const preview = button('Preview', { iconName: 'search' });
  const cutBtn = button('Cut', { kind: 'primary', iconName: 'trash', disabled: true });
  const cancel = button('Cancel', { onClick: () => modal.close() });

  preview.addEventListener('click', async () => {
    fail('');
    const built = buildCutRequest({ ...form, dryRun: true });
    if (built.error) {
      fail(built.error);
      return;
    }
    result.textContent = 'Counting rows...';
    try {
      const report = await withBusy(preview, () => n.post('/analytics/cut', built.request));
      previewKey = cutKey(built.request);
      previewRows = Number(report.rows) || 0;
      previewText = describePreview(report, built.cutoffMs);
      result.textContent = previewText;
    } catch (ex) {
      previewKey = '';
      previewRows = 0;
      previewText = '';
      result.textContent = '';
      fail(failureText(ex));
    }
    sync();
  });

  cutBtn.addEventListener('click', async () => {
    fail('');
    const built = current();
    if (built.error || !canRunCut({ previewKey, request: built.request, acknowledged })) return;
    if (!built.request.archive) {
      const ok = await confirmDialog({
        title: 'Delete data permanently',
        message: 'This cut writes no archive. The rows are removed from the node and cannot be recovered.',
        confirmLabel: 'Delete permanently',
        danger: true,
      });
      if (!ok) return;
    }
    result.textContent = 'Cutting...';
    try {
      const report = await withBusy(cutBtn, () => n.post('/analytics/cut', built.request));
      toast(describeCut(report), 'success');
      modal.close();
      if (onDone) onDone(describeCut(report));
    } catch (ex) {
      result.textContent = '';
      fail(failureText(ex));
      sync();
    }
  });

  const content = h('div', { class: 'form' },
    h('p', { class: 'muted' }, 'Move old rows out of the live database. Preview first to see how many rows are affected.'),
    field('Cutoff', modeSeg, null, { group: true }),
    daysField, dateField,
    checkRow(archiveIn, 'Archive the rows before deleting them'),
    h('p', { class: 'hint' }, 'Archived rows are written to files on the node and verified before anything is deleted.'),
    warn, ackRow, errorBox, result);
  const modal = openModal({ title: 'Cut old data', content, actions: [cancel, preview, cutBtn] });
  sync();
  return modal;
}

export function archivesPanel(node, { onDataChanged } = {}) {
  const n = nodeApi(node);
  const status = h('p', { class: 'muted', role: 'status', 'aria-live': 'polite' });
  const host = h('div', {});
  const backupBtn = button('Back up now', { iconName: 'file' });
  const cutBtn = button('Cut old data', { iconName: 'clock' });
  const changed = () => {
    if (onDataChanged) onDataChanged();
  };
  const setSupported = (ok) => {
    backupBtn.hidden = !ok;
    cutBtn.hidden = !ok;
  };
  const load = async () => {
    try {
      const list = await n.get('/analytics/archives');
      setSupported(true);
      return list || { items: [], dir_bytes: 0 };
    } catch (ex) {
      if (isUnsupported(ex)) {
        setSupported(false);
        return null;
      }
      throw ex;
    }
  };

  const download = async (view) => {
    const path = archivePath(node, view.name);
    if (!path) return;
    if (isMock) {
      const text = await n.get('/analytics/archives/' + encodeURIComponent(view.name));
      saveText(String(text), view.name, 'text/plain');
    } else {
      startNavigation('/api/v1' + path);
    }
    status.textContent = `Download of ${view.name} started. Your browser saves it to its downloads folder.`;
  };

  const restore = async (view) => {
    const ok = await confirmDialog({
      title: `Restore ${view.kind.toLowerCase()}`,
      message: `Import ${view.name} into the live analytics data? The file stays on the node.`,
      confirmLabel: 'Restore',
    });
    if (!ok) return;
    status.textContent = `Restoring ${view.name}...`;
    try {
      const res = await n.post('/analytics/restore', { name: view.name });
      status.textContent = `Restored ${fmtInt(res && res.rows)} rows from ${view.name}.`;
      toast('Restore finished', 'success');
      changed();
    } catch (ex) {
      status.textContent = '';
      toast(failureText(ex), 'error');
    }
  };

  const remove = async (view, again) => {
    const ok = await confirmDialog({
      title: `Delete ${view.kind.toLowerCase()}`,
      message: `Delete ${view.name} from the node? Download it first if you want to keep a copy. This cannot be undone.`,
      confirmLabel: 'Delete',
      danger: true,
    });
    if (!ok) return;
    try {
      await n.del('/analytics/archives/' + encodeURIComponent(view.name));
      status.textContent = `Deleted ${view.name}.`;
      again();
    } catch (ex) {
      toast(failureText(ex), 'error');
    }
  };

  const rowActions = (view, again) => {
    const act = (label, iconName, fn, kind) => button(label, {
      size: 'sm', iconName, kind, title: `${label} ${view.name}`, disabled: !view.actionable,
      onClick: () => fn().catch((ex) => toast(failureText(ex), 'error')),
    });
    return h('div', { class: 'pill-row' },
      act('Download', 'download', () => download(view)),
      act('Restore', 'refresh', () => restore(view)),
      act('Delete', 'trash', () => remove(view, again), 'danger'));
  };

  const run = loadInto(host, load, (list, again) => {
    if (list === null) return h('p', { class: 'notice', role: 'note' }, SUPPORT_NOTE);
    const items = sortEntries(list.items);
    const intro = items.length
      ? `${fmtInt(items.length)} ${items.length === 1 ? 'file' : 'files'} using ${fmtBytes(list.dir_bytes)} on the node.`
      : 'No archives or backups yet. Back up now, or cut old data with archiving on, to create one.';
    return h('div', { class: 'stack-sm' },
      h('div', { class: 'section-row' }, h('h2', { class: 'section-title' }, 'Archives and backups')),
      h('p', { class: 'muted' }, intro),
      items.length ? dataTable({
        columns: [
          { label: 'Name', render: (e) => h('span', { class: 'mono wrap-any' }, entryView(e).name) },
          { label: 'Kind', render: (e) => pill(entryView(e).kind, 'muted') },
          { label: 'Size', align: 'right', render: (e) => h('span', { class: 'mono' }, entryView(e).size) },
          { label: 'Created', render: (e) => h('span', { class: 'mono muted' }, entryView(e).created) },
          { label: 'SHA-256', render: (e) => h('span', { class: 'mono muted', title: e.sha256 || '' }, entryView(e).sha) },
          {
            label: 'Contents',
            render: (e) => {
              const v = entryView(e);
              const parts = [v.rows ? `${v.rows} rows` : '', v.range].filter(Boolean);
              return h('span', { class: 'muted' }, parts.length ? parts.join(', ') : '-');
            },
          },
          { label: 'Actions', render: (e) => rowActions(entryView(e), again) },
        ],
        rows: items,
      }) : null);
  }, { skeleton: () => skeletonBlock(80) });

  backupBtn.addEventListener('click', async () => {
    status.textContent = 'Creating a backup...';
    try {
      const made = await withBusy(backupBtn, () => n.post('/analytics/backup', {}));
      const view = entryView(made);
      status.textContent = `Backup ${view.name} created (${view.size}).`;
      toast('Backup created', 'success');
      run();
    } catch (ex) {
      status.textContent = '';
      if (isUnsupported(ex)) setSupported(false);
      toast(failureText(ex), 'error');
    }
  });

  cutBtn.addEventListener('click', () => {
    openCutDialog({
      node,
      onDone: (text) => {
        status.textContent = text;
        run();
        changed();
      },
    });
  });

  return {
    el: h('div', { class: 'stack-sm' }, host, status),
    actions: [backupBtn, cutBtn],
    refresh: run,
  };
}
