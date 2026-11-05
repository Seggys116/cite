import { fmtBytes, fmtDate, fmtInt } from './ui.js';

export const MAX_RETENTION_DAYS = 3650;
export const DEFAULT_LIMIT_DAYS = 90;
const DAY_MS = 86400000;
const NAME_RE = /^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$/;
const DATE_RE = /^(\d{4})-(\d{2})-(\d{2})$/;

export const FOREVER_NOTE = 'Hourly history is never deleted. Raw requests are still limited by the recent events setting.';
export const ARCHIVE_NOTE = 'Archives are kept on the node and can be downloaded from the storage card on the Traffic page.';
export const DELETE_WARNING = 'Archiving is off. Data older than the limit will be deleted permanently and cannot be recovered.';
export const SUPPORT_NOTE = 'This node needs a connector update before it can back up, archive or cut data.';

export function parseDays(text, label = 'Days') {
  const t = String(text ?? '').trim();
  if (!/^\d+$/.test(t)) return { error: `${label} must be a whole number from 1 to ${MAX_RETENTION_DAYS}.` };
  const n = Number(t);
  if (n < 1 || n > MAX_RETENTION_DAYS) return { error: `${label} must be between 1 and ${MAX_RETENTION_DAYS}.` };
  return { value: n };
}

// Zero means keep forever; any positive number is a limit, and archiving defaults to on
export function retentionFormFrom(retention) {
  const days = Number(retention && retention.hour_buckets_days) || 0;
  return {
    mode: days > 0 ? 'limit' : 'forever',
    days: days > 0 ? String(days) : String(DEFAULT_LIMIT_DAYS),
    archive: !retention || retention.archive_before_delete !== false,
  };
}

export function deletesWithoutArchive(form) {
  return form.mode === 'limit' && !form.archive;
}

export function applyRetentionForm(current, form) {
  let days = 0;
  if (form.mode === 'limit') {
    const parsed = parseDays(form.days, 'Days to keep');
    if (parsed.error) return { error: parsed.error };
    days = parsed.value;
  } else if (form.mode !== 'forever') {
    return { error: 'Choose how long to keep data.' };
  }
  return { retention: { ...current, hour_buckets_days: days, archive_before_delete: Boolean(form.archive) } };
}

export function cutoffFromDays(days, now = Date.now()) {
  return now - days * DAY_MS;
}

// A date input has no zone, so the cut is made at local midnight at the start of that day
export function cutoffFromDate(text, now = Date.now()) {
  const m = DATE_RE.exec(String(text || '').trim());
  if (!m) return { error: 'Choose a date.' };
  const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
  const date = new Date(y, mo - 1, d);
  if (date.getFullYear() !== y || date.getMonth() !== mo - 1 || date.getDate() !== d) return { error: 'That date does not exist.' };
  const ms = date.getTime();
  if (ms > now) return { error: 'Choose a date in the past.' };
  return { value: ms };
}

// Turns the cut dialog state into the request body and the cutoff it implies, or the first problem found
export function buildCutRequest(form, now = Date.now()) {
  const request = {};
  let cutoffMs = 0;
  if (form.mode === 'date') {
    const parsed = cutoffFromDate(form.date, now);
    if (parsed.error) return { error: parsed.error };
    request.before_ms = parsed.value;
    cutoffMs = parsed.value;
  } else if (form.mode === 'days') {
    const parsed = parseDays(form.days, 'Days');
    if (parsed.error) return { error: parsed.error };
    request.before_days = parsed.value;
    cutoffMs = cutoffFromDays(parsed.value, now);
  } else {
    return { error: 'Choose how to pick the cutoff.' };
  }
  request.archive = Boolean(form.archive);
  request.dry_run = Boolean(form.dryRun);
  return { request, cutoffMs };
}

// Identifies what a preview covered, so a changed form needs a fresh preview
export function cutKey(request) {
  return JSON.stringify([request.before_days ?? null, request.before_ms ?? null, request.archive]);
}

export function canRunCut({ previewKey, request, acknowledged }) {
  if (!request || previewKey !== cutKey(request)) return false;
  return request.archive || Boolean(acknowledged);
}

const plural = (n, one, many) => `${fmtInt(n)} ${n === 1 ? one : many}`;

export function describePreview(report, cutoffMs) {
  const cut = cutoffMs || report.cutoff_ms;
  if (!report.rows) return `Nothing is older than ${fmtDate(cut)}, so no data would be cut.`;
  const oldest = report.oldest_ms ? ` The oldest is from ${fmtDate(report.oldest_ms)}.` : '';
  const fate = report.archive
    ? ' They are written to archive files and verified before anything is deleted.'
    : ' They are deleted permanently with no archive.';
  return `${plural(report.rows, 'row', 'rows')} older than ${fmtDate(cut)} would be cut.${oldest}${fate}`;
}

export function describeCut(report) {
  const files = Array.isArray(report.files) ? report.files.length : 0;
  if (!report.rows) return 'Nothing was old enough to cut.';
  if (!report.archive) return `Cut ${plural(report.rows, 'row', 'rows')} permanently.`;
  return `Cut ${plural(report.rows, 'row', 'rows')}; ${plural(report.archived_rows, 'row', 'rows')} archived in ${plural(files, 'file', 'files')}.`;
}

export function validArchiveName(name) {
  return typeof name === 'string' && NAME_RE.test(name);
}

export function archivePath(node, name) {
  if (!validArchiveName(name)) return null;
  return `/nodes/${encodeURIComponent(node)}/analytics/archives/${encodeURIComponent(name)}`;
}

// An older connector has no archive routes at all, which shows up as a plain 404 on the list or action
export function isUnsupported(err) {
  return Boolean(err) && err.status === 404;
}

export function shortSha(sha) {
  const t = String(sha || '').trim();
  return t ? t.slice(0, 12) : '-';
}

export function entryRange(entry) {
  const from = entry.from_ms ? fmtDate(entry.from_ms) : '';
  const to = entry.to_ms ? fmtDate(entry.to_ms) : '';
  if (from && to) return `${from} to ${to}`;
  return from || to;
}

export function entryView(entry) {
  const kind = entry.kind === 'backup' ? 'Backup' : entry.kind === 'archive' ? 'Archive' : 'Other';
  const hasRows = entry.rows !== null && entry.rows !== undefined;
  return {
    name: String(entry.name),
    kind,
    isBackup: entry.kind === 'backup',
    size: fmtBytes(entry.bytes),
    created: entry.created_ms ? fmtDate(entry.created_ms) : '-',
    sha: shortSha(entry.sha256),
    rows: hasRows ? fmtInt(entry.rows) : '',
    range: entryRange(entry),
    actionable: validArchiveName(entry.name),
  };
}

export function sortEntries(items) {
  return [...(items || [])].sort((a, b) => (b.created_ms || 0) - (a.created_ms || 0));
}
