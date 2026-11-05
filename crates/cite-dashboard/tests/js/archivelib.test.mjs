import test from 'node:test';
import assert from 'node:assert/strict';
import {
  MAX_RETENTION_DAYS, applyRetentionForm, archivePath, buildCutRequest, canRunCut, cutKey, cutoffFromDate, cutoffFromDays,
  deletesWithoutArchive, describeCut, describePreview, entryView, isUnsupported, parseDays, retentionFormFrom, shortSha,
  sortEntries, validArchiveName,
} from '../../web/js/archivelib.js';

const DAY = 86400000;
const NOW = new Date(2026, 10, 5, 12, 0, 0).getTime();

test('zero days means keep forever and archiving defaults to on', () => {
  assert.deepEqual(retentionFormFrom({ hour_buckets_days: 0 }), { mode: 'forever', days: '90', archive: true });
  assert.deepEqual(retentionFormFrom(undefined), { mode: 'forever', days: '90', archive: true });
  assert.deepEqual(retentionFormFrom({ hour_buckets_days: 30, archive_before_delete: false }), { mode: 'limit', days: '30', archive: false });
  assert.equal(retentionFormFrom({ hour_buckets_days: 30 }).archive, true);
});

test('saving forever writes zero and keeps the other retention fields', () => {
  const current = { recent_events: 5000, audit_days: 365, hour_buckets_days: 90 };
  const out = applyRetentionForm(current, { mode: 'forever', days: '12', archive: true });
  assert.deepEqual(out.retention, { recent_events: 5000, audit_days: 365, hour_buckets_days: 0, archive_before_delete: true });
});

test('a day limit is validated between 1 and 3650', () => {
  assert.equal(applyRetentionForm({}, { mode: 'limit', days: '3650', archive: false }).retention.hour_buckets_days, 3650);
  for (const bad of ['0', '3651', '-1', '1.5', 'abc', '', ' ']) {
    assert.ok(applyRetentionForm({}, { mode: 'limit', days: bad, archive: true }).error, bad);
  }
  assert.ok(applyRetentionForm({}, { mode: 'nonsense', days: '5', archive: true }).error);
  assert.equal(parseDays(' 30 ').value, 30);
  assert.match(parseDays('0').error, new RegExp(String(MAX_RETENTION_DAYS)));
});

test('only a limit with archiving off is destructive', () => {
  assert.equal(deletesWithoutArchive({ mode: 'limit', days: '30', archive: false }), true);
  assert.equal(deletesWithoutArchive({ mode: 'limit', days: '30', archive: true }), false);
  assert.equal(deletesWithoutArchive({ mode: 'forever', days: '30', archive: false }), false);
});

test('cutoffs come from days or a local date and never from the future', () => {
  assert.equal(cutoffFromDays(30, NOW), NOW - 30 * DAY);
  assert.equal(cutoffFromDate('2026-11-01', NOW).value, new Date(2026, 10, 1).getTime());
  assert.equal(cutoffFromDate('2026-11-05', NOW).value, new Date(2026, 10, 5).getTime());
  for (const bad of ['', 'yesterday', '2026-02-31', '2026-13-01', '26-11-01', '2026-11-06']) {
    assert.ok(cutoffFromDate(bad, NOW).error, bad);
  }
});

test('cut requests carry exactly one cutoff plus the archive and dry run flags', () => {
  const byDays = buildCutRequest({ mode: 'days', days: '30', archive: true, dryRun: true }, NOW);
  assert.deepEqual(byDays.request, { before_days: 30, archive: true, dry_run: true });
  assert.equal(byDays.cutoffMs, NOW - 30 * DAY);
  const byDate = buildCutRequest({ mode: 'date', date: '2026-10-01', archive: false, dryRun: false }, NOW);
  assert.deepEqual(byDate.request, { before_ms: new Date(2026, 9, 1).getTime(), archive: false, dry_run: false });
  assert.equal('before_days' in byDate.request, false);
  assert.ok(buildCutRequest({ mode: 'days', days: '0', archive: true }, NOW).error);
  assert.ok(buildCutRequest({ mode: 'days', days: '9999', archive: true }, NOW).error);
  assert.ok(buildCutRequest({ mode: 'date', date: '', archive: true }, NOW).error);
  assert.ok(buildCutRequest({ mode: 'other', archive: true }, NOW).error);
});

test('a cut needs a matching preview and an acknowledgement when archiving is off', () => {
  const archived = buildCutRequest({ mode: 'days', days: '30', archive: true }, NOW).request;
  const bare = buildCutRequest({ mode: 'days', days: '30', archive: false }, NOW).request;
  assert.equal(canRunCut({ previewKey: '', request: archived, acknowledged: false }), false);
  assert.equal(canRunCut({ previewKey: cutKey(archived), request: archived, acknowledged: false }), true);
  assert.equal(canRunCut({ previewKey: cutKey(archived), request: bare, acknowledged: true }), false);
  assert.equal(canRunCut({ previewKey: cutKey(bare), request: bare, acknowledged: false }), false);
  assert.equal(canRunCut({ previewKey: cutKey(bare), request: bare, acknowledged: true }), true);
  const other = buildCutRequest({ mode: 'days', days: '31', archive: true }, NOW).request;
  assert.equal(canRunCut({ previewKey: cutKey(archived), request: other, acknowledged: true }), false);
  assert.equal(canRunCut({ previewKey: cutKey(archived), request: null, acknowledged: true }), false);
});

test('preview and result text state the counts and whether data is archived', () => {
  const none = describePreview({ rows: 0, cutoff_ms: NOW, archive: true }, NOW);
  assert.match(none, /no data would be cut/);
  const kept = describePreview({ rows: 1200, oldest_ms: NOW - 40 * DAY, cutoff_ms: NOW, archive: true }, NOW);
  assert.match(kept, /^1,200 rows older than \d{4}-\d{2}-\d{2} \d{2}:\d{2} would be cut\./);
  assert.match(kept, /verified before anything is deleted/);
  assert.match(describePreview({ rows: 1, cutoff_ms: NOW, archive: false }, NOW), /^1 row .*deleted permanently/);
  assert.equal(describeCut({ rows: 0 }), 'Nothing was old enough to cut.');
  assert.equal(describeCut({ rows: 5, archive: false }), 'Cut 5 rows permanently.');
  assert.equal(describeCut({ rows: 5, archive: true, archived_rows: 5, files: ['a.ndjson.gz'] }), 'Cut 5 rows; 5 rows archived in 1 file.');
});

test('archive names are plain file names', () => {
  for (const ok of ['requests-2026-11-05.ndjson.gz', 'analytics-20261105-101500.db', 'a_b-c.1']) assert.equal(validArchiveName(ok), true, ok);
  for (const bad of ['', '.hidden', '..', 'a/b', 'a\\b', 'a b', 'a%2e', 'é.gz', 'x'.repeat(129), null, 5]) assert.equal(validArchiveName(bad), false, String(bad));
  assert.equal(archivePath('edge 1', 'a.db'), '/nodes/edge%201/analytics/archives/a.db');
  assert.equal(archivePath('edge', '../etc'), null);
});

test('entries are formatted for the list and tolerate missing optional fields', () => {
  const archive = entryView({ name: 'requests-2026-11-05.ndjson.gz', kind: 'archive', bytes: 2048, created_ms: NOW, sha256: 'ab'.repeat(32), rows: 1234, from_ms: NOW - DAY, to_ms: NOW });
  assert.equal(archive.kind, 'Archive');
  assert.equal(archive.size, '2.0 KB');
  assert.equal(archive.sha, 'abababababab');
  assert.equal(archive.rows, '1,234');
  assert.match(archive.range, /^\d{4}-\d{2}-\d{2} \d{2}:\d{2} to \d{4}-\d{2}-\d{2} \d{2}:\d{2}$/);
  assert.equal(archive.actionable, true);
  const backup = entryView({ name: 'analytics-1.db', kind: 'backup', bytes: 10, created_ms: NOW, sha256: '', rows: null, from_ms: null, to_ms: null });
  assert.equal(backup.kind, 'Backup');
  assert.equal(backup.isBackup, true);
  assert.equal(backup.rows, '');
  assert.equal(backup.range, '');
  assert.equal(backup.sha, '-');
  assert.equal(entryView({ name: '../x', kind: 'weird', bytes: 0 }).actionable, false);
  assert.equal(entryView({ name: 'a', kind: 'weird', bytes: 0 }).kind, 'Other');
  assert.equal(shortSha('0123456789abcdef'), '0123456789ab');
});

test('entries sort newest first without changing the input', () => {
  const items = [{ name: 'a', created_ms: 1 }, { name: 'b', created_ms: 3 }, { name: 'c', created_ms: 2 }];
  assert.deepEqual(sortEntries(items).map((e) => e.name), ['b', 'c', 'a']);
  assert.deepEqual(items.map((e) => e.name), ['a', 'b', 'c']);
  assert.deepEqual(sortEntries(undefined), []);
});

test('a 404 marks a node without archive support', () => {
  assert.equal(isUnsupported({ status: 404 }), true);
  assert.equal(isUnsupported({ status: 409 }), false);
  assert.equal(isUnsupported(null), false);
});
