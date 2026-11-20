import test from 'node:test';
import assert from 'node:assert/strict';
import {
  BACKUP_EVERY_HOURS, DEFAULT_MAJOR, PG_MAJORS, PRESETS, TRADEOFFS,
  backupRows, canDownload, canOverride, canPush, canRestore, conflictSummary, conflictsFromError, dataFeatures, deleteBackupBlock,
  externalUrlProblem, healthKind, jobDelayMs, linkDraftProblem, linkLabel, linkRequest, linkedFromText, linksForTarget, locations,
  manualConflicts, orphanText, pgNameProblem, pollJob, policyFromForm, policyProblem, policyToForm, presetBody, presetOptionsProblem,
  presetPreview, presetSpec, prunePlanRows, pruneSummary, resourceNameProblem, restoreText, retentionProblem, retentionText, runsServer,
  s3Problem, scheduleText, secretBytesProblem, sharedBody, sharedProblem, sharedToForm, showsDataTab, showsDatabasesPage, suggestedVar,
  targetBody, targetProblem, tenantRows, userCreateBody, userFormProblem, userPatchBody, wholeNumberProblem,
  deleteBlockedReason, envTargetOf, jobStepText, levelLabel, linkRows, rotateSecretText, userState,
  FREEZE_OPTIONS, anyRunning, convertActions, convertSettled, convertTarget, mismatchRows, phaseLabel, pollUntil, transferActions,
  transferPercent, transferPlanBody, transferProblem, transferRows, transferSettled, transfersOfSite, verifyText,
  unmanagedSessions,
} from '../../web/js/datalib.js';

const pgInfo = { capabilities: ['data-postgres', 'data-backups'] };
const nodeSite = { source: { repo: 'a/b', runtime: 'node' } };

test('the default major is 18 and 17 is selectable, nothing else', () => {
  assert.equal(DEFAULT_MAJOR, 18);
  assert.deepEqual(PG_MAJORS, [18, 17]);
});

test('the trade-off table covers each row of the shared instance design', () => {
  assert.deepEqual(TRADEOFFS.map((r) => r.aspect), ['Isolation', 'Noisy neighbour', 'Postgres major', 'Blast radius', 'Resources', 'Restart', 'Backups']);
  assert.ok(TRADEOFFS.every((r) => r.dedicated && r.shared));
});

test('database and user names follow the node rules', () => {
  assert.equal(pgNameProblem('app', 'database'), '');
  assert.notEqual(pgNameProblem('App', 'database'), '');
  assert.notEqual(pgNameProblem('my-db', 'database'), '');
  assert.notEqual(pgNameProblem('a'.repeat(17), 'database'), '');
  assert.notEqual(pgNameProblem('postgres', 'database'), '');
  assert.equal(pgNameProblem('postgres', 'user name'), '');
  assert.equal(resourceNameProblem('auth-secret'), '');
  assert.notEqual(resourceNameProblem('1auth'), '');
  assert.notEqual(resourceNameProblem('a'.repeat(32)), '');
});

test('whole numbers are bounded and blank is allowed only when optional', () => {
  assert.equal(wholeNumberProblem('5', { min: 1, max: 9, what: 'the count' }), '');
  assert.match(wholeNumberProblem('', { min: 1, max: 9, what: 'the count' }), /Enter the count/);
  assert.equal(wholeNumberProblem('', { min: 1, max: 9, what: 'the count', optional: true }), '');
  assert.match(wholeNumberProblem('10', { min: 1, max: 9, what: 'the count' }), /between 1 and 9/);
  assert.match(wholeNumberProblem('1.5', { min: 1, max: 9, what: 'the count' }), /whole number/);
  assert.equal(secretBytesProblem('32'), '');
  assert.notEqual(secretBytesProblem('31'), '');
  assert.notEqual(secretBytesProblem('129'), '');
});

test('a new user body carries only what was filled in', () => {
  const body = userCreateBody({ name: ' reporting ', level: 'readonly', connectionLimit: '', statementTimeoutMs: '5000', idleTimeoutMs: '' });
  assert.deepEqual(body, { name: 'reporting', level: 'readonly', statement_timeout_ms: 5000 });
  assert.equal(userFormProblem({ name: 'reporting', level: 'readonly', connectionLimit: '10' }, { existing: [] }), '');
  assert.match(userFormProblem({ name: 'app', level: 'owner' }, { existing: ['app'] }), /already exists/);
  assert.notEqual(userFormProblem({ name: 'x', level: 'root' }, { existing: [] }), '');
  assert.notEqual(userFormProblem({ name: 'x', level: 'owner', connectionLimit: '501' }, { existing: [] }), '');
  assert.notEqual(userFormProblem({ name: 'x', level: 'owner', idleTimeoutMs: '10' }, { existing: [] }), '');
});

test('a user patch sends only the changed fields', () => {
  const user = { name: 'app', level: 'readwrite', connection_limit: 20, statement_timeout_ms: 30000, idle_in_transaction_timeout_ms: 60000 };
  assert.deepEqual(userPatchBody(user, { level: 'readwrite', connectionLimit: '20', statementTimeoutMs: '30000', idleTimeoutMs: '60000' }), {});
  assert.deepEqual(userPatchBody(user, { level: 'readonly', connectionLimit: '5', statementTimeoutMs: '30000', idleTimeoutMs: '' }), { level: 'readonly', connection_limit: 5 });
});

test('every preset maps to the links of the design table', () => {
  assert.deepEqual(PRESETS.map((p) => p.id), ['generic', 'prisma', 'drizzle', 'authjs', 'better-auth']);
  const keys = (id) => presetSpec(id).links.map((l) => `${l.var}:${l.target}`);
  assert.deepEqual(keys('generic'), [
    'DATABASE_URL:runtime', 'PGHOST:runtime', 'PGPORT:runtime', 'PGDATABASE:runtime', 'PGUSER:runtime', 'PGPASSWORD:runtime', 'PGSSLMODE:runtime',
    'MIGRATION_DATABASE_URL:build',
  ]);
  assert.deepEqual(keys('prisma'), ['DATABASE_URL:runtime', 'DATABASE_URL:build', 'DIRECT_URL:build']);
  assert.deepEqual(keys('drizzle'), ['DATABASE_URL:runtime', 'DATABASE_URL:build']);
  assert.deepEqual(keys('authjs'), ['AUTH_SECRET:runtime', 'AUTH_DATABASE_URL:runtime', 'AUTH_MIGRATION_DATABASE_URL:build']);
  assert.deepEqual(keys('better-auth'), ['BETTER_AUTH_SECRET:runtime', 'BETTER_AUTH_URL:runtime', 'DATABASE_URL:runtime', 'DATABASE_URL:build']);
  assert.equal(presetSpec('nope'), null);
});

test('runtime links use the readwrite user and build links the owner', () => {
  const spec = presetSpec('prisma');
  const rt = spec.links.find((l) => l.var === 'DATABASE_URL' && l.target === 'runtime');
  const bd = spec.links.find((l) => l.var === 'DATABASE_URL' && l.target === 'build');
  assert.equal(rt.source.user, 'app');
  assert.equal(bd.source.user, 'migrate');
  assert.deepEqual(spec.users, [['app', 'app', 'readwrite'], ['app', 'migrate', 'owner']]);
});

test('auth presets create a generated secret and Auth.js uses a separate database', () => {
  assert.deepEqual(presetSpec('authjs').secrets, ['auth-secret']);
  assert.deepEqual(presetSpec('better-auth').secrets, ['better-auth-secret']);
  assert.ok(presetSpec('authjs').users.every(([db]) => db === 'auth'));
  assert.deepEqual(presetSpec('prisma').secrets, []);
});

test('a preset preview lists what is new, what exists and what is created', () => {
  const data = {
    postgres: { databases: [{ name: 'app', users: [{ name: 'app', level: 'readwrite' }] }] },
    secrets: [],
    links: [{ var: 'DATABASE_URL', target: 'runtime', source: { kind: 'postgres', database: 'app', user: 'app', field: 'url' } }],
  };
  const p = presetPreview('prisma', {}, data, { runtime: [], build: [] });
  assert.equal(p.problem, '');
  assert.deepEqual(p.users, [{ database: 'app', user: 'migrate', level: 'owner' }]);
  assert.deepEqual(p.databases, []);
  assert.deepEqual(p.links.map((l) => l.state), ['exists', 'new', 'new']);
  const auth = presetPreview('authjs', {}, data, {});
  assert.deepEqual(auth.databases, ['auth']);
  assert.deepEqual(auth.secrets, ['auth-secret']);
});

test('a preview reports a manual var it would replace and a link it cannot', () => {
  const data = { postgres: { databases: [{ name: 'app', users: [] }] }, secrets: [], links: [] };
  const p = presetPreview('drizzle', {}, data, { runtime: ['DATABASE_URL'], build: [] });
  assert.deepEqual(p.conflicts, [{ var: 'DATABASE_URL', target: 'runtime', set_by: 'manual' }]);
  assert.equal(p.needsOverride, true);
  const other = { postgres: { databases: [] }, secrets: [], links: [{ var: 'DATABASE_URL', target: 'build', source: { kind: 'secret', name: 'x' } }] };
  const blocked = presetPreview('drizzle', {}, other, {});
  assert.match(blocked.problem, /already linked/);
  assert.equal(blocked.links[1].state, 'blocked');
});

test('a user at the wrong level blocks a preset', () => {
  const data = { postgres: { databases: [{ name: 'app', users: [{ name: 'migrate', level: 'readonly' }] }] }, secrets: [], links: [] };
  assert.match(presetPreview('generic', {}, data, {}).problem, /migrate/);
});

test('preset options are checked and sent with their wire names', () => {
  assert.equal(presetOptionsProblem('prisma', {}), '');
  assert.match(presetOptionsProblem('prisma', { runtimeUser: 'x', migrateUser: 'x' }), /differ/);
  assert.notEqual(presetOptionsProblem('prisma', { database: 'Bad' }), '');
  assert.deepEqual(presetBody('prisma', {}, false), { preset: 'prisma', database: 'app', runtime_user: 'app', migrate_user: 'migrate' });
  const auth = presetBody('authjs', { authDatabase: 'idp' }, true);
  assert.equal(auth.auth_database, 'idp');
  assert.equal(auth.override_manual, true);
});

test('link labels prefer the node text and fall back to the source', () => {
  const link = { var: 'DATABASE_URL', target: 'runtime', label: 'postgres app/app url', source: { kind: 'postgres', database: 'app', user: 'app', field: 'url' } };
  assert.equal(linkLabel(link), 'postgres app/app url');
  assert.equal(linkedFromText(link), 'linked from postgres app/app url');
  assert.equal(linkLabel({ source: { kind: 'secret', name: 'auth-secret' } }), 'secret auth-secret');
  assert.equal(linkLabel({ source: { kind: 'site_url' } }), 'site URL');
  const map = linksForTarget([link, { ...link, var: 'X', target: 'build' }], 'runtime');
  assert.deepEqual([...map.keys()], ['DATABASE_URL']);
});

test('a link draft is checked before it is sent', () => {
  const draft = { var: 'DATABASE_URL', target: 'both', kind: 'postgres', database: 'app', user: 'app', field: 'url' };
  assert.equal(linkDraftProblem(draft, { links: [] }), '');
  assert.notEqual(linkDraftProblem({ ...draft, var: 'lower' }, {}), '');
  assert.notEqual(linkDraftProblem({ ...draft, user: '' }, {}), '');
  assert.notEqual(linkDraftProblem({ ...draft, field: 'nope' }, {}), '');
  assert.notEqual(linkDraftProblem({ ...draft, kind: 'secret', name: '' }, {}), '');
  const clash = { links: [{ var: 'DATABASE_URL', target: 'build', source: { kind: 'secret', name: 'x' }, label: 'secret x' }] };
  assert.match(linkDraftProblem(draft, clash), /already linked from secret x/);
  assert.deepEqual(linkRequest({ ...draft, var: ' DATABASE_URL ' }), { var: 'DATABASE_URL', target: 'both', source: { kind: 'postgres', database: 'app', user: 'app', field: 'url' } });
  assert.equal(suggestedVar({ kind: 'secret', name: 'auth-secret' }), 'AUTH_SECRET');
  assert.equal(suggestedVar({ kind: 'postgres', field: 'url' }), 'DATABASE_URL');
  assert.equal(suggestedVar({ kind: 'postgres', field: 'host' }), 'PGHOST');
});

test('a 409 body is read into conflicts and anything else is not', () => {
  const body = { error: 'conflict', conflicts: [{ var: 'A', target: 'runtime', set_by: 'manual' }, { var: 'B', target: 'build', set_by: 'link' }, null] };
  assert.deepEqual(conflictsFromError({ status: 409, data: body }), [
    { var: 'A', target: 'runtime', set_by: 'manual' }, { var: 'B', target: 'build', set_by: 'link' },
  ]);
  assert.equal(conflictsFromError({ status: 409, data: { error: 'x' } }), null);
  assert.equal(conflictsFromError({ status: 409, data: { conflicts: [] } }), null);
  assert.equal(conflictsFromError({ status: 400, data: body }), null);
  assert.equal(conflictsFromError(null), null);
  assert.equal(conflictsFromError(new Error('boom')), null);
});

test('override applies only when every conflict is a manual var', () => {
  const manual = [{ var: 'A', target: 'runtime', set_by: 'manual' }];
  const mixed = [...manual, { var: 'B', target: 'build', set_by: 'link' }];
  assert.equal(canOverride(manual), true);
  assert.equal(canOverride(mixed), false);
  assert.equal(canOverride([]), false);
  assert.match(conflictSummary(manual), /Override deletes the manual value of A \(runtime\)/);
  assert.match(conflictSummary(mixed), /B \(build\) already linked elsewhere/);
});

test('manual conflicts are found per target and skip vars that are already links', () => {
  const requested = [{ var: 'DATABASE_URL', target: 'both' }, { var: 'OTHER', target: 'runtime' }];
  const found = manualConflicts(requested, { runtime: ['DATABASE_URL', 'OTHER'], build: [] }, [{ var: 'OTHER', target: 'runtime' }]);
  assert.deepEqual(found, [{ var: 'DATABASE_URL', target: 'runtime', set_by: 'manual' }]);
  assert.deepEqual(manualConflicts(requested, {}, []), []);
});

test('external URLs need a user, a host and a database, and are never echoed', () => {
  assert.equal(externalUrlProblem('postgres://u:p@db.example.com:5432/app?sslmode=require'), '');
  assert.notEqual(externalUrlProblem('mysql://u:p@h/d'), '');
  assert.notEqual(externalUrlProblem('postgres://h/d'), '');
  assert.notEqual(externalUrlProblem('postgres://u:p@h'), '');
  assert.notEqual(externalUrlProblem('postgres://u:p@a,b/d'), '');
  assert.equal(externalUrlProblem('', { required: false }), '');
  const hunter = externalUrlProblem('postgres://u:hunter2@/d');
  assert.ok(!hunter.includes('hunter2'));
});

test('an S3 attachment needs keys when new and keeps them when omitted on edit', () => {
  const form = { name: 'media', endpoint: 'https://s3.example.com', bucket: 'b', region: 'eu', accessKeyId: '', secretAccessKey: '' };
  assert.match(s3Problem(form), /both/);
  assert.equal(s3Problem(form, { hasKeys: true }), '');
  assert.match(s3Problem({ ...form, accessKeyId: 'AK' }, { hasKeys: true }), /both keys/);
  assert.equal(s3Problem({ ...form, accessKeyId: 'AK', secretAccessKey: 'SK' }), '');
  assert.notEqual(s3Problem({ ...form, name: 'Bad Name' }, { hasKeys: true }), '');
  assert.notEqual(s3Problem({ ...form, endpoint: 'nope' }, { hasKeys: true }), '');
});

test('a backup target must be https and carries keys only when typed', () => {
  const form = {
    name: 'offsite', endpoint: 'https://s3.example.com', bucket: 'b', region: 'eu', pathStyle: true, prefix: ' cite/ ', encrypt: true, accessKeyId: '', secretAccessKey: '',
  };
  assert.match(targetProblem({ ...form, endpoint: 'http://s3.example.com' }, { hasKeys: true }), /https/);
  assert.match(targetProblem(form), /both/);
  assert.equal(targetProblem(form, { hasKeys: true }), '');
  const body = targetBody(form);
  assert.equal(body.prefix, 'cite/');
  assert.ok(!('access_key_id' in body) && !('secret_access_key' in body));
  assert.equal(targetBody({ ...form, accessKeyId: 'AK', secretAccessKey: 'SK' }).secret_access_key, 'SK');
});

test('retention text states the policy and the always-kept versions', () => {
  const text = retentionText({ keep_all_hours: 24, daily_days: 7, weekly_weeks: 4, monthly_months: 6 });
  assert.match(text, /last 24 hours/);
  assert.match(text, /each day for 7 days/);
  assert.match(text, /each week for 4 weeks/);
  assert.match(text, /each month for 6 months/);
  assert.match(text, /Pinned versions and the newest complete version are always kept/);
  assert.match(retentionText({ keep_all_hours: 1, daily_days: 0, weekly_weeks: 0, monthly_months: 0 }), /last 1 hour\./);
  assert.match(retentionText({ keep_all_hours: 0, daily_days: 0, weekly_weeks: 0, monthly_months: 0 }), /only the newest version/);
});

test('retention numbers are bounded as the node bounds them', () => {
  const ok = { keep_all_hours: '24', daily_days: '7', weekly_weeks: '4', monthly_months: '6', pre_restore_days: '7' };
  assert.equal(retentionProblem(ok), '');
  assert.notEqual(retentionProblem({ ...ok, keep_all_hours: '721' }), '');
  assert.notEqual(retentionProblem({ ...ok, daily_days: '367' }), '');
  assert.notEqual(retentionProblem({ ...ok, weekly_weeks: '261' }), '');
  assert.notEqual(retentionProblem({ ...ok, monthly_months: '121' }), '');
  assert.notEqual(retentionProblem({ ...ok, monthly_months: '' }), '');
});

test('a policy round trips through the editor form', () => {
  const policy = {
    schedule: { every_hours: 6, minute: 5 },
    local: { keep_all_hours: 12, daily_days: 3, weekly_weeks: 2, monthly_months: 1, pre_restore_days: 9 },
    s3: { target: 'offsite', retention: { keep_all_hours: 0, daily_days: 30, weekly_weeks: 12, monthly_months: 24, pre_restore_days: 7 } },
  };
  const form = policyToForm(policy);
  assert.equal(policyProblem(form), '');
  assert.deepEqual(policyFromForm(form), policy);
  const bare = policyFromForm(policyToForm({ local: policy.local }));
  assert.ok(!('schedule' in bare) && !('s3' in bare));
  assert.deepEqual(bare.local, policy.local);
});

test('a policy with S3 copies needs a target and a valid schedule', () => {
  const form = policyToForm({ local: {} });
  form.s3On = true;
  assert.match(policyProblem(form), /target/);
  form.s3Target = 'offsite';
  assert.equal(policyProblem(form), '');
  form.scheduled = true;
  form.minute = '60';
  assert.notEqual(policyProblem(form), '');
  form.minute = '0';
  form.everyHours = '5';
  assert.notEqual(policyProblem(form), '');
  assert.deepEqual(BACKUP_EVERY_HOURS, [1, 2, 3, 4, 6, 8, 12, 24]);
  assert.equal(scheduleText(null), 'No scheduled backups.');
  assert.match(scheduleText({ every_hours: 24, minute: 3 }), /00:03 UTC/);
});

const rec = (over) => ({
  id: 'A', database: 'pg:app', version: 1, created_at: '2026-11-01T00:00:00Z', trigger: 'manual', label: null, pinned: false, size_bytes: 10, sha256: 'abcdef0123456789', status: 'ok', local: { file: 'A.cbk', stored_bytes: 12 }, s3: null, ...over,
});

test('backup rows are newest first and show where each version is held', () => {
  const rows = backupRows([
    rec({ id: 'A', version: 1 }),
    rec({ id: 'B', version: 2, created_at: '2026-11-02T00:00:00Z', s3: { target: 't', key: 'k' } }),
    rec({ id: 'C', version: 3, database: 'pg:auth', created_at: '2026-11-03T00:00:00Z' }),
  ], 'pg:app');
  assert.deepEqual(rows.map((r) => r.id), ['B', 'A']);
  assert.deepEqual(rows[0].locations, ['node', 's3']);
  assert.equal(rows[0].sha, 'abcdef01');
  assert.equal(rows[0].triggerText, 'Manual');
  assert.equal(backupRows([rec({ trigger: 'pre_restore' })])[0].triggerText, 'Before restore');
  assert.deepEqual(locations(rec({ local: null })), []);
});

test('backup actions follow status, pinning and copies', () => {
  const row = (o) => backupRows([rec(o)])[0];
  assert.equal(canDownload(row({})), true);
  assert.equal(canDownload(row({ status: 'failed' })), false);
  assert.equal(canRestore(row({}), { external: false }), true);
  assert.equal(canRestore(row({}), { external: true }), false);
  assert.equal(canPush(row({}), { hasTarget: true }), true);
  assert.equal(canPush(row({}), { hasTarget: false }), false);
  assert.equal(canPush(row({ s3: { target: 't', key: 'k' } }), { hasTarget: true }), false);
  assert.match(deleteBackupBlock(row({ pinned: true })), /Pinned/);
  assert.equal(deleteBackupBlock(row({})), '');
  assert.match(deleteBackupBlock(row({ status: 'running' })), /running/);
});

test('the restore text says a backup is taken first', () => {
  const text = restoreText(backupRows([rec({ version: 4 })])[0], 'shop');
  assert.match(text, /version 4 of app into shop/);
  assert.match(text, /backup of the current data is taken first/);
  assert.match(text, /connections drop/);
});

test('prune previews name versions, give reasons and total the deletions', () => {
  const records = [rec({ id: 'A', version: 1 }), rec({ id: 'B', version: 2 })];
  const preview = { database: 'pg:app', local: { keep: [{ id: 'B', reason: 'newest' }], delete: ['A'] }, s3: { keep: [], delete: [] } };
  const rows = prunePlanRows(preview, 'local', records);
  assert.deepEqual(rows.keep, [{ id: 'B', name: 'v2', reason: 'newest complete version' }]);
  assert.deepEqual(rows.delete, [{ id: 'A', name: 'v1' }]);
  assert.equal(pruneSummary([preview]), 'Would delete 1 copy on the node.');
  assert.equal(pruneSummary([{ local: { delete: ['a', 'b'] }, s3: { delete: ['c'] } }]), 'Would delete 2 copies on the node and 1 copy in S3.');
  assert.equal(pruneSummary([]), 'Nothing would be deleted.');
  assert.deepEqual(prunePlanRows(null, 's3', []), { keep: [], delete: [] });
});

test('job polling slows down, and slows more while the tab is hidden', () => {
  assert.deepEqual([0, 1, 2, 3, 4, 9].map((n) => jobDelayMs(n)), [1000, 1000, 2000, 3000, 5000, 5000]);
  assert.equal(jobDelayMs(4, true), 15000);
  assert.equal(jobDelayMs(-1), 1000);
});

function fakeClock() {
  let t = 0;
  const waits = [];
  return { now: () => t, sleep: async (ms) => { waits.push(ms); t += ms; }, waits };
}

test('a job is polled until it is done and the waits grow', async () => {
  const clock = fakeClock();
  const states = ['running', 'running', 'running', 'ok'];
  const seen = [];
  const job = await pollJob({
    jobId: 'j1', get: async () => ({ id: 'j1', state: states.shift(), step: 'dump' }), sleep: clock.sleep, now: clock.now, onUpdate: (j) => seen.push(j.state),
  });
  assert.equal(job.state, 'ok');
  assert.deepEqual(clock.waits, [1000, 1000, 2000]);
  assert.equal(seen.length, 4);
});

test('a failed job rejects with the node message', async () => {
  const clock = fakeClock();
  await assert.rejects(
    pollJob({ jobId: 'j', get: async () => ({ state: 'failed', error: 'disk full' }), sleep: clock.sleep, now: clock.now }),
    /disk full/,
  );
});

test('a job the node no longer knows ends the poll', async () => {
  const clock = fakeClock();
  const gone = Object.assign(new Error('job not found'), { status: 404 });
  await assert.rejects(pollJob({ jobId: 'j', get: async () => { throw gone; }, sleep: clock.sleep, now: clock.now }), /no longer knows/);
});

test('a few failed reads are tolerated, many are not', async () => {
  const clock = fakeClock();
  let n = 0;
  const flaky = async () => {
    n += 1;
    if (n <= 2) throw new Error('network');
    return { state: 'ok' };
  };
  assert.equal((await pollJob({ jobId: 'j', get: flaky, sleep: clock.sleep, now: clock.now })).state, 'ok');
  const dead = fakeClock();
  let calls = 0;
  await assert.rejects(pollJob({ jobId: 'j', get: async () => { calls += 1; throw new Error('down'); }, sleep: dead.sleep, now: dead.now }), /down/);
  assert.equal(calls, 5);
});

test('polling stops when the panel is gone and when the job runs too long', async () => {
  const clock = fakeClock();
  let calls = 0;
  const out = await pollJob({
    jobId: 'j', get: async () => { calls += 1; return { state: 'running' }; }, sleep: clock.sleep, now: clock.now, alive: () => calls < 2,
  });
  assert.equal(out, null);
  const slow = fakeClock();
  await assert.rejects(
    pollJob({ jobId: 'j', get: async () => ({ state: 'running' }), sleep: slow.sleep, now: slow.now, maxMs: 10000 }),
    /still running/,
  );
  assert.ok(slow.waits.length < 20, 'it must not hammer the node');
});

test('health text is mapped to a pill colour', () => {
  assert.equal(healthKind('running (healthy)'), 'ok');
  assert.equal(healthKind('running (unhealthy)'), 'bad');
  assert.equal(healthKind('running (starting)'), 'warn');
  assert.equal(healthKind('missing'), 'bad');
  assert.equal(healthKind(''), 'muted');
  assert.equal(healthKind(null), 'muted');
});

test('the shared instance form maps to the node request', () => {
  const form = sharedToForm({ major: 17, memory_mb: 2048, nano_cpus: 1500000000, max_connections: 300 });
  assert.deepEqual(form, { major: '17', memoryMb: '2048', cpus: '1.5', maxConnections: '300' });
  assert.deepEqual(sharedBody(form, { creating: true }), { memory_mb: 2048, cpus: 1.5, max_connections: 300, major: 17 });
  assert.ok(!('major' in sharedBody(form, { creating: false })));
  assert.deepEqual(sharedToForm(null), { major: '18', memoryMb: '1024', cpus: '1', maxConnections: '200' });
  assert.equal(sharedProblem(form, { creating: true }), '');
  assert.notEqual(sharedProblem({ ...form, major: '16' }, { creating: true }), '');
  assert.equal(sharedProblem({ ...form, major: '16' }, { creating: false }), '');
  assert.notEqual(sharedProblem({ ...form, memoryMb: '100' }, { creating: false }), '');
  assert.notEqual(sharedProblem({ ...form, cpus: '0.1' }, { creating: false }), '');
  assert.notEqual(sharedProblem({ ...form, maxConnections: '1001' }, { creating: false }), '');
});

test('tenants are sorted and their database sizes summed', () => {
  const rows = tenantRows({ tenants: [
    { site: 'zed', databases: [{ name: 'app', size_bytes: 5 }] },
    { site: 'alpha', databases: [{ name: 'app', size_bytes: 10 }, { name: 'auth', size_bytes: 2 }] },
  ] });
  assert.deepEqual(rows.map((r) => [r.site, r.size]), [['alpha', 12], ['zed', 5]]);
  assert.deepEqual(tenantRows(null), []);
});

test('an orphan is described by what is left of it', () => {
  assert.equal(orphanText({ dedicated_volume: 'v', shared_databases: ['a', 'b'], backups: 1, secrets: 3 }), 'a dedicated database volume, 2 shared databases, 1 backup, 3 stored secrets');
  assert.equal(orphanText({}), 'nothing left');
});

test('the Data tab needs a data capability and a site that runs a server', () => {
  assert.equal(showsDataTab(pgInfo, nodeSite), true);
  assert.equal(showsDataTab({ capabilities: ['data-s3'] }, nodeSite), true);
  assert.equal(showsDataTab({ capabilities: ['data-backups'] }, nodeSite), false);
  assert.equal(showsDataTab({ capabilities: [] }, nodeSite), false);
  assert.equal(showsDataTab(null, nodeSite), false);
  assert.equal(showsDataTab(pgInfo, { source: null }), false);
  assert.equal(showsDataTab(pgInfo, { source: { runtime: 'static' } }), false);
  assert.equal(showsDataTab(pgInfo, { source: { runtime: 'node', rendering: 'static' } }), false);
  assert.equal(runsServer({ source: { repo: 'a/b' } }), true);
  assert.equal(dataFeatures(pgInfo).backups, true);
  assert.equal(dataFeatures(pgInfo).shared, false);
  assert.equal(showsDatabasesPage({ capabilities: ['data-shared'] }), true);
  assert.equal(showsDatabasesPage({ capabilities: ['site-logs'] }), false);
});

test('a job step is shown as the node reports it, or a plain word', () => {
  assert.equal(jobStepText({ step: 'dumping the database' }), 'dumping the database');
  assert.equal(jobStepText({ step: null }), 'working');
  assert.equal(jobStepText(null), 'working');
});

test('link rows are ordered by variable then target and read the env page target', () => {
  const rows = linkRows([
    { var: 'B', target: 'runtime' }, { var: 'A', target: 'runtime' }, { var: 'A', target: 'build' },
  ]);
  assert.deepEqual(rows.map((r) => `${r.var}:${r.target}`), ['A:build', 'A:runtime', 'B:runtime']);
  assert.deepEqual(linkRows(null), []);
  assert.equal(envTargetOf('build-env'), 'build');
  assert.equal(envTargetOf('runtime-env'), 'runtime');
});

test('user state and delete refusal reasons come from the listed fields', () => {
  assert.deepEqual(userState({ disabled: true }), { text: 'Disabled', kind: 'warn' });
  assert.deepEqual(userState({ retiring: 'a' }), { text: 'Rotating', kind: 'info' });
  assert.deepEqual(userState({}), { text: 'Active', kind: 'ok' });
  assert.match(deleteBlockedReason({ linked_by: ['DATABASE_URL'] }), /Linked by DATABASE_URL/);
  assert.equal(deleteBlockedReason({ linked_by: [] }), '');
  assert.equal(deleteBlockedReason({}), '');
  assert.equal(levelLabel('readwrite'), 'Read and write');
});

test('rotating an auth secret warns that users are signed out', () => {
  assert.match(rotateSecretText({ name: 'auth-secret' }), /signs every user out/);
  assert.match(rotateSecretText({ name: 'better-auth-secret' }), /signs every user out/);
  assert.doesNotMatch(rotateSecretText({ name: 'session-key' }), /signs every user out/);
});

const tview = (over) => ({
  id: 't1',
  plan: { source_node: 'a', target_node: 'b', site: 'shop', database: 'pg:app', freeze: 'maintenance' },
  phase: 'streaming', bytes_done: 50, bytes_total: 200, counts_match: null, mismatches: [], error: null, updated_at: '2026-11-20T10:00:00Z', running: true, awaiting_operator: false, ...over,
});

test('only maintenance and read only are offered while a database is moved', () => {
  assert.deepEqual(FREEZE_OPTIONS.map((o) => o.value), ['maintenance', 'read_only']);
  assert.match(FREEZE_OPTIONS[0].text, /maintenance page/);
  assert.match(FREEZE_OPTIONS[1].text, /refuses writes/);
});

test('a transfer plan is checked and sent with the wire names', () => {
  const form = { source: 'a', target: 'b', site: 'shop', database: 'app', freeze: 'read_only', replace: true, overrideManual: false };
  assert.equal(transferProblem(form), '');
  assert.notEqual(transferProblem({ ...form, target: 'a' }), '');
  assert.notEqual(transferProblem({ ...form, target: '' }), '');
  assert.notEqual(transferProblem({ ...form, database: '' }), '');
  assert.notEqual(transferProblem({ ...form, freeze: 'none' }), '');
  assert.deepEqual(transferPlanBody(form), {
    source_node: 'a', target_node: 'b', site: 'shop', database: 'pg:app', freeze: 'read_only', override_manual: false, replace: true, auto_cutover: false,
  });
});

test('progress is a bounded percent of the bytes copied', () => {
  assert.equal(transferPercent(tview({})), 25);
  assert.equal(transferPercent(tview({ bytes_done: 500 })), 100);
  assert.equal(transferPercent(tview({ bytes_total: 0 })), 0);
  assert.equal(transferPercent(tview({ bytes_total: 0, phase: 'done' })), 100);
  assert.equal(phaseLabel('rolled_back'), 'Rolled back');
});

test('the buttons of a transfer follow its phase, run state and row counts', () => {
  assert.deepEqual(transferActions(tview({})), { cancel: true, resume: false, cutover: false, rollback: false });
  const failed = transferActions(tview({ phase: 'failed', running: false }));
  assert.deepEqual(failed, { cancel: false, resume: true, cutover: false, rollback: true });
  const ready = transferActions(tview({ phase: 'verifying', running: false, awaiting_operator: true, counts_match: true }));
  assert.deepEqual(ready, { cancel: false, resume: false, cutover: true, rollback: true });
  const differ = transferActions(tview({ phase: 'verifying', running: false, awaiting_operator: true, counts_match: false }));
  assert.deepEqual(differ, { cancel: false, resume: false, cutover: false, rollback: true });
  assert.equal(transferActions(tview({ phase: 'cutover', running: false })).cutover, true);
  assert.deepEqual(transferActions(tview({ phase: 'done', running: false })), { cancel: false, resume: false, cutover: false, rollback: false });
});

test('mismatches name the tables and say which side lacks one', () => {
  const view = tview({ counts_match: false, mismatches: [{ schema: 'public', table: 'users', source: 10, target: 9 }, { schema: 'public', table: 'logs', source: 3, target: null }] });
  assert.deepEqual(mismatchRows(view), [
    { table: 'public.users', source: '10', target: '9' }, { table: 'public.logs', source: '3', target: 'missing' },
  ]);
  assert.match(verifyText(view), /2 tables have a different row count/);
  assert.match(verifyText(tview({ counts_match: true })), /safe to cut over/);
  assert.equal(verifyText(tview({})), '');
});

test('transfers are listed for one site, open ones first, and polling stops when none runs', () => {
  const list = [
    tview({ id: 'old', phase: 'done', running: false, updated_at: '2026-11-19T00:00:00Z' }),
    tview({ id: 'live', updated_at: '2026-11-18T00:00:00Z' }),
    tview({ id: 'other', plan: { source_node: 'a', target_node: 'b', site: 'blog', database: 'pg:app' } }),
    tview({ id: 'elsewhere', plan: { source_node: 'x', target_node: 'y', site: 'shop', database: 'pg:app' } }),
  ];
  assert.deepEqual(transfersOfSite(list, 'shop', 'a').map((t) => t.id), ['live', 'old']);
  assert.equal(transferSettled(tview({ running: false })), true);
  assert.equal(transferSettled(tview({})), false);
  assert.equal(anyRunning(list), true);
  assert.equal(anyRunning([tview({ running: false })]), false);
});

test('the Databases page shows open transfers and only the last week of finished ones', () => {
  const now = Date.parse('2026-11-20T00:00:00Z');
  const rows = transferRows([
    tview({ id: 'ancient', phase: 'done', running: false, updated_at: '2026-10-01T00:00:00Z' }),
    tview({ id: 'fresh', phase: 'done', running: false, updated_at: '2026-11-19T00:00:00Z' }),
    tview({ id: 'stuck', phase: 'failed', running: false, updated_at: '2026-10-01T00:00:00Z', error: 'boom' }),
  ], now);
  assert.deepEqual(rows.map((r) => r.id), ['stuck', 'fresh']);
  assert.equal(rows[0].error, 'boom');
  assert.equal(rows[1].database, 'app');
  assert.equal(rows[1].percent, 25);
});

test('a conversion settles when it needs a decision or ends, and the buttons follow', () => {
  assert.equal(convertSettled({ state: 'dumping' }), false);
  for (const s of ['awaiting_cutover', 'done', 'failed', 'rolled_back']) assert.equal(convertSettled({ state: s }), true, s);
  assert.deepEqual(convertActions({ state: 'awaiting_cutover' }), { cutover: true, abort: true });
  assert.deepEqual(convertActions({ state: 'dumping' }), { cutover: false, abort: true });
  assert.deepEqual(convertActions({ state: 'failed' }), { cutover: false, abort: true });
  assert.deepEqual(convertActions({ state: 'done' }), { cutover: false, abort: false });
  assert.equal(convertTarget({ mode: 'dedicated' }), 'shared');
  assert.equal(convertTarget({ mode: 'shared' }), 'dedicated');
});

test('node sessions that no console transfer owns are listed on their own', () => {
  const sessions = [
    { id: 'e1', kind: 'export', state: 'ready', database: 'pg:app', updated_at: '2026-11-20T10:00:00Z' },
    { id: 'i1', kind: 'import', state: 'receiving', database: 'pg:auth', updated_at: '2026-11-20T10:01:00Z' },
    { id: 'e2', kind: 'export', state: 'dumping', database: 'pg:app', updated_at: '2026-11-20T10:02:00Z' },
  ];
  const transfers = [tview({ export_id: 'e1', import_id: null }), tview({ id: 't2', export_id: null, import_id: 'x9' })];
  const rows = unmanagedSessions(sessions, transfers);
  assert.deepEqual(rows.map((r) => r.id), ['i1', 'e2']);
  assert.deepEqual(rows[0], { id: 'i1', kind: 'Import', database: 'auth', state: 'Receiving data', updatedAt: '2026-11-20T10:01:00Z' });
  assert.equal(rows[1].state, 'Dumping');
  assert.deepEqual(unmanagedSessions(undefined, transfers), []);
  assert.equal(unmanagedSessions(sessions, undefined).length, 3);
});

test('pollUntil stops when settled, when gone, and after repeated failures', async () => {
  const clock = fakeClock();
  const values = [{ n: 1 }, { n: 2 }, { n: 3, done: true }];
  const out = await pollUntil({ get: async () => values.shift(), finished: (v) => v.done, sleep: clock.sleep, now: clock.now });
  assert.equal(out.n, 3);
  assert.deepEqual(clock.waits, [1000, 1000]);
  const gone = fakeClock();
  assert.equal(await pollUntil({ get: async () => ({}), finished: () => false, sleep: gone.sleep, now: gone.now, alive: () => false }), null);
  const dead = fakeClock();
  let calls = 0;
  await assert.rejects(pollUntil({ get: async () => { calls += 1; throw new Error('down'); }, finished: () => true, sleep: dead.sleep, now: dead.now }), /down/);
  assert.equal(calls, 5);
  const missing = fakeClock();
  await assert.rejects(pollUntil({ get: async () => { throw Object.assign(new Error('nope'), { status: 404 }); }, finished: () => true, sleep: missing.sleep, now: missing.now }), /nope/);
});
