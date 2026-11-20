// Pure helpers for the site Data tab and the node Databases page: wording, validation, request bodies, link and preset planning,
// retention text and job polling. No DOM here, so every rule can be tested with node --test.

import { hasFeature } from './caplib.js';

export const DEFAULT_MAJOR = 18;
export const PG_MAJORS = [18, 17];
export const MIN_SECRET_BYTES = 32;
export const MAX_SECRET_BYTES = 128;
export const MIN_SHARED_MEMORY_MB = 256;
export const MAX_SHARED_MEMORY_MB = 65536;
export const MAX_LABEL_CHARS = 100;
export const BACKUP_EVERY_HOURS = [1, 2, 3, 4, 6, 8, 12, 24];

export const WRITE_ONLY_PASSWORDS = 'Passwords are never shown. Linked env vars deliver them where they are used, and Rotate password issues a new one.';
export const WRITE_ONLY_CREDENTIALS = 'Write-only: the node stores it and never sends it back. Saving again replaces it.';
export const EXTERNAL_EGRESS_NOTE = 'External databases are reached through the node egress forward: the site runs on a filtered network and its connection goes through a TCP forward that still refuses private and internal addresses. With sslmode verify-full the host name check fails through the forward, so link the TLS server name where your driver accepts one.';
export const EXTERNAL_BACKUP_NOTE = 'External databases can be backed up by hand only. A version can be restored into a managed database, never back into the external one.';
export const KEY_BACKUP_NOTE = 'Backups are encrypted with the node key. A copy in S3 cannot be restored without it: export the key and keep it somewhere else.';

// ---- Postgres mode and the trade-off table ----

export const PG_MODES = [
  { value: 'dedicated', label: 'Dedicated database', summary: 'Its own Postgres container, volume and network for this site.' },
  { value: 'shared', label: 'Shared node database', summary: 'A database and roles on the one Postgres instance of the node.' },
];

export const TRADEOFFS = [
  { aspect: 'Isolation', dedicated: 'Own process, own volume, own network.', shared: 'Separate database and roles, but the same process, volume and network rules per site.' },
  { aspect: 'Noisy neighbour', dedicated: 'None.', shared: 'CPU, memory, I/O and connection slots are shared with every tenant.' },
  { aspect: 'Postgres major', dedicated: 'Chosen per site.', shared: 'One for all tenants; upgrading means moving every tenant.' },
  { aspect: 'Blast radius', dedicated: 'This site only.', shared: 'An instance crash or a full disk affects every tenant.' },
  { aspect: 'Resources', dedicated: 'About 30 to 60 MiB of idle memory per site plus its own shared buffers.', shared: 'One process, much cheaper with many small sites.' },
  { aspect: 'Restart', dedicated: 'Per site.', shared: 'An instance restart interrupts every tenant.' },
  { aspect: 'Backups', dedicated: 'Per database.', shared: 'Per database, plus an optional whole-instance backup.' },
];

export function modeLabel(mode) {
  const found = PG_MODES.find((m) => m.value === mode);
  return found ? found.label : String(mode || 'unknown');
}

export function majorProblem(major) {
  return PG_MAJORS.includes(Number(major)) ? '' : `Pick Postgres ${PG_MAJORS.join(' or ')}.`;
}

// ---- Privilege levels ----

export const LEVELS = [
  { value: 'owner', label: 'Owner', text: 'Owns every object and can change the schema. Use it for migrations, not for the running app.' },
  { value: 'readwrite', label: 'Read and write', text: 'Reads and changes data, cannot change the schema. The right level for the running app.' },
  { value: 'readonly', label: 'Read only', text: 'Reads data only. For reports and analytics.' },
];

export function levelLabel(level) {
  const found = LEVELS.find((l) => l.value === level);
  return found ? found.label : String(level || 'unknown');
}

export function levelText(level) {
  const found = LEVELS.find((l) => l.value === level);
  return found ? found.text : '';
}

// ---- Names and numbers ----

const PG_NAME = /^[a-z][a-z0-9]{0,15}$/;
const RESOURCE_NAME = /^[a-z][a-z0-9-]{0,30}$/;
const RESERVED_DATABASES = ['postgres', 'template0', 'template1'];

export function pgNameProblem(name, what = 'name') {
  const v = String(name ?? '');
  if (!PG_NAME.test(v)) return `A ${what} is 1 to 16 characters: lowercase letters and digits, starting with a letter.`;
  if (what === 'database' && RESERVED_DATABASES.includes(v)) return `${v} is reserved by Postgres.`;
  return '';
}

export function resourceNameProblem(name, what = 'name') {
  const v = String(name ?? '');
  if (!RESOURCE_NAME.test(v)) return `A ${what} is 1 to 31 characters: lowercase letters, digits and dashes, starting with a letter.`;
  return '';
}

// A whole number inside [min, max]; blank is allowed only when optional
export function wholeNumberProblem(text, { min, max, what, optional = false }) {
  const v = String(text ?? '').trim();
  if (!v) return optional ? '' : `Enter ${what}.`;
  if (!/^\d+$/.test(v)) return `${what[0].toUpperCase()}${what.slice(1)} must be a whole number.`;
  const n = Number(v);
  if (n < min || n > max) return `${what[0].toUpperCase()}${what.slice(1)} must be between ${min} and ${max}.`;
  return '';
}

export function optionalNumber(text) {
  const v = String(text ?? '').trim();
  return v === '' ? undefined : Number(v);
}

export function secretBytesProblem(text) {
  return wholeNumberProblem(text, { min: MIN_SECRET_BYTES, max: MAX_SECRET_BYTES, what: 'the size in bytes' });
}

export function labelProblem(label) {
  const v = String(label ?? '');
  if ([...v].length > MAX_LABEL_CHARS) return `A label is at most ${MAX_LABEL_CHARS} characters.`;
  if ([...v].some((c) => c.charCodeAt(0) < 0x20 || c.charCodeAt(0) === 0x7f)) return 'A label cannot contain control characters.';
  return '';
}

// ---- Users ----

export function userCreateBody(form) {
  const body = { name: String(form.name || '').trim(), level: form.level };
  const limit = optionalNumber(form.connectionLimit);
  if (limit !== undefined) body.connection_limit = limit;
  const stmt = optionalNumber(form.statementTimeoutMs);
  if (stmt !== undefined) body.statement_timeout_ms = stmt;
  const idle = optionalNumber(form.idleTimeoutMs);
  if (idle !== undefined) body.idle_in_transaction_timeout_ms = idle;
  return body;
}

export function userFormProblem(form, { existing = [], creating = true } = {}) {
  if (creating) {
    const bad = pgNameProblem(form.name, 'user name');
    if (bad) return bad;
    if (existing.includes(String(form.name).trim())) return `${String(form.name).trim()} already exists in this database.`;
    if (!LEVELS.some((l) => l.value === form.level)) return 'Pick a level.';
  }
  return wholeNumberProblem(form.connectionLimit, { min: 1, max: 500, what: 'the connection limit', optional: true })
    || wholeNumberProblem(form.statementTimeoutMs, { min: 0, max: 3600000, what: 'the statement timeout', optional: true })
    || wholeNumberProblem(form.idleTimeoutMs, { min: 1000, max: 3600000, what: 'the idle in transaction timeout', optional: true });
}

// Only what differs from the user as listed is sent
export function userPatchBody(user, form) {
  const body = {};
  if (form.level && form.level !== user.level) body.level = form.level;
  const limit = optionalNumber(form.connectionLimit);
  if (limit !== undefined && limit !== user.connection_limit) body.connection_limit = limit;
  const stmt = optionalNumber(form.statementTimeoutMs);
  if (stmt !== undefined && stmt !== user.statement_timeout_ms) body.statement_timeout_ms = stmt;
  const idle = optionalNumber(form.idleTimeoutMs);
  if (idle !== undefined && idle !== user.idle_in_transaction_timeout_ms) body.idle_in_transaction_timeout_ms = idle;
  return body;
}

export function userState(user) {
  if (user.disabled) return { text: 'Disabled', kind: 'warn' };
  if (user.retiring) return { text: 'Rotating', kind: 'info' };
  return { text: 'Active', kind: 'ok' };
}

export function linkedByText(list) {
  const names = Array.isArray(list) ? list : [];
  return names.length ? names.join(', ') : '';
}

export function deleteBlockedReason(resource) {
  const by = Array.isArray(resource && resource.linked_by) ? resource.linked_by : [];
  return by.length ? `Linked by ${by.join(', ')}. Remove those links first.` : '';
}

export const ROTATE_TEXT = 'A new password is issued on the spare login while the current one keeps working, so running connections are not cut. Linked runtime env vars pick it up on the next deploy, and the old login is retired once nothing uses it.';

// ---- Env links ----

export const LINK_TARGETS = [
  { value: 'runtime', label: 'Runtime' },
  { value: 'build', label: 'Build' },
  { value: 'both', label: 'Both' },
];

export const PG_FIELDS = ['url', 'host', 'port', 'database', 'user', 'password', 'sslmode'];
export const EXTERNAL_FIELDS = [...PG_FIELDS, 'tls_servername'];
export const S3_FIELDS = ['endpoint', 'bucket', 'region', 'access_key_id', 'secret_access_key', 'path_style'];

export const SOURCE_KINDS = [
  { value: 'postgres', label: 'Managed Postgres' },
  { value: 'external', label: 'External Postgres' },
  { value: 's3', label: 'S3 attachment' },
  { value: 'secret', label: 'Generated secret' },
  { value: 'site_url', label: 'Site URL' },
];

export function fieldsFor(kind) {
  if (kind === 'postgres') return PG_FIELDS;
  if (kind === 'external') return EXTERNAL_FIELDS;
  if (kind === 's3') return S3_FIELDS;
  return [];
}

export function sourceLabel(source) {
  if (!source || typeof source !== 'object') return 'unknown';
  switch (source.kind) {
    case 'postgres': return `postgres ${source.database}/${source.user} ${source.field}`;
    case 'external': return `external ${source.name} ${source.field}`;
    case 's3': return `s3 ${source.name} ${source.field}`;
    case 'secret': return `secret ${source.name}`;
    case 'site_url': return 'site URL';
    default: return 'unknown';
  }
}

export function sameSource(a, b) {
  return JSON.stringify(canonicalSource(a)) === JSON.stringify(canonicalSource(b));
}

function canonicalSource(s) {
  if (!s) return null;
  const { kind, database, user, field, name } = s;
  return [kind, database ?? null, user ?? null, field ?? null, name ?? null];
}

// The node supplies the label; the text built here is only the fallback for an answer without one
export function linkLabel(link) {
  return link && link.label ? link.label : sourceLabel(link && link.source);
}

export function linkedFromText(link) {
  return `linked from ${linkLabel(link)}`;
}

export function targetLabel(target) {
  if (target === 'both') return 'Runtime and build';
  return target === 'build' ? 'Build' : 'Runtime';
}

export function targetsOf(sel) {
  if (sel === 'both') return ['runtime', 'build'];
  return sel === 'build' ? ['build'] : ['runtime'];
}

// Rows for the links table, one per var and target, in a stable order
export function linkRows(links) {
  return [...(Array.isArray(links) ? links : [])].sort((a, b) => (a.var === b.var ? a.target.localeCompare(b.target) : a.var.localeCompare(b.var)));
}

// var -> link for one target, for the Build tab's read-only rows
export function linksForTarget(links, target) {
  const map = new Map();
  for (const l of Array.isArray(links) ? links : []) if (l.target === target) map.set(l.var, l);
  return map;
}

export function envTargetOf(which) {
  return which === 'build-env' ? 'build' : 'runtime';
}

export function sourceFromDraft(draft) {
  switch (draft.kind) {
    case 'postgres': return { kind: 'postgres', database: draft.database, user: draft.user, field: draft.field };
    case 'external': return { kind: 'external', name: draft.name, field: draft.field };
    case 's3': return { kind: 's3', name: draft.name, field: draft.field };
    case 'secret': return { kind: 'secret', name: draft.name };
    default: return { kind: 'site_url' };
  }
}

// A name for the var that matches common conventions
export function suggestedVar(source) {
  if (!source) return '';
  if (source.kind === 'secret') return source.name.toUpperCase().replace(/-/g, '_');
  if (source.kind === 'site_url') return 'SITE_URL';
  if (source.kind === 's3') return `S3_${String(source.field).toUpperCase()}`;
  if (source.field === 'url') return source.kind === 'external' ? `${String(source.name).toUpperCase().replace(/-/g, '_')}_URL` : 'DATABASE_URL';
  return `PG${String(source.field).toUpperCase()}`;
}

const VAR_NAME = /^[A-Z_][A-Z0-9_]{0,63}$/;

export function linkDraftProblem(draft, data) {
  if (!VAR_NAME.test(String(draft.var || '').trim())) return 'Use capital letters, digits and underscores for the variable name, up to 64 characters.';
  if (!['runtime', 'build', 'both'].includes(draft.target)) return 'Pick runtime, build or both.';
  const src = draft.kind;
  if (src === 'postgres') {
    if (!draft.database) return 'Pick a database.';
    if (!draft.user) return 'Pick a user.';
    if (!PG_FIELDS.includes(draft.field)) return 'Pick a field.';
  } else if (src === 'external') {
    if (!draft.name) return 'Pick an external database.';
    if (!EXTERNAL_FIELDS.includes(draft.field)) return 'Pick a field.';
  } else if (src === 's3') {
    if (!draft.name) return 'Pick an S3 attachment.';
    if (!S3_FIELDS.includes(draft.field)) return 'Pick a field.';
  } else if (src === 'secret') {
    if (!draft.name) return 'Pick a generated secret.';
  } else if (src !== 'site_url') {
    return 'Pick what to link.';
  }
  const links = (data && data.links) || [];
  const want = sourceFromDraft(draft);
  for (const t of targetsOf(draft.target)) {
    const clash = links.find((l) => l.var === draft.var.trim() && l.target === t);
    if (clash && !sameSource(clash.source, want)) return `${draft.var.trim()} (${t}) is already linked from ${linkLabel(clash)}. Remove that link first.`;
  }
  return '';
}

export function linkRequest(draft) {
  return { var: draft.var.trim(), target: draft.target, source: sourceFromDraft(draft) };
}

// 409 body of POST links: { error, conflicts: [{ var, target, set_by }] }. ApiError may carry the parsed body as data or body.
export function conflictsFromError(err) {
  if (!err || err.status !== 409) return null;
  const body = err.data || err.body || null;
  const list = body && Array.isArray(body.conflicts) ? body.conflicts : null;
  if (!list || !list.length) return null;
  return list.filter((c) => c && typeof c.var === 'string').map((c) => ({ var: c.var, target: c.target, set_by: c.set_by }));
}

// Which requested vars already exist as manual vars; names are what GET build-env and runtime-env list
export function manualConflicts(requested, manualNames, links) {
  const out = [];
  const linked = new Set((links || []).map((l) => `${l.target}:${l.var}`));
  for (const r of requested) {
    for (const t of targetsOf(r.target)) {
      if (linked.has(`${t}:${r.var}`)) continue;
      const names = manualNames && manualNames[t];
      if (names && names.includes(r.var)) out.push({ var: r.var, target: t, set_by: 'manual' });
    }
  }
  return out;
}

export function conflictLines(conflicts) {
  return (conflicts || []).map((c) => `${c.var} (${c.target}) is set ${c.set_by === 'link' ? 'by another link' : 'by hand'}`);
}

export function conflictSummary(conflicts) {
  const manual = (conflicts || []).filter((c) => c.set_by !== 'link');
  const links = (conflicts || []).filter((c) => c.set_by === 'link');
  const parts = [];
  if (manual.length) parts.push(`Override deletes the manual value of ${manual.map((c) => `${c.var} (${c.target})`).join(', ')}.`);
  if (links.length) parts.push(`${links.map((c) => `${c.var} (${c.target})`).join(', ')} already linked elsewhere; remove that link first, override does not replace links.`);
  return parts.join(' ');
}

export function canOverride(conflicts) {
  return Boolean(conflicts && conflicts.length) && conflicts.every((c) => c.set_by === 'manual');
}

// ---- Presets ----

export const PRESETS = [
  { id: 'generic', label: 'Generic', summary: 'DATABASE_URL and the PG* variables at runtime, MIGRATION_DATABASE_URL for the build.' },
  { id: 'prisma', label: 'Prisma', summary: 'DATABASE_URL at runtime, DATABASE_URL and DIRECT_URL for the build.' },
  { id: 'drizzle', label: 'Drizzle', summary: 'DATABASE_URL at runtime and for the build.' },
  { id: 'authjs', label: 'Auth.js', summary: 'AUTH_SECRET, plus a separate auth database with its own runtime and migration URLs.' },
  { id: 'better-auth', label: 'Better Auth', summary: 'BETTER_AUTH_SECRET, BETTER_AUTH_URL and DATABASE_URL.' },
];

export const PRESET_DEFAULTS = { database: 'app', runtimeUser: 'app', migrateUser: 'migrate', authDatabase: 'auth' };

const pgSource = (database, user, field) => ({ kind: 'postgres', database, user, field });

// Mirrors the node's preset table: what each preset needs and links
export function presetSpec(id, opts = {}) {
  const o = { ...PRESET_DEFAULTS, ...opts };
  const rt = 'runtime';
  const bd = 'build';
  const main = [[o.database, o.runtimeUser, 'readwrite'], [o.database, o.migrateUser, 'owner']];
  switch (id) {
    case 'generic':
      return {
        users: main,
        secrets: [],
        links: [
          ...['url:DATABASE_URL', 'host:PGHOST', 'port:PGPORT', 'database:PGDATABASE', 'user:PGUSER', 'password:PGPASSWORD', 'sslmode:PGSSLMODE'].map((p) => {
            const [field, name] = p.split(':');
            return { var: name, target: rt, source: pgSource(o.database, o.runtimeUser, field) };
          }),
          { var: 'MIGRATION_DATABASE_URL', target: bd, source: pgSource(o.database, o.migrateUser, 'url') },
        ],
      };
    case 'prisma':
      return {
        users: main,
        secrets: [],
        links: [
          { var: 'DATABASE_URL', target: rt, source: pgSource(o.database, o.runtimeUser, 'url') },
          { var: 'DATABASE_URL', target: bd, source: pgSource(o.database, o.migrateUser, 'url') },
          { var: 'DIRECT_URL', target: bd, source: pgSource(o.database, o.migrateUser, 'url') },
        ],
      };
    case 'drizzle':
      return {
        users: main,
        secrets: [],
        links: [
          { var: 'DATABASE_URL', target: rt, source: pgSource(o.database, o.runtimeUser, 'url') },
          { var: 'DATABASE_URL', target: bd, source: pgSource(o.database, o.migrateUser, 'url') },
        ],
      };
    case 'authjs':
      return {
        users: [[o.authDatabase, o.runtimeUser, 'readwrite'], [o.authDatabase, o.migrateUser, 'owner']],
        secrets: ['auth-secret'],
        links: [
          { var: 'AUTH_SECRET', target: rt, source: { kind: 'secret', name: 'auth-secret' } },
          { var: 'AUTH_DATABASE_URL', target: rt, source: pgSource(o.authDatabase, o.runtimeUser, 'url') },
          { var: 'AUTH_MIGRATION_DATABASE_URL', target: bd, source: pgSource(o.authDatabase, o.migrateUser, 'url') },
        ],
      };
    case 'better-auth':
      return {
        users: main,
        secrets: ['better-auth-secret'],
        links: [
          { var: 'BETTER_AUTH_SECRET', target: rt, source: { kind: 'secret', name: 'better-auth-secret' } },
          { var: 'BETTER_AUTH_URL', target: rt, source: { kind: 'site_url' } },
          { var: 'DATABASE_URL', target: rt, source: pgSource(o.database, o.runtimeUser, 'url') },
          { var: 'DATABASE_URL', target: bd, source: pgSource(o.database, o.migrateUser, 'url') },
        ],
      };
    default:
      return null;
  }
}

export function presetOptionsProblem(id, opts = {}) {
  const o = { ...PRESET_DEFAULTS, ...opts };
  const bad = pgNameProblem(o.database, 'database') || pgNameProblem(o.runtimeUser, 'user name') || pgNameProblem(o.migrateUser, 'user name')
    || (id === 'authjs' ? pgNameProblem(o.authDatabase, 'database') : '');
  if (bad) return bad;
  if (o.runtimeUser === o.migrateUser) return 'The runtime user and the migrate user must differ.';
  return '';
}

// What applying a preset would do to the site as it is now. data is the SiteDataView; manualNames is { runtime, build } name lists.
export function presetPreview(id, opts, data, manualNames) {
  const spec = presetSpec(id, opts);
  if (!spec) return { problem: 'Unknown preset.', links: [], users: [], databases: [], secrets: [], conflicts: [], needsOverride: false };
  const pg = data && data.postgres;
  const problems = [];
  const databases = [];
  const users = [];
  for (const [database, user, level] of spec.users) {
    const db = pg && (pg.databases || []).find((d) => d.name === database);
    if (!db && !databases.includes(database)) databases.push(database);
    const existing = db && (db.users || []).find((u) => u.name === user);
    if (existing) {
      if (existing.level !== level) problems.push(`User ${database}/${user} is ${levelLabel(existing.level).toLowerCase()} but this preset needs ${levelLabel(level).toLowerCase()}.`);
      continue;
    }
    users.push({ database, user, level });
  }
  const secrets = spec.secrets.filter((n) => !((data && data.secrets) || []).some((s) => s.name === n));
  const existingLinks = (data && data.links) || [];
  const links = [];
  for (const l of spec.links) {
    const same = existingLinks.find((e) => e.var === l.var && e.target === l.target);
    if (same && sameSource(same.source, l.source)) {
      links.push({ ...l, state: 'exists' });
    } else if (same) {
      problems.push(`${l.var} (${l.target}) is already linked from ${linkLabel(same)}. Remove that link first.`);
      links.push({ ...l, state: 'blocked' });
    } else {
      links.push({ ...l, state: 'new' });
    }
  }
  const conflicts = manualConflicts(links.filter((l) => l.state === 'new'), manualNames, existingLinks);
  return {
    problem: problems[0] || '', links, users, databases, secrets, conflicts, needsOverride: conflicts.length > 0,
  };
}

export function presetBody(id, opts, overrideManual) {
  const o = { ...PRESET_DEFAULTS, ...opts };
  const body = { preset: id, database: o.database, runtime_user: o.runtimeUser, migrate_user: o.migrateUser };
  if (id === 'authjs') body.auth_database = o.authDatabase;
  if (overrideManual) body.override_manual = true;
  return body;
}

// ---- Generated secrets ----

export const SECRET_ENCODINGS = [
  { value: 'base64url', label: 'base64url' },
  { value: 'hex', label: 'hex' },
];

export const AUTH_ROTATE_WARNING = 'Rotating an auth secret signs every user out, because sessions signed with the old value stop validating.';

export function isAuthSecret(name) {
  return /auth/i.test(String(name || ''));
}

export function rotateSecretText(secret) {
  const base = `Replace the value of ${secret.name}. The previous value stops working once a deploy picks the new one up.`;
  return isAuthSecret(secret.name) ? `${base} ${AUTH_ROTATE_WARNING}` : base;
}

export function secretCreateBody(form) {
  const body = { name: String(form.name || '').trim() };
  const bytes = optionalNumber(form.bytes);
  if (bytes !== undefined) body.bytes = bytes;
  if (form.encoding) body.encoding = form.encoding;
  return body;
}

// ---- External Postgres and S3 attachments ----

export function externalUrlProblem(text, { required = true } = {}) {
  const v = String(text ?? '').trim();
  if (!v) return required ? 'Enter the connection URL.' : '';
  if (v.length > 2048) return 'The URL is longer than 2048 characters.';
  if (!/^postgres(ql)?:\/\//i.test(v)) return 'The URL must start with postgres:// or postgresql://.';
  let url;
  try {
    url = new URL(v);
  } catch (ex) {
    return 'That is not a valid URL.';
  }
  if (!url.hostname || v.includes(',')) return 'Give exactly one host.';
  if (!url.username) return 'Include the user name in the URL, as postgres://user:password@host/database.';
  if (url.pathname.length <= 1) return 'Include the database name at the end of the URL.';
  return '';
}

export function s3Problem(form, { hasKeys = false } = {}) {
  const name = resourceNameProblem(form.name, 'attachment name');
  if (name) return name;
  let url;
  try {
    url = new URL(String(form.endpoint || '').trim());
  } catch (ex) {
    return 'Enter the endpoint as a full URL, for example https://s3.eu-west-1.amazonaws.com.';
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return 'The endpoint must be an http or https URL.';
  if (!String(form.bucket || '').trim()) return 'Enter the bucket.';
  if (!String(form.region || '').trim()) return 'Enter the region.';
  const hasId = Boolean(String(form.accessKeyId || '').trim());
  const hasSecret = Boolean(form.secretAccessKey);
  if (!hasKeys && !(hasId && hasSecret)) return 'Enter both the access key id and the secret access key.';
  if (hasKeys && hasId !== hasSecret) return 'Enter both keys, or neither to keep the stored ones.';
  return '';
}

export function s3Body(form) {
  const body = {
    endpoint: String(form.endpoint).trim(), bucket: String(form.bucket).trim(), region: String(form.region).trim(), path_style: Boolean(form.pathStyle),
  };
  if (String(form.accessKeyId || '').trim()) body.access_key_id = String(form.accessKeyId).trim();
  if (form.secretAccessKey) body.secret_access_key = form.secretAccessKey;
  return body;
}

// ---- Backups ----

export const TRIGGER_LABELS = {
  manual: 'Manual', scheduled: 'Scheduled', pre_restore: 'Before restore', transfer: 'Transfer', import: 'Import',
};

export function triggerLabel(trigger) {
  return TRIGGER_LABELS[trigger] || String(trigger || '');
}

export function statusKind(status) {
  if (status === 'ok') return 'ok';
  if (status === 'failed') return 'bad';
  return 'info';
}

export function statusText(status) {
  if (status === 'ok') return 'Complete';
  if (status === 'failed') return 'Failed';
  return 'Running';
}

export function shortSha(sha) {
  const v = String(sha || '');
  return v ? v.slice(0, 8) : '-';
}

export function databaseKey(name) {
  return `pg:${name}`;
}

export function databaseName(key) {
  return String(key || '').replace(/^(pg|ext):/, '');
}

export function isExternalKey(key) {
  return String(key || '').startsWith('ext:');
}

// Where a version's bytes are held
export function locations(rec) {
  const out = [];
  if (rec && rec.local) out.push('node');
  if (rec && rec.s3) out.push('s3');
  return out;
}

export function backupRows(records, key) {
  const list = (Array.isArray(records) ? records : []).filter((r) => !key || r.database === key);
  return list
    .map((r) => ({
      id: r.id,
      database: r.database,
      version: r.version,
      createdAt: r.created_at,
      trigger: r.trigger,
      triggerText: triggerLabel(r.trigger),
      label: r.label || '',
      pinned: Boolean(r.pinned),
      size: r.size_bytes || 0,
      sha: shortSha(r.sha256),
      status: r.status,
      statusText: statusText(r.status),
      statusKind: statusKind(r.status),
      error: r.error || '',
      locations: locations(r),
      raw: r,
    }))
    .sort((a, b) => (a.createdAt === b.createdAt ? b.version - a.version : (a.createdAt < b.createdAt ? 1 : -1)));
}

export function canDownload(rec) {
  return rec.status === 'ok' && rec.locations.length > 0;
}

export function canRestore(rec, { external = false } = {}) {
  return rec.status === 'ok' && rec.locations.length > 0 && !external;
}

export function canPush(rec, { hasTarget = false } = {}) {
  return rec.status === 'ok' && rec.locations.includes('node') && !rec.locations.includes('s3') && hasTarget;
}

// Pinned versions are refused by the node; the button says why before a request is made
export function deleteBackupBlock(rec) {
  if (rec.pinned) return 'Pinned versions cannot be deleted. Unpin it first.';
  if (rec.status === 'running') return 'This backup is still running.';
  return '';
}

export function restoreText(rec, site) {
  return `Restore version ${rec.version} of ${databaseName(rec.database)} into ${site}. A backup of the current data is taken first, as a Before restore version, then connections drop while the restore runs and the app sees errors until it finishes. A failed restore is rolled back.`;
}

export function deleteBackupText(rec) {
  const where = rec.locations.length === 2 ? 'the node and S3' : rec.locations[0] === 's3' ? 'S3' : 'the node';
  return `Delete version ${rec.version} from ${where}. This cannot be undone.`;
}

export function backupFileName(site, rec) {
  return `${site}-${databaseName(rec.database)}-v${rec.version}.dump`;
}

export function labelBody(text) {
  const v = String(text ?? '').trim();
  return { label: v === '' ? null : v };
}

// ---- Retention ----

export const RETENTION_LIMITS = {
  keep_all_hours: { min: 0, max: 720, label: 'Keep every backup for (hours)' },
  daily_days: { min: 0, max: 366, label: 'Keep one a day for (days)' },
  weekly_weeks: { min: 0, max: 260, label: 'Keep one a week for (weeks)' },
  monthly_months: { min: 0, max: 120, label: 'Keep one a month for (months)' },
  pre_restore_days: { min: 0, max: 366, label: 'Keep Before restore versions for (days)' },
};

export const RETENTION_DEFAULTS = {
  keep_all_hours: 24, daily_days: 7, weekly_weeks: 4, monthly_months: 6, pre_restore_days: 7,
};

export function retentionOf(r) {
  const out = { ...RETENTION_DEFAULTS };
  for (const key of Object.keys(RETENTION_DEFAULTS)) if (r && Number.isInteger(r[key])) out[key] = r[key];
  return out;
}

function plural(n, one, many) {
  return `${n} ${n === 1 ? one : many}`;
}

export function retentionText(r) {
  const v = retentionOf(r);
  const parts = [];
  if (v.keep_all_hours) parts.push(`every backup from the last ${plural(v.keep_all_hours, 'hour', 'hours')}`);
  if (v.daily_days) parts.push(`the newest of each day for ${plural(v.daily_days, 'day', 'days')}`);
  if (v.weekly_weeks) parts.push(`the newest of each week for ${plural(v.weekly_weeks, 'week', 'weeks')}`);
  if (v.monthly_months) parts.push(`the newest of each month for ${plural(v.monthly_months, 'month', 'months')}`);
  const base = parts.length ? `Keeps ${parts.join(', ')}.` : 'Keeps only the newest version.';
  return `${base} Pinned versions and the newest complete version are always kept.`;
}

export const BUCKET_EXPLANATION = 'Days, weeks and months are calendar buckets in UTC: each bucket keeps its newest version, and anything no rule keeps is deleted. Weeks start on Monday.';

export function retentionProblem(form) {
  for (const [key, lim] of Object.entries(RETENTION_LIMITS)) {
    const bad = wholeNumberProblem(form[key], { min: lim.min, max: lim.max, what: lim.label.replace(/ \(.*\)$/, '').toLowerCase() });
    if (bad) return `${lim.label}: ${bad}`;
  }
  return '';
}

export function retentionFromForm(form) {
  const out = {};
  for (const key of Object.keys(RETENTION_LIMITS)) out[key] = Number(String(form[key]).trim());
  return out;
}

export function retentionToForm(r) {
  const v = retentionOf(r);
  return Object.fromEntries(Object.entries(v).map(([k, n]) => [k, String(n)]));
}

export function scheduleText(s) {
  if (!s) return 'No scheduled backups.';
  const minute = String(s.minute ?? 0).padStart(2, '0');
  if (s.every_hours === 24) return `Every day at 00:${minute} UTC.`;
  return `Every ${s.every_hours === 1 ? 'hour' : `${s.every_hours} hours`} at minute ${minute}, on the hours that divide evenly (UTC).`;
}

export function scheduleProblem(form) {
  if (!form.scheduled) return '';
  if (!BACKUP_EVERY_HOURS.includes(Number(form.everyHours))) return `Pick one of ${BACKUP_EVERY_HOURS.join(', ')} hours.`;
  return wholeNumberProblem(form.minute, { min: 0, max: 59, what: 'the minute' });
}

// The editor's form from a stored BackupPolicy and back
export function policyToForm(policy) {
  const p = policy || {};
  return {
    scheduled: Boolean(p.schedule),
    everyHours: String(p.schedule ? p.schedule.every_hours : 24),
    minute: String(p.schedule ? p.schedule.minute : 17),
    local: retentionToForm(p.local),
    s3On: Boolean(p.s3),
    s3Target: p.s3 ? p.s3.target : '',
    s3: retentionToForm(p.s3 && p.s3.retention),
  };
}

export function policyProblem(form) {
  const sched = scheduleProblem(form);
  if (sched) return sched;
  const local = retentionProblem(form.local);
  if (local) return `Node copies: ${local}`;
  if (form.s3On) {
    if (!form.s3Target) return 'Pick a backup target for the S3 copies.';
    const s3 = retentionProblem(form.s3);
    if (s3) return `S3 copies: ${s3}`;
  }
  return '';
}

export function policyFromForm(form) {
  const out = { local: retentionFromForm(form.local) };
  if (form.scheduled) out.schedule = { every_hours: Number(form.everyHours), minute: Number(form.minute) };
  if (form.s3On) out.s3 = { target: form.s3Target, retention: retentionFromForm(form.s3) };
  return out;
}

export const KEEP_REASONS = {
  pinned: 'pinned',
  newest: 'newest complete version',
  recent: 'inside the keep-everything window',
  pre_restore: 'taken before a restore',
  daily: 'newest of its day',
  weekly: 'newest of its week',
  monthly: 'newest of its month',
};

export function keepReasonText(reason) {
  return KEEP_REASONS[reason] || String(reason || '');
}

// One PrunePreview per database: { database, local: { keep, delete }, s3: { keep, delete } }
export function prunePlanRows(preview, tier, records) {
  const plan = (preview && preview[tier]) || { keep: [], delete: [] };
  const byId = new Map((records || []).map((r) => [r.id, r]));
  const name = (id) => {
    const r = byId.get(id);
    return r ? `v${r.version}` : id;
  };
  return {
    keep: (plan.keep || []).map((k) => ({ id: k.id, name: name(k.id), reason: keepReasonText(k.reason) })),
    delete: (plan.delete || []).map((id) => ({ id, name: name(id) })),
  };
}

export function pruneTotal(previews, tier) {
  return (Array.isArray(previews) ? previews : []).reduce((n, p) => n + ((p[tier] && p[tier].delete) || []).length, 0);
}

export function pruneSummary(previews) {
  const local = pruneTotal(previews, 'local');
  const s3 = pruneTotal(previews, 's3');
  if (!local && !s3) return 'Nothing would be deleted.';
  const parts = [];
  if (local) parts.push(`${plural(local, 'copy', 'copies')} on the node`);
  if (s3) parts.push(`${plural(s3, 'copy', 'copies')} in S3`);
  return `Would delete ${parts.join(' and ')}.`;
}

// ---- Jobs ----

// Starts at one second, slows to five, and slows further while the tab is hidden
export function jobDelayMs(attempt, hidden = false) {
  const steps = [1000, 1000, 2000, 3000, 5000];
  const base = steps[Math.min(Math.max(attempt, 0), steps.length - 1)];
  return hidden ? base * 3 : base;
}

export const JOB_MAX_MS = 30 * 60 * 1000;
const JOB_MAX_FAILED_READS = 5;

// The step the node reports, or a plain word while it has not reported one yet
export function jobStepText(job) {
  return job && job.step ? String(job.step) : 'working';
}

// Reads a job until it is no longer running. get(jobId) returns the JobView; sleep(ms) and now() are injectable.
// Resolves with the finished job, throws when it failed, was lost or ran too long, resolves null when alive() turns false.
export async function pollJob({
  jobId, get, sleep, now = Date.now, onUpdate, alive = () => true, hidden = () => false, maxMs = JOB_MAX_MS,
}) {
  const started = now();
  let attempt = 0;
  let failures = 0;
  for (;;) {
    if (!alive()) return null;
    let job = null;
    try {
      job = await get(jobId);
      failures = 0;
    } catch (ex) {
      if (ex && ex.status === 404) throw new Error('The node no longer knows this job. It may have restarted; reload to see where things stand.');
      failures += 1;
      if (failures >= JOB_MAX_FAILED_READS) throw ex;
    }
    if (job) {
      if (onUpdate) onUpdate(job);
      if (job.state === 'ok') return job;
      if (job.state === 'failed') throw new Error(job.error || 'The job failed without a message.');
    }
    if (now() - started > maxMs) throw new Error('The job is still running after 30 minutes. It keeps going on the node; reload later to check.');
    await sleep(jobDelayMs(attempt, hidden()));
    attempt += 1;
  }
}

// ---- Polling of anything that settles ----

// Like pollJob for a state that is read until it settles. get() returns the state, finished(state) says when to stop.
// Resolves with the settled state, null when alive() turns false, throws after repeated failed reads or when it runs too long.
export async function pollUntil({
  get, finished, sleep, now = Date.now, onUpdate, alive = () => true, hidden = () => false, maxMs = JOB_MAX_MS,
}) {
  const started = now();
  let attempt = 0;
  let failures = 0;
  for (;;) {
    if (!alive()) return null;
    let value = null;
    try {
      value = await get();
      failures = 0;
    } catch (ex) {
      failures += 1;
      if (failures >= JOB_MAX_FAILED_READS || (ex && ex.status === 404)) throw ex;
    }
    if (value !== null) {
      if (onUpdate) onUpdate(value);
      if (finished(value)) return value;
    }
    if (now() - started > maxMs) throw new Error('Stopped watching after 30 minutes. Reload the page to check again.');
    await sleep(jobDelayMs(attempt, hidden()));
    attempt += 1;
  }
}

// ---- Node-to-node transfer ----

export const FREEZE_OPTIONS = [
  { value: 'maintenance', label: 'Maintenance page', text: 'The site serves the maintenance page during the final copy, so no write can be lost.' },
  { value: 'read_only', label: 'Read only', text: 'The site stays up but refuses writes while the final copy runs.' },
];

export const TRANSFER_SOURCE_NOTE = 'A transfer never deletes the source database. It stays on the source node, frozen, until you delete it yourself.';
export const LIVE_TRANSFER_NOTE = 'Near-zero-downtime transfer is planned for a later release.';

export function freezeText(value) {
  const found = FREEZE_OPTIONS.find((o) => o.value === value);
  return found ? found.text : '';
}

export const TRANSFER_PHASES = {
  pending: 'Waiting to start',
  freezing: 'Freezing the source',
  dumping: 'Dumping the source database',
  streaming: 'Copying to the target',
  restoring: 'Restoring on the target',
  verifying: 'Comparing row counts',
  cutover: 'Cutting over',
  done: 'Done',
  failed: 'Failed',
  rolled_back: 'Rolled back',
};

export function phaseLabel(phase) {
  return TRANSFER_PHASES[phase] || String(phase || '');
}

export function phaseKind(phase) {
  if (phase === 'done') return 'ok';
  if (phase === 'failed') return 'bad';
  if (phase === 'rolled_back' || phase === 'pending') return 'muted';
  return 'info';
}

export function transferFinished(view) {
  return Boolean(view) && (view.phase === 'done' || view.phase === 'rolled_back');
}

// Percent of the dump copied, 0 to 100; unknown until the size is known
export function transferPercent(view) {
  const total = Number(view && view.bytes_total) || 0;
  if (!total) return transferFinished(view) && view.phase === 'done' ? 100 : 0;
  return Math.max(0, Math.min(100, Math.floor(((Number(view.bytes_done) || 0) / total) * 100)));
}

// Polling stops once the server task is not running; an action that starts one again begins a new poll
export function transferSettled(view) {
  return !view || !view.running;
}

// What the operator can press for a transfer, from the view alone
export function transferActions(view) {
  const open = Boolean(view) && !transferFinished(view);
  const waiting = Boolean(view && view.awaiting_operator);
  const running = Boolean(view && view.running);
  return {
    cancel: open && running,
    resume: open && !running && !waiting,
    cutover: open && !running && (view.phase === 'cutover' || (waiting && view.counts_match === true)),
    rollback: open && !running,
  };
}

export function mismatchRows(view) {
  const text = (n) => (n === null || n === undefined ? 'missing' : String(n));
  return ((view && view.mismatches) || []).map((m) => ({
    table: `${m.schema}.${m.table}`, source: text(m.source), target: text(m.target),
  }));
}

export function verifyText(view) {
  if (!view || view.counts_match === null || view.counts_match === undefined) return '';
  if (view.counts_match) return 'Every table has the same number of rows on both nodes. It is safe to cut over.';
  const n = (view.mismatches || []).length;
  return `${n} ${n === 1 ? 'table has' : 'tables have'} a different row count on the target. Roll back, or resume to copy again.`;
}

export function transferTitle(view) {
  const plan = (view && view.plan) || {};
  return `${databaseName(plan.database)} of ${plan.site}: ${plan.source_node} to ${plan.target_node}`;
}

export function transferProblem(form) {
  if (!form.target) return 'Choose the node to move the database to.';
  if (form.target === form.source) return 'The target must be a different node.';
  if (!form.database) return 'Choose the database to move.';
  const bad = pgNameProblem(form.database, 'database');
  if (bad) return bad;
  if (!FREEZE_OPTIONS.some((o) => o.value === form.freeze)) return 'Choose how the site behaves during the final copy.';
  return '';
}

export function transferPlanBody(form) {
  return {
    source_node: form.source,
    target_node: form.target,
    site: form.site,
    database: databaseKey(form.database),
    freeze: form.freeze,
    override_manual: Boolean(form.overrideManual),
    replace: Boolean(form.replace),
    auto_cutover: false,
  };
}

// Transfers of one site that touch this node, running first and then newest
export function transfersOfSite(list, site, node) {
  return sortTransfers((Array.isArray(list) ? list : []).filter((t) => t.plan && t.plan.site === site
    && (t.plan.source_node === node || t.plan.target_node === node)));
}

function sortTransfers(list) {
  const open = (t) => (transferFinished(t) ? 1 : 0);
  return [...list].sort((a, b) => open(a) - open(b) || (a.updated_at < b.updated_at ? 1 : a.updated_at > b.updated_at ? -1 : 0));
}

// Rows for the Databases page: everything still open plus what finished within the last week, at most 25
export function transferRows(list, now = Date.now()) {
  const week = 7 * 24 * 3600 * 1000;
  const recent = (t) => !transferFinished(t) || now - Date.parse(t.updated_at) < week || Number.isNaN(Date.parse(t.updated_at));
  return sortTransfers((Array.isArray(list) ? list : []).filter((t) => t.plan && recent(t))).slice(0, 25).map((t) => ({
    id: t.id,
    site: t.plan.site,
    database: databaseName(t.plan.database),
    source: t.plan.source_node,
    target: t.plan.target_node,
    phase: t.phase,
    label: phaseLabel(t.phase),
    kind: phaseKind(t.phase),
    percent: transferPercent(t),
    running: Boolean(t.running),
    awaiting: Boolean(t.awaiting_operator),
    updatedAt: t.updated_at,
    error: t.error || '',
  }));
}

export function anyRunning(list) {
  return (Array.isArray(list) ? list : []).some((t) => t.running);
}

// ---- Sessions the node reports ----

export const SESSION_STATES = {
  pending: 'Starting',
  freezing: 'Freezing the site',
  dumping: 'Dumping',
  ready: 'Ready to copy',
  receiving: 'Receiving data',
  restoring: 'Restoring',
  verifying: 'Comparing row counts',
  awaiting_cutover: 'Ready to cut over',
  cutover: 'Cutting over',
  failed: 'Failed',
};

export const OTHER_SESSIONS_NOTE = 'These transfers are open on this node but were not started from this console, for example from the desktop app. Finish or cancel them where they were started.';

// Open exports and imports of the node that no transfer of this console accounts for
export function unmanagedSessions(sessions, transfers) {
  const owned = new Set();
  for (const t of Array.isArray(transfers) ? transfers : []) {
    if (t.export_id) owned.add(t.export_id);
    if (t.import_id) owned.add(t.import_id);
  }
  return (Array.isArray(sessions) ? sessions : []).filter((s) => s && !owned.has(s.id)).map((s) => ({
    id: s.id,
    kind: s.kind === 'import' ? 'Import' : 'Export',
    database: databaseName(s.database),
    state: SESSION_STATES[s.state] || String(s.state || ''),
    updatedAt: s.updated_at,
  }));
}

// ---- Conversion between dedicated and shared on one node ----

export const CONVERT_STATES = {
  pending: 'Starting',
  freezing: 'Freezing the site',
  dumping: 'Dumping the database',
  restoring: 'Restoring into the new database',
  verifying: 'Comparing row counts',
  awaiting_cutover: 'Ready to cut over',
  cutover: 'Cutting over',
  done: 'Done',
  failed: 'Failed',
  rolled_back: 'Aborted',
};

export function convertLabel(state) {
  return CONVERT_STATES[state] || String(state || '');
}

export function convertKind(state) {
  if (state === 'done') return 'ok';
  if (state === 'failed') return 'bad';
  if (state === 'rolled_back') return 'muted';
  return state === 'awaiting_cutover' ? 'warn' : 'info';
}

// The two states in which a person decides; the others settle on their own
export function convertSettled(session) {
  return !session || ['awaiting_cutover', 'done', 'failed', 'rolled_back'].includes(session.state);
}

export function convertActions(session) {
  const state = session && session.state;
  return {
    cutover: state === 'awaiting_cutover',
    abort: Boolean(state) && state !== 'done' && state !== 'rolled_back',
  };
}

export function convertTarget(pg) {
  return pg && pg.mode === 'shared' ? 'dedicated' : 'shared';
}

export function convertText(to) {
  return to === 'shared'
    ? 'Copies the databases into the shared instance of this node. Resources and the Postgres major then follow the instance. The dedicated database is kept, frozen, until you delete it.'
    : 'Copies the databases out of the shared instance into a dedicated Postgres for this site. The shared copy is kept, frozen, until you delete it.';
}

export const CONVERT_NOTE = 'After a conversion the previous database is never deleted for you. It stays frozen and is listed as retired until you delete it.';

// ---- Shared instance ----

export function healthKind(text) {
  const v = String(text || '').toLowerCase();
  if (!v) return 'muted';
  if (v.includes('unhealthy') || v.includes('missing') || v.includes('exited') || v.includes('dead') || v.includes('stopped')) return 'bad';
  if (v.includes('starting') || v.includes('restarting') || v.includes('paused')) return 'warn';
  if (v.includes('healthy') || v.includes('running')) return 'ok';
  return 'muted';
}

export function cpusOf(nano) {
  const n = Number(nano) || 0;
  return n ? Math.round((n / 1e9) * 100) / 100 : 0;
}

export function sharedToForm(view) {
  const v = view || {};
  return {
    major: String(v.major || DEFAULT_MAJOR),
    memoryMb: String(v.memory_mb || 1024),
    cpus: String(cpusOf(v.nano_cpus) || 1),
    maxConnections: String(v.max_connections || 200),
  };
}

export function sharedProblem(form, { creating }) {
  if (creating) {
    const bad = majorProblem(form.major);
    if (bad) return bad;
  }
  const memory = wholeNumberProblem(form.memoryMb, { min: MIN_SHARED_MEMORY_MB, max: MAX_SHARED_MEMORY_MB, what: 'the memory limit in MiB' });
  if (memory) return memory;
  const cpus = Number(String(form.cpus).trim());
  if (!String(form.cpus).trim() || !Number.isFinite(cpus) || cpus < 0.25 || cpus > 64) return 'CPUs must be a number from 0.25 to 64.';
  return wholeNumberProblem(form.maxConnections, { min: 10, max: 1000, what: 'the connection limit' });
}

export function sharedBody(form, { creating }) {
  const body = {
    memory_mb: Number(form.memoryMb), cpus: Number(form.cpus), max_connections: Number(form.maxConnections),
  };
  if (creating) body.major = Number(form.major);
  return body;
}

export function tenantRows(shared) {
  const tenants = (shared && Array.isArray(shared.tenants)) ? shared.tenants : [];
  return tenants.map((t) => ({
    site: t.site,
    databases: t.databases || [],
    size: (t.databases || []).reduce((n, d) => n + (d.size_bytes || 0), 0),
  })).sort((a, b) => a.site.localeCompare(b.site));
}

export function sharedDeleteText(shared) {
  const tenants = tenantRows(shared);
  if (!tenants.length) return 'Removes the shared Postgres container and its network. The data volumes are kept.';
  return `${plural(tenants.length, 'site still uses', 'sites still use')} this instance. Deleting it removes every tenant database for good, takes those sites off Postgres and leaves them needing a redeploy.`;
}

export function sharedUpdateText() {
  return 'Changing the limits recreates the container. Every tenant is disconnected for a moment.';
}

// ---- Backup targets ----

export function targetProblem(form, { hasKeys = false } = {}) {
  const name = String(form.name || '').trim();
  if (!name) return 'Enter a name.';
  if (name.length > 64) return 'The name is at most 64 characters.';
  let url;
  try {
    url = new URL(String(form.endpoint || '').trim());
  } catch (ex) {
    return 'Enter the endpoint as a full URL, for example https://s3.eu-west-1.amazonaws.com.';
  }
  if (url.protocol !== 'https:') return 'Backup targets must use https.';
  if (!String(form.bucket || '').trim()) return 'Enter the bucket.';
  if (!String(form.region || '').trim()) return 'Enter the region.';
  const hasId = Boolean(String(form.accessKeyId || '').trim());
  const hasSecret = Boolean(form.secretAccessKey);
  if (!hasKeys && !(hasId && hasSecret)) return 'Enter both the access key id and the secret access key.';
  if (hasKeys && hasId !== hasSecret) return 'Enter both keys, or neither to keep the stored ones.';
  return '';
}

export function targetBody(form) {
  const body = {
    name: String(form.name).trim(),
    endpoint: String(form.endpoint).trim(),
    bucket: String(form.bucket).trim(),
    region: String(form.region).trim(),
    path_style: Boolean(form.pathStyle),
    prefix: String(form.prefix || '').trim(),
    encrypt: Boolean(form.encrypt),
  };
  if (String(form.accessKeyId || '').trim()) body.access_key_id = String(form.accessKeyId).trim();
  if (form.secretAccessKey) body.secret_access_key = form.secretAccessKey;
  return body;
}

export function targetToForm(t) {
  const v = t || {};
  return {
    name: v.name || '', endpoint: v.endpoint || '', bucket: v.bucket || '', region: v.region || '', pathStyle: Boolean(v.path_style),
    prefix: v.prefix || '', encrypt: v.encrypt !== false, accessKeyId: '', secretAccessKey: '',
  };
}

export function targetTestText(result) {
  if (result && result.ok) return 'The node reached the bucket and could write and read a test object.';
  return `Test failed: ${result && result.error ? result.error : 'the node did not say why'}`;
}

export function orphanText(o) {
  const parts = [];
  if (o.dedicated_volume) parts.push('a dedicated database volume');
  if (o.shared_databases && o.shared_databases.length) parts.push(plural(o.shared_databases.length, 'shared database', 'shared databases'));
  if (o.backups) parts.push(plural(o.backups, 'backup', 'backups'));
  if (o.secrets) parts.push(plural(o.secrets, 'stored secret', 'stored secrets'));
  return parts.length ? parts.join(', ') : 'nothing left';
}

// ---- Gating ----

// Whether a site can use the data services: a node that lists any data capability, and a site that is built and runs a server
export function runsServer(site) {
  const src = site && site.source;
  if (!src) return false;
  return (src.runtime || 'node') !== 'static' && src.rendering !== 'static';
}

// Dedicated database limits as the node validates them
export function pgResourceProblem(memoryText, connectionsText) {
  return wholeNumberProblem(memoryText, { min: MIN_SHARED_MEMORY_MB, max: MAX_SHARED_MEMORY_MB, what: 'the memory in MiB' })
    || wholeNumberProblem(connectionsText, { min: 10, max: 1000, what: 'the connection limit' });
}

export function dataFeatures(info) {
  return {
    postgres: hasFeature(info, 'dataPostgres'),
    shared: hasFeature(info, 'dataShared'),
    external: hasFeature(info, 'dataExternal'),
    s3: hasFeature(info, 'dataS3'),
    backups: hasFeature(info, 'dataBackups'),
    links: hasFeature(info, 'dataLinks'),
    transfer: hasFeature(info, 'dataTransfer'),
  };
}

export function showsDataTab(info, site) {
  const f = dataFeatures(info);
  return (f.postgres || f.external || f.s3) && runsServer(site);
}

export function showsDatabasesPage(info) {
  const f = dataFeatures(info);
  return f.shared || f.postgres;
}
