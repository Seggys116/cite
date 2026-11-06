export const MAX_KEYS = 128;
export const MAX_VALUE = 4096;
export const MAX_BYTES = 24 * 1024;
const NAME_RE = /^[A-Z_][A-Z0-9_]{0,63}$/;
const DENIED = [
  'LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT', 'NODE_OPTIONS', 'NODE_EXTRA_CA_CERTS', 'HOME', 'PATH', 'TMPDIR', 'SSL_CERT_FILE', 'SSL_CERT_DIR',
  'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'ALL_PROXY', 'PNPM_HOME', 'NPM_CONFIG_PREFIX',
];
const DENIED_PREFIXES = ['XDG_', 'GIT_', 'NPM_CONFIG_', 'CITE_'];
// Mirrors RESERVED_BUILD_KEYS and RESERVED_BUILD_PREFIXES in cite-core, which apply to build variables only
const BUILD_DENIED = [
  'PATH', 'HOME', 'HOSTNAME', 'TERM', 'SHELL', 'USER', 'LOGNAME', 'BASH_ENV', 'ENV', 'RUST_LOG', 'NODE_VERSION', 'YARN_VERSION', 'TMPDIR', 'TMP', 'TEMP',
  'PNPM_HOME', 'NODE_OPTIONS', 'NODE_PATH', 'NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE',
  'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'NPM_CONFIG_CACHE', 'NPM_CONFIG_STORE_DIR', 'PNPM_CONFIG_STORE_DIR', 'COREPACK_HOME',
  'COREPACK_ENABLE_DOWNLOAD_PROMPT', 'BUN_INSTALL_CACHE_DIR', 'YARN_CACHE_FOLDER', 'YARN_GLOBAL_FOLDER', 'YARN_ENABLE_GLOBAL_CACHE',
  'CARGO_HOME', 'CARGO_TARGET_DIR', 'CARGO_TERM_COLOR',
];
const BUILD_DENIED_PREFIXES = ['CITE_', 'LD_', 'DYLD_', 'GIT_', 'XDG_'];
// Names the executor sets for the app itself, refused for runtime variables only
const RUNTIME_DENIED = ['PORT', 'NODE_ENV', 'HOST', 'HOSTNAME', 'NITRO_HOST'];

export function envNameProblem(name, kind = 'build') {
  const n = String(name ?? '');
  if (!NAME_RE.test(n)) return 'Use capital letters, digits and underscores, not starting with a digit, up to 64 characters.';
  const denied = kind === 'runtime' ? RUNTIME_DENIED : BUILD_DENIED;
  const prefixes = kind === 'runtime' ? [] : BUILD_DENIED_PREFIXES;
  if (DENIED.includes(n) || denied.includes(n) || DENIED_PREFIXES.concat(prefixes).some((p) => n.startsWith(p))) return `${n} is reserved by the node and cannot be set.`;
  return null;
}

export function envValueProblem(value) {
  const v = String(value ?? '');
  if (new TextEncoder().encode(v).length > MAX_VALUE) return `A value is at most ${MAX_VALUE} bytes.`;
  if ([...v].some((ch) => ch.charCodeAt(0) < 0x20 || ch.charCodeAt(0) === 0x7f)) return 'A value cannot contain control characters, so it must be one line.';
  return null;
}

export function buildPatch(pending, existing = [], kind = 'build') {
  const set = {};
  for (const [name, value] of pending.set) {
    const bad = envNameProblem(name, kind) || envValueProblem(value);
    if (bad) return { problem: `${name || 'A variable'}: ${bad}` };
    set[name] = value;
  }
  const unset = [];
  for (const name of pending.unset) {
    if (name in set) return { problem: `${name} is both replaced and removed.` };
    if (!NAME_RE.test(name)) return { problem: `${name}: the name is not valid.` };
    unset.push(name);
  }
  if (!Object.keys(set).length && !unset.length) return { problem: 'Nothing to save.' };
  if (Object.keys(set).length > MAX_KEYS || unset.length > MAX_KEYS) return { problem: `Change at most ${MAX_KEYS} variables at once.` };
  const total = Object.keys(set).length + existing.filter((n) => !unset.includes(n) && !(n in set)).length;
  if (total > MAX_KEYS) return { problem: `A site holds at most ${MAX_KEYS} variables.` };
  const size = new TextEncoder().encode(JSON.stringify({ set, unset })).length;
  if (size > MAX_BYTES) return { problem: 'The change is larger than 24 KiB.' };
  return { patch: { set, unset } };
}

// A new variable row: both parts must be given, and a name already on the node is a replace, not an add
export function addProblem(name, value, existing, pendingNames = [], kind = 'build') {
  const n = String(name ?? '').trim();
  if (!n) return 'Enter a variable name.';
  const bad = envNameProblem(n, kind);
  if (bad) return bad;
  if (existing.includes(n) || pendingNames.includes(n)) return `${n} is already in the list; use Replace on it.`;
  if (String(value ?? '') === '') return 'Enter a value.';
  return envValueProblem(value);
}

export function pendingCount(pending) {
  return pending.set.size + pending.unset.size;
}

export function pendingSummary(pending) {
  const parts = [];
  if (pending.set.size) parts.push(`${pending.set.size} to set`);
  if (pending.unset.size) parts.push(`${pending.unset.size} to remove`);
  return parts.join(', ') || 'No changes';
}

export function emptyPending() {
  return { set: new Map(), unset: new Set() };
}
