// The build settings of a site as one flat form, converted to and from the node's Source and checked with the node's own rules
import { parseRepo } from './repolib.js';

export const RUNTIMES = ['node', 'bun', 'static', 'rust'];
export const NODE_MAJORS = [22, 24];
export const PACKAGE_MANAGERS = ['npm', 'pnpm', 'yarn', 'bun'];
export const RENDERINGS = ['static', 'ssr'];
export const MAX_PATH = 255;
export const MAX_COMMAND = 1024;
export const MAX_POLL_SECS = 366 * 86400;
const START_DENIED = ['npm', 'npx', 'pnpm', 'yarn', 'cargo', 'sh', 'bash', 'env'];
const START_META = new Set([';', '|', '&', '<', '>', '`', '$', '(', ')', '{', '}', '*', '?', '~', '!', '#', '\\']);

export const TEXT_KEYS = ['root_dir', 'install_command', 'build_command', 'output_dir', 'framework', 'start_command', 'spa_fallback'];
export const SOURCE_KEYS = ['repo', 'branch', 'runtime', 'node_major', 'poll_interval', 'package_manager', 'rendering', 'prune', ...TEXT_KEYS];

// Changing the poll interval needs no build; everything else changes what a build produces or where it comes from
export const NO_REBUILD_KEYS = ['poll_interval'];

export const FIELD_LABELS = {
  repo: 'Repository',
  branch: 'Branch',
  runtime: 'Runtime',
  node_major: 'Node version',
  poll_interval: 'Check for new commits every',
  package_manager: 'Package manager',
  rendering: 'Rendering',
  prune: 'Prune development dependencies',
  root_dir: 'Root directory',
  install_command: 'Install command',
  build_command: 'Build command',
  output_dir: 'Output directory',
  framework: 'Framework',
  start_command: 'Start command',
  spa_fallback: 'SPA fallback file',
};

export function sourceToForm(source) {
  const s = source || {};
  const text = (v) => (v === null || v === undefined ? '' : String(v));
  return {
    repo: text(s.repo),
    branch: text(s.branch) || 'main',
    runtime: text(s.runtime) || 'node',
    node_major: s.node_major ? String(s.node_major) : (s.runtime === 'rust' ? '' : '22'),
    poll_interval: text(s.poll_interval) || '5m',
    package_manager: text(s.package_manager),
    rendering: text(s.rendering),
    prune: s.prune === true ? 'true' : s.prune === false ? 'false' : '',
    root_dir: text(s.root_dir),
    install_command: text(s.install_command),
    build_command: text(s.build_command),
    output_dir: text(s.output_dir),
    framework: text(s.framework),
    start_command: text(s.start_command),
    spa_fallback: text(s.spa_fallback),
  };
}

// An empty field means "auto", so it is left out and the node detects the value; the stored secret reference is carried over untouched
export function formToSource(form, previous) {
  const repo = parseRepo(form.repo);
  const out = {
    repo: repo.ok ? repo.repo : String(form.repo || '').trim(),
    branch: String(form.branch || '').trim() || 'main',
    runtime: form.runtime || 'node',
    node_major: form.runtime === 'rust' ? null : Number(form.node_major) || null,
    poll_interval: String(form.poll_interval || '').trim() || '5m',
  };
  if (previous && previous.secret) out.secret = previous.secret;
  for (const key of TEXT_KEYS) {
    const v = String(form[key] ?? '').trim();
    if (v) out[key] = v;
  }
  if (form.package_manager) out.package_manager = form.package_manager;
  if (form.rendering) out.rendering = form.rendering;
  if (form.prune === 'true') out.prune = true;
  if (form.prune === 'false') out.prune = false;
  return out;
}

function branchProblem(b) {
  const ok = b.length >= 1 && b.length <= 255
    && [...b].every((ch) => ch.charCodeAt(0) > 0x20 && ch.charCodeAt(0) < 0x7f && !'~^:?*[\\'.includes(ch))
    && !b.includes('..') && !b.includes('@{') && !b.includes('//')
    && !b.startsWith('-') && !b.startsWith('/') && !b.endsWith('/') && !b.endsWith('.') && !b.endsWith('.lock');
  return ok ? null : 'This is not a valid git branch name.';
}

export function pollSeconds(text) {
  const t = String(text ?? '').trim();
  if (t === '0' || t.toLowerCase() === 'off') return 0;
  const m = t.match(/^(\d+)([A-Za-z]+)$/);
  if (!m) return null;
  const n = Number(m[1]);
  const unit = m[2].toLowerCase();
  const mult = { ms: 0.001, s: 1, sec: 1, secs: 1, m: 60, min: 60, mins: 60, h: 3600, hr: 3600, hrs: 3600, d: 86400, day: 86400, days: 86400 }[unit];
  if (mult === undefined) return null;
  return Math.floor(n * mult);
}

export function pollProblem(text) {
  const t = String(text ?? '').trim();
  if (t === '0' || t.toLowerCase() === 'off') return null;
  const secs = pollSeconds(text);
  if (secs === null) return 'The poll interval must be off, or a number with a unit such as 5m, 1h or 1d.';
  if (secs < 60) return 'The interval must be at least 60 seconds (or off).';
  if (secs > MAX_POLL_SECS) return 'The interval must be at most 366d.';
  return null;
}

export function relativePathProblem(value) {
  const p = String(value);
  const ok = p.length >= 1 && p.length <= MAX_PATH && /^[A-Za-z0-9._/-]+$/.test(p) && !p.startsWith('/') && !p.startsWith('-') && !p.split('/').includes('..');
  return ok ? null : 'Use a relative path of letters, digits, . _ - and / without "..".';
}

export function commandProblem(value) {
  const c = String(value);
  if (!c.trim() || c.length > MAX_COMMAND) return `Use 1 to ${MAX_COMMAND} characters.`;
  if ([...c].some((ch) => ch.charCodeAt(0) < 0x20 || ch.charCodeAt(0) === 0x7f)) return 'Use one line without control characters.';
  return null;
}

// The start command runs without a shell, so shell syntax is refused rather than escaped
export function startCommandProblem(value) {
  const base = commandProblem(value);
  if (base) return base;
  let quote = null;
  for (const ch of String(value)) {
    if (quote) {
      if (ch === quote) quote = null;
      else if (quote === '"' && (ch === '$' || ch === '`' || ch === '\\')) return 'Do not use shell expansion.';
    } else if (ch === '\'' || ch === '"') {
      quote = ch;
    } else if (START_META.has(ch)) {
      return 'Do not use shell characters such as ; | & < > $ ( ) * ? ~ ! # or a backslash.';
    }
  }
  if (quote) return 'A quote is not closed.';
  const argv0 = String(value).trim().split(/\s+/)[0].replace(/^['"]+|['"]+$/g, '');
  const program = argv0.split('/').pop();
  if (!program || argv0.includes('=') || START_DENIED.includes(program)) return 'Start with the program to run, not a package manager, shell or env.';
  return null;
}

export function slugProblem(value) {
  return /^[a-z0-9-]{1,32}$/.test(String(value)) ? null : 'Use 1 to 32 characters of a-z, 0-9 and -.';
}

// Every problem by field name, so the form can mark each field and the Save button can stay off
export function sourceProblems(form) {
  const out = {};
  const set = (key, message) => {
    if (message) out[key] = message;
  };
  const repo = parseRepo(form.repo);
  set('repo', repo.ok ? null : (repo.error || 'Enter the repository as owner/name or paste its address.'));
  set('branch', branchProblem(String(form.branch || '').trim()));
  if (!RUNTIMES.includes(form.runtime)) set('runtime', 'Pick node, bun, static or rust.');
  if (form.runtime !== 'rust' && !NODE_MAJORS.includes(Number(form.node_major))) set('node_major', 'The Node version is 22 or 24.');
  set('poll_interval', pollProblem(form.poll_interval));
  for (const key of ['root_dir', 'output_dir', 'spa_fallback']) {
    if (String(form[key] ?? '').trim()) set(key, relativePathProblem(String(form[key]).trim()));
  }
  for (const key of ['install_command', 'build_command']) {
    if (String(form[key] ?? '').trim()) set(key, commandProblem(String(form[key]).trim()));
  }
  const start = String(form.start_command ?? '').trim();
  if (start) {
    set('start_command', startCommandProblem(start));
    if (!out.start_command && form.rendering === 'static') set('rendering', 'Rendering cannot be static when a start command is set.');
  }
  if (String(form.framework ?? '').trim()) set('framework', slugProblem(String(form.framework).trim()));
  if (form.package_manager && !PACKAGE_MANAGERS.includes(form.package_manager)) set('package_manager', 'Pick npm, pnpm, yarn or bun.');
  if (form.rendering && !RENDERINGS.includes(form.rendering)) set('rendering', 'Pick static or ssr.');
  return out;
}

export function firstSourceProblem(form) {
  const all = sourceProblems(form);
  const key = SOURCE_KEYS.find((k) => all[k]);
  return key ? { field: key, message: all[key] } : null;
}

const norm = (v) => (v === undefined || v === '' ? null : v);

// The fields that differ between the stored source and the one the form would send
export function sourceDiff(previous, next) {
  // Both sides go through the form so a missing branch and the default branch do not count as a change
  const canon = (s) => (s ? formToSource(sourceToForm(s), s) : {});
  const a = canon(previous);
  const b = canon(next);
  return SOURCE_KEYS.filter((key) => JSON.stringify(norm(a[key])) !== JSON.stringify(norm(b[key])));
}

export function needsRebuild(changed) {
  return changed.some((key) => !NO_REBUILD_KEYS.includes(key));
}

export function changedLabels(changed) {
  return changed.map((key) => FIELD_LABELS[key] || key);
}

// The report's detected block lists what the manager chose on its own; an unset field shows it as a hint
export function autoHint(key, detected) {
  const d = detected && typeof detected === 'object' ? detected[key] : undefined;
  if (d === undefined || d === null || d === '') return 'Auto';
  return `Auto (detected: ${typeof d === 'object' ? JSON.stringify(d) : String(d)})`;
}

export function placeholderFor(key, detected) {
  const hint = autoHint(key, detected);
  return hint === 'Auto' ? 'Auto' : hint;
}
