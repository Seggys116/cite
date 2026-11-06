export const RING_SIZE = 5000;
export const FOLLOW_MS = 2000;
export const FIRST_TAIL = 300;
export const LEVELS = ['error', 'warn', 'info', 'debug'];

const ESC = String.fromCharCode(27);
const CSI = new RegExp(`${ESC}\\[[0-9;?]*[ -/]*[@-~]`, 'g');
const OSC = new RegExp(`${ESC}\\][^${String.fromCharCode(7)}${ESC}]*(?:${String.fromCharCode(7)}|${ESC}\\\\)`, 'g');
const OTHER = new RegExp(`${ESC}(?:[()*+][0-9A-Za-z]|[@-Z\\\\-_])`, 'g');
const chr = String.fromCharCode;
// Tab and newline are kept; carriage returns and other control characters are dropped
const CONTROL = new RegExp(`[${chr(0)}-${chr(8)}${chr(11)}-${chr(31)}${chr(127)}]`, 'g');

export function stripAnsi(text) {
  return String(text ?? '').replace(OSC, '').replace(CSI, '').replace(OTHER, '').replace(CONTROL, '');
}

const ERROR_RE = /\b(?:error|fatal|panic|exception|failed|failure|cannot|unhandled)\b|\berr!|can't/i;
const WARN_RE = /\b(warn|warning|deprecated)\b/i;
const DEBUG_RE = /\b(debug|trace|verbose)\b/i;

export function levelOf(line) {
  const given = String((line && line.level) || '').toLowerCase();
  if (given === 'warning') return 'warn';
  if (LEVELS.includes(given)) return given;
  if (given === 'fatal' || given === 'critical') return 'error';
  if (given === 'trace') return 'debug';
  const text = String((line && line.text) || '');
  if (ERROR_RE.test(text)) return 'error';
  if (WARN_RE.test(text)) return 'warn';
  if (DEBUG_RE.test(text)) return 'debug';
  return 'info';
}

export function normaliseLine(line, id) {
  const text = stripAnsi(line && line.text);
  return {
    id,
    ts: (line && line.ts) || '',
    stream: (line && line.stream) || '',
    phase: (line && line.phase) || '',
    level: levelOf({ level: line && line.level, text }),
    text,
  };
}

export class LogBuffer {
  constructor(size = RING_SIZE) {
    this.size = size;
    this.reset();
  }

  reset() {
    this.lines = [];
    this.cursor = null;
    this.next = 1;
    this.dropped = 0;
    this.truncated = false;
  }

  // Returns how many lines were added; a batch bigger than the ring keeps only its newest lines
  push(response) {
    const incoming = response && Array.isArray(response.lines) ? response.lines : [];
    if (response && response.cursor) this.cursor = response.cursor;
    if (response && response.truncated) this.truncated = true;
    for (const raw of incoming) {
      this.lines.push(normaliseLine(raw, this.next));
      this.next += 1;
    }
    const over = this.lines.length - this.size;
    if (over > 0) {
      this.lines.splice(0, over);
      this.dropped += over;
    }
    return incoming.length;
  }
}

export function filterLines(lines, { search = '', levels = null } = {}) {
  const needle = String(search).trim().toLowerCase();
  return lines.filter((l) => (!levels || levels.includes(l.level)) && (!needle || l.text.toLowerCase().includes(needle)));
}

// Splits text around matches so the viewer can wrap each match in an element and never builds markup from log text
export function splitMatches(text, search) {
  const needle = String(search ?? '').trim().toLowerCase();
  if (!needle) return [{ text, hit: false }];
  const lower = text.toLowerCase();
  const out = [];
  let at = 0;
  for (;;) {
    const i = lower.indexOf(needle, at);
    if (i < 0) break;
    if (i > at) out.push({ text: text.slice(at, i), hit: false });
    out.push({ text: text.slice(i, i + needle.length), hit: true });
    at = i + needle.length;
  }
  if (at < text.length) out.push({ text: text.slice(at), hit: false });
  return out.length ? out : [{ text, hit: false }];
}

export function linesToText(lines) {
  return lines.map((l) => `${l.ts ? `${l.ts} ` : ''}${l.text}`).join('\n');
}

// The query for the next request: the first load asks for a tail, later loads ask only for what is new
export function nextQuery({ source, slot, cursor }) {
  const q = { source };
  if (slot) q.slot = slot;
  if (cursor) q.since = cursor;
  else q.tail = FIRST_TAIL;
  return q;
}

// Polling stops while the tab is hidden or the viewer is not following, and the first load always happens
export function shouldPoll({ follow, hidden, loaded }) {
  if (!loaded) return !hidden;
  return Boolean(follow) && !hidden;
}

export function levelCounts(lines) {
  const out = { error: 0, warn: 0, info: 0, debug: 0 };
  for (const l of lines) out[l.level] += 1;
  return out;
}
