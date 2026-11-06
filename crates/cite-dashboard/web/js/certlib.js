// The connector caps the whole JSON body at 128 KiB, so the certificate and key together stay under 100 KiB to leave room for escaping
export const MAX_PEM_BYTES = 100 * 1024;
export const MAX_NAME_CHARS = 64;
export const MAX_RANGES = 256;
export const WARN_DAYS = 30;
export const DANGER_DAYS = 7;

export const SUPPORT_NOTE = 'This node needs a connector update before it can store certificates.';
export const MANUAL_BADGE = 'Placed on the node by hand: read-only';

// Hand-placed files are listed with source "manual" and an id such as file:name, which the item routes refuse
export function isManualCert(cert) {
  return Boolean(cert) && cert.source === 'manual';
}

export const HTTPS_OFF_NOTE = 'HTTPS is turned off on this node, so certificates are stored but not served. Set an HTTPS port to start serving them.';

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/;
export const NAME_RULE = `Use up to ${MAX_NAME_CHARS} letters, digits, spaces, dots, dashes or underscores. Start with a letter or digit, do not start or end with a space and do not use -----.`;
const CERT_BLOCK = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/;
const KEY_BLOCK = /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z]+ )?PRIVATE KEY-----/;
const ENCRYPTED_KEY = /-----BEGIN ENCRYPTED PRIVATE KEY-----|Proc-Type:\s*4,\s*ENCRYPTED/;
const V4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const HEX_GROUP = /^[0-9a-f]{1,4}$/i;

export function validCertName(name) {
  return typeof name === 'string' && name.length <= MAX_NAME_CHARS && NAME_RE.test(name) && !name.endsWith(' ') && !name.includes('-----');
}

// Anything over the limit is not searched at all, because the lazy block patterns are slow on huge text
function searchable(pem) {
  const text = String(pem || '');
  return text.length > MAX_PEM_BYTES ? '' : text;
}

export function hasCertificateBlock(pem) {
  return CERT_BLOCK.test(searchable(pem));
}

export function hasPrivateKeyBlock(pem) {
  return KEY_BLOCK.test(searchable(pem));
}

const byteLength = (text) => new TextEncoder().encode(String(text || '')).length;

// The first problem with an upload form, checked before anything is sent; the server still validates everything
export function uploadProblem({ name, certificate, privateKey, requireName = true }) {
  const label = String(name ?? '');
  if (requireName || label !== '') {
    if (!validCertName(label)) return `The certificate name is not valid. ${NAME_RULE}`;
  }
  // Sizes come first so a huge paste never reaches the block patterns below
  if (byteLength(certificate) + byteLength(privateKey) > MAX_PEM_BYTES) return `The certificate and key together must be no larger than ${MAX_PEM_BYTES / 1024} KiB.`;
  if (!String(certificate || '').trim()) return 'Add the certificate chain in PEM format.';
  if (hasPrivateKeyBlock(certificate)) return 'The certificate box contains a private key. Put the key in the private key box.';
  if (!hasCertificateBlock(certificate)) return 'The certificate must be PEM text that starts with -----BEGIN CERTIFICATE-----.';
  if (!String(privateKey || '').trim()) return 'Add the private key in PEM format.';
  if (ENCRYPTED_KEY.test(String(privateKey))) return 'The private key is encrypted. Remove its passphrase first, for example with openssl.';
  if (!hasPrivateKeyBlock(privateKey)) return 'The private key must be PEM text that starts with -----BEGIN PRIVATE KEY-----.';
  return null;
}

// Healthy certificates get no chip; under 30 days is a warning and under 7, or expired, is danger
export function expiryState(daysLeft) {
  const days = Math.floor(Number(daysLeft));
  if (!Number.isFinite(days)) return { kind: null, text: 'unknown' };
  if (days < 0) {
    const ago = -days;
    return { kind: 'bad', text: `Expired ${ago} ${ago === 1 ? 'day' : 'days'} ago` };
  }
  const text = days === 0 ? 'Expires today' : `${days} ${days === 1 ? 'day' : 'days'} left`;
  if (days < DANGER_DAYS) return { kind: 'bad', text };
  if (days < WARN_DAYS) return { kind: 'warn', text };
  return { kind: null, text };
}

export function shortFingerprint(fingerprint) {
  const hex = String(fingerprint || '').replace(/[^0-9a-f]/gi, '').toLowerCase();
  return hex ? hex.slice(0, 16) : '-';
}

// Short list for a table cell, naming how many more there are
export function hostList(hosts, max = 3) {
  const list = Array.isArray(hosts) ? hosts.filter(Boolean) : [];
  if (!list.length) return 'no site hosts';
  if (list.length <= max) return list.join(', ');
  return `${list.slice(0, max).join(', ')} and ${list.length - max} more`;
}

export function coverageText(covers) {
  const list = Array.isArray(covers) ? covers.filter(Boolean) : [];
  return list.length ? `Covers ${hostList(list)}` : 'Covers no site hosts';
}

export function uncoveredNote(hosts) {
  const list = Array.isArray(hosts) ? hosts.filter(Boolean) : [];
  if (!list.length) return '';
  const noun = list.length === 1 ? 'site host has' : 'site hosts have';
  return `${list.length} ${noun} no certificate on this node: ${list.join(', ')}. Visitors to ${list.length === 1 ? 'it' : 'them'} over HTTPS get a certificate warning, unless the site uses Flexible SSL behind Cloudflare.`;
}

// A dotted quad as a number, or null when an octet is above 255 or has a leading zero, which the node's parser refuses
function parseV4(text) {
  const m = V4.exec(text);
  if (!m || m.slice(1).some((octet) => Number(octet) > 255 || (octet.length > 1 && octet.startsWith('0')))) return null;
  return m.slice(1).reduce((acc, octet) => (acc << 8n) | BigInt(octet), 0n);
}

// An IPv6 address as a 128-bit number; a dotted tail such as ::ffff:1.2.3.4 is read as its last two groups
function parseV6(raw) {
  let text = raw;
  if (text.includes('.')) {
    const at = text.lastIndexOf(':');
    const tail = parseV4(text.slice(at + 1));
    if (tail === null) return null;
    text = `${text.slice(0, at + 1)}${(tail >> 16n).toString(16)}:${(tail & 0xffffn).toString(16)}`;
  }
  if (!/^[0-9a-f:]+$/i.test(text) || text.includes(':::')) return null;
  const halves = text.split('::');
  if (halves.length > 2) return null;
  const groups = (part) => (part === '' ? [] : part.split(':'));
  const head = groups(halves[0]);
  const tail = halves.length === 2 ? groups(halves[1]) : [];
  const all = [...head, ...tail];
  if (!all.every((g) => HEX_GROUP.test(g))) return null;
  if (halves.length === 2 ? all.length > 7 : all.length !== 8) return null;
  const filled = [...head, ...Array(8 - all.length).fill('0'), ...tail];
  return filled.reduce((acc, g) => (acc << 16n) | BigInt(`0x${g}`), 0n);
}

// HAProxy tests an IPv4 peer as ::ffff:a.b.c.d against IPv6 entries, so these blocks must not overlap a custom IPv6 range
const V4_EMBEDDING_BLOCKS = [[0xffffn << 32n, 96], [0n, 96], [0x2002n << 112n, 16], [0x64ff9bn << 96n, 96]];
const MIN_PREFIX_V4 = 12;
const MIN_PREFIX_V6 = 28;

function v6Overlaps(addr, bits, block, blockBits) {
  const shared = BigInt(Math.min(bits, blockBits));
  const mask = shared === 0n ? 0n : ((1n << 128n) - 1n) ^ ((1n << (128n - shared)) - 1n);
  return (addr & mask) === (block & mask);
}

// Returns why a range is refused, or null. A bare address means a single host, and the width and overlap rules are the node's.
export function cidrProblem(text) {
  const parts = String(text).split('/');
  if (parts.length > 2 || (parts.length === 2 && !/^(0|[1-9]\d{0,2})$/.test(parts[1]))) return 'is not a CIDR range such as 203.0.113.0/24';
  const v4 = !parts[0].includes(':');
  let addr = v4 ? parseV4(parts[0]) : parseV6(parts[0]);
  if (addr === null) return 'has an invalid address';
  const max = v4 ? 32 : 128;
  let bits = parts.length === 2 ? Number(parts[1]) : max;
  if (bits > max) return `has a prefix longer than ${max}`;
  let family = v4 ? 'IPv4' : 'IPv6';
  if (!v4 && bits >= 96 && addr >> 32n === 0xffffn) {
    addr &= 0xffffffffn;
    bits -= 96;
    family = 'IPv4';
  }
  if (bits === 0) return `matches every ${family} address, which would trust the whole internet`;
  if (family === 'IPv4') return bits < MIN_PREFIX_V4 ? `is too wide; IPv4 ranges must be /${MIN_PREFIX_V4} or narrower` : null;
  if (bits < MIN_PREFIX_V6) return `is too wide; IPv6 ranges must be /${MIN_PREFIX_V6} or narrower`;
  if (V4_EMBEDDING_BLOCKS.some(([block, blockBits]) => v6Overlaps(addr, bits, block, blockBits))) {
    return 'overlaps a block that also covers IPv4 clients; list IPv4 ranges as IPv4';
  }
  return null;
}

// One CIDR per line; blank lines are skipped and repeats collapse into one
export function parseRanges(text) {
  const ranges = [];
  const errors = [];
  String(text || '').split(/\r?\n/).forEach((raw, i) => {
    const line = raw.trim();
    if (!line) return;
    const problem = cidrProblem(line);
    if (problem) errors.push(`Line ${i + 1}: ${line} ${problem}.`);
    else if (!ranges.includes(line)) ranges.push(line);
  });
  if (ranges.length > MAX_RANGES) errors.push(`Use at most ${MAX_RANGES} ranges.`);
  return { ranges, errors };
}

export function rangesToText(ranges) {
  return (Array.isArray(ranges) ? ranges : []).join('\n');
}

// An empty override means the node falls back to its built-in list
export function rangesSaveNote(ranges) {
  return ranges.length ? `Saves ${ranges.length} custom ${ranges.length === 1 ? 'range' : 'ranges'}.` : 'No custom ranges, so the built-in list is used.';
}

export function parsePort(text) {
  const t = String(text ?? '').trim();
  if (!/^\d{1,5}$/.test(t)) return { error: 'The HTTPS port must be a whole number from 1 to 65535.' };
  const n = Number(t);
  if (n < 1 || n > 65535) return { error: 'The HTTPS port must be between 1 and 65535.' };
  return { value: n };
}
