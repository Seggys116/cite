import test from 'node:test';
import assert from 'node:assert/strict';
import {
  MANUAL_BADGE, MAX_PEM_BYTES, MAX_RANGES, NAME_RULE, isManualCert, cidrProblem, coverageText, expiryState, hasCertificateBlock, hasPrivateKeyBlock, hostList, parsePort,
  parseRanges, rangesSaveNote, rangesToText, shortFingerprint, uncoveredNote, uploadProblem, validCertName,
} from '../../web/js/certlib.js';

// PEM blocks are assembled at run time so no complete key block sits in the source
const pem = (label, body = 'AA', extra = '') => `-----BEGIN ${label}-----\n${extra}${body}\n-----END ${label}-----\n`;
const CERT = pem('CERTIFICATE', 'MIIB');
const KEY = pem(['PRIVATE', 'KEY'].join(' '), 'MIGH');
const form = (over) => ({ name: 'main', certificate: CERT, privateKey: KEY, ...over });

test('names are short plain labels', () => {
  for (const ok of ['main', 'My cert_2026-11', 'a.b', 'a'.repeat(64)]) assert.equal(validCertName(ok), true, ok);
  for (const bad of ['', '   ', 'a/b', 'a\n', 'é', 'a%20', 'a'.repeat(65), null, undefined]) assert.equal(validCertName(bad), false, String(bad));
});

test('names must start with a letter or digit, have no edge spaces and never carry a PEM header', () => {
  for (const bad of [' lead', 'trail ', '.dot', '-dash', '_under', 'a-----b', '-----BEGIN CERTIFICATE-----', '-----BEGIN PRIVATE KEY-----']) {
    assert.equal(validCertName(bad), false, bad);
  }
  for (const ok of ['a', '9lives', 'a b', 'a-b', 'a----b']) assert.equal(validCertName(ok), true, ok);
  assert.match(uploadProblem({ name: '-----BEGIN CERTIFICATE-----', certificate: CERT, privateKey: KEY }), /-----/);
  assert.match(uploadProblem({ name: ' main', certificate: CERT, privateKey: KEY }), /Start with a letter or digit/);
  assert.match(NAME_RULE, /do not start or end with a space/);
});

test('PEM markers are found only as whole blocks', () => {
  assert.equal(hasCertificateBlock(CERT), true);
  assert.equal(hasCertificateBlock('-----BEGIN CERTIFICATE-----'), false);
  assert.equal(hasCertificateBlock(KEY), false);
  assert.equal(hasCertificateBlock(undefined), false);
  for (const label of ['PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY', 'ENCRYPTED PRIVATE KEY']) {
    assert.equal(hasPrivateKeyBlock(pem(label)), true, label);
  }
  assert.equal(hasPrivateKeyBlock(CERT), false);
  assert.equal(hasPrivateKeyBlock('-----BEGIN PUBLIC KEY-----\nAA\n-----END PUBLIC KEY-----'), false);
});

test('a complete upload passes and the first problem is reported otherwise', () => {
  assert.equal(uploadProblem(form({})), null);
  assert.equal(uploadProblem(form({ privateKey: pem('RSA PRIVATE KEY') })), null);
  assert.match(uploadProblem(form({ name: 'bad/name' })), /name/);
  assert.match(uploadProblem(form({ name: '' })), /name/);
  assert.match(uploadProblem(form({ certificate: '  ' })), /certificate chain/i);
  assert.match(uploadProblem(form({ certificate: 'hello' })), /BEGIN CERTIFICATE/);
  assert.match(uploadProblem(form({ certificate: KEY })), /private key/);
  assert.match(uploadProblem(form({ certificate: CERT + KEY })), /private key box/);
  assert.match(uploadProblem(form({ privateKey: '' })), /private key/i);
  assert.match(uploadProblem(form({ privateKey: CERT })), /BEGIN PRIVATE KEY/);
});

test('encrypted keys are refused with advice', () => {
  const encrypted = pem('ENCRYPTED PRIVATE KEY');
  assert.match(uploadProblem(form({ privateKey: encrypted })), /passphrase/);
  const legacy = pem('RSA PRIVATE KEY', 'AA', 'Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,AB\n\n');
  assert.match(uploadProblem(form({ privateKey: legacy })), /passphrase/);
});

test('a replacement may keep its name but not carry a bad one', () => {
  assert.equal(uploadProblem(form({ name: '', requireName: false })), null);
  assert.match(uploadProblem(form({ name: 'bad/name', requireName: false })), /name/);
});

test('the certificate and key together may not exceed 100 KiB', () => {
  assert.equal(MAX_PEM_BYTES, 100 * 1024);
  assert.match(uploadProblem(form({ certificate: CERT + 'A'.repeat(MAX_PEM_BYTES) })), /together.*100 KiB/);
  assert.match(uploadProblem(form({ privateKey: KEY + 'B'.repeat(MAX_PEM_BYTES) })), /together.*100 KiB/);
  const half = MAX_PEM_BYTES / 2;
  assert.match(uploadProblem(form({ certificate: CERT + 'A'.repeat(half), privateKey: KEY + 'B'.repeat(half) })), /together/);
  const room = MAX_PEM_BYTES - CERT.length - KEY.length;
  assert.equal(uploadProblem(form({ certificate: CERT + 'A'.repeat(room) })), null);
  assert.match(uploadProblem(form({ certificate: CERT + 'A'.repeat(room + 1) })), /together/);
});

test('a huge paste is refused on size alone, before any block pattern runs', () => {
  const huge = '-----BEGIN CERTIFICATE-----\n' + 'A'.repeat(5 * 1024 * 1024);
  const started = Date.now();
  assert.match(uploadProblem(form({ certificate: huge })), /together/);
  assert.match(uploadProblem(form({ privateKey: '-----BEGIN PRIVATE KEY-----\n' + 'B'.repeat(5 * 1024 * 1024) })), /together/);
  assert.ok(Date.now() - started < 2000);
  assert.equal(hasCertificateBlock(huge), false);
  assert.equal(hasPrivateKeyBlock('-----BEGIN PRIVATE KEY-----\n' + 'B'.repeat(MAX_PEM_BYTES + 1) + '\n-----END PRIVATE KEY-----'), false);
  assert.equal(validCertName('a'.repeat(100000)), false);
});

test('multibyte text counts as bytes against the limit', () => {
  const wide = CERT + 'é'.repeat(MAX_PEM_BYTES / 2);
  assert.match(uploadProblem(form({ certificate: wide })), /together/);
});

test('expiry is plain above 30 days, a warning under 30 and danger under 7 or when expired', () => {
  assert.deepEqual(expiryState(212), { kind: null, text: '212 days left' });
  assert.deepEqual(expiryState(30), { kind: null, text: '30 days left' });
  assert.deepEqual(expiryState(29), { kind: 'warn', text: '29 days left' });
  assert.deepEqual(expiryState(7), { kind: 'warn', text: '7 days left' });
  assert.deepEqual(expiryState(6), { kind: 'bad', text: '6 days left' });
  assert.deepEqual(expiryState(1), { kind: 'bad', text: '1 day left' });
  assert.deepEqual(expiryState(0), { kind: 'bad', text: 'Expires today' });
  assert.deepEqual(expiryState(-1), { kind: 'bad', text: 'Expired 1 day ago' });
  assert.deepEqual(expiryState(-12), { kind: 'bad', text: 'Expired 12 days ago' });
  assert.equal(expiryState(undefined).kind, null);
  assert.equal(expiryState('abc').text, 'unknown');
});

test('hand-placed certificates are recognised by their source', () => {
  assert.equal(isManualCert({ id: 'file:legacy.pem', source: 'manual' }), true);
  assert.equal(isManualCert({ id: '01JC9ZQ7M3X8V4N2B6T5R0WHYA', source: 'api' }), false);
  assert.equal(isManualCert({ id: '01JC9ZQ7M3X8V4N2B6T5R0WHYA' }), false);
  assert.equal(isManualCert(null), false);
  assert.match(MANUAL_BADGE, /by hand/);
  assert.match(MANUAL_BADGE, /read-only/);
});

test('fingerprints are shortened to sixteen hex digits', () => {
  assert.equal(shortFingerprint('AB:CD:EF:01:23:45:67:89:AA:BB'), 'abcdef0123456789');
  assert.equal(shortFingerprint('a'.repeat(64)), 'a'.repeat(16));
  assert.equal(shortFingerprint(''), '-');
  assert.equal(shortFingerprint(undefined), '-');
});

test('host coverage reads as plain text', () => {
  assert.equal(hostList(['a.com', 'b.com']), 'a.com, b.com');
  assert.equal(hostList(['a.com', 'b.com', 'c.com', 'd.com', 'e.com']), 'a.com, b.com, c.com and 2 more');
  assert.equal(hostList([]), 'no site hosts');
  assert.equal(coverageText(['a.com']), 'Covers a.com');
  assert.equal(coverageText([]), 'Covers no site hosts');
  assert.equal(coverageText(undefined), 'Covers no site hosts');
  assert.equal(uncoveredNote([]), '');
  assert.match(uncoveredNote(['docs.example.com']), /^1 site host has no certificate on this node: docs\.example\.com\./);
  assert.match(uncoveredNote(['a.com', 'b.com']), /^2 site hosts have no certificate on this node: a\.com, b\.com\./);
});

test('CIDR ranges are validated for both address families', () => {
  for (const ok of ['173.245.48.0/20', '10.0.0.0/12', '255.255.255.255/32', '2400:cb00::/32', '2a06:98c0::/29', '2400::/28', '1:2:3:4:5:6:7:8/64',
    '::ffff:198.51.100.0/120']) {
    assert.equal(cidrProblem(ok), null, ok);
  }
  for (const bad of ['', '1.2.3.4/', '1.2.3.4/33', '1.2.3/24', '256.1.1.1/24', '1.2.3.4/-1', '1.2.3.4/2x', 'abc/24', '2400:cb00::/129',
    '2400::cb00::1/32', ':::/16', '1:2:3:4:5:6:7:8:9/64', '1:2:3:4:5:6:7/64', 'g::/16', '1.2.3.4/24/8', '1.2.3.4.5', '1.2.3.4/']) {
    assert.ok(cidrProblem(bad), bad);
  }
  assert.match(cidrProblem('0.0.0.0/0'), /every IPv4 address/);
  assert.match(cidrProblem('::/0'), /every IPv6 address/);
});

test('bare addresses are single hosts, as the node reads them', () => {
  for (const ok of ['192.0.2.7', '1.2.3.4', '2001:db8::1', '2400:cb00::1', '::ffff:198.51.100.7', '1:2:3:4:5:6:7:8']) {
    assert.equal(cidrProblem(ok), null, ok);
  }
  assert.ok(cidrProblem('1.2.3'));
  assert.ok(cidrProblem('300.1.1.1'));
  assert.ok(cidrProblem('2001:::1'));
  assert.deepEqual(parseRanges('192.0.2.7\n2001:db8::1').ranges, ['192.0.2.7', '2001:db8::1']);
});

test('leading zeros are refused in octets and prefix lengths', () => {
  for (const bad of ['010.0.0.1', '10.00.0.1', '10.0.0.01', '192.168.001.1/24', '10.0.0.0/08', '10.0.0.0/012', '::ffff:010.0.0.1', '2400:cb00::/032']) {
    assert.ok(cidrProblem(bad), bad);
  }
  for (const ok of ['10.0.0.1', '10.0.0.0/16', '0.1.2.3', '192.0.2.0/24', '2400:cb00::/32', '1.2.3.4/0']) {
    assert.ok(cidrProblem(ok) === null || /every|wide/.test(cidrProblem(ok)), ok);
  }
  assert.equal(cidrProblem('10.0.0.1'), null);
  assert.equal(cidrProblem('0.1.2.3'), null);
  assert.match(cidrProblem('10.0.0.0/0'), /every IPv4/);
});

test('ranges the node refuses as too wide are refused here', () => {
  for (const bad of ['10.0.0.0/11', '0.0.0.0/1', '10.0.0.0/8', '2400::/27', '2000::/3', 'fe80::/10', '1.2.3.4/8']) {
    assert.match(cidrProblem(bad), /too wide/, bad);
  }
  assert.match(cidrProblem('10.0.0.0/11'), /IPv4 ranges must be \/12 or narrower/);
  assert.match(cidrProblem('2400::/27'), /IPv6 ranges must be \/28 or narrower/);
});

test('IPv6 ranges that also cover IPv4 clients are refused', () => {
  for (const bad of ['::1/128', '::/96', '::/28', '2002::/16', '2002:c000:204::/48', '64:ff9b::/96', '64:ff9b::1:2/128', '::ffff:0:0/95', '::ffff:0:0/28']) {
    assert.match(cidrProblem(bad), /IPv4 clients|too wide|every/, bad);
  }
  assert.match(cidrProblem('2002::/28'), /list IPv4 ranges as IPv4/);
  assert.match(cidrProblem('2002::/16'), /too wide/);
  assert.match(cidrProblem('64:ff9b::/96'), /list IPv4 ranges as IPv4/);
  assert.match(cidrProblem('::1/128'), /list IPv4 ranges as IPv4/);
  assert.match(cidrProblem('::ffff:0:0/96'), /every IPv4 address/);
  assert.equal(cidrProblem('2003::/32'), null);
});

test('range text becomes a clean list with line numbered errors', () => {
  const ok = parseRanges('173.245.48.0/20\n\n  103.21.244.0/22  \r\n173.245.48.0/20\n2400:cb00::/32');
  assert.deepEqual(ok.ranges, ['173.245.48.0/20', '103.21.244.0/22', '2400:cb00::/32']);
  assert.deepEqual(ok.errors, []);
  const bad = parseRanges('10.0.0.0/16\nnot-a-range\n1.2.3.4/40');
  assert.deepEqual(bad.ranges, ['10.0.0.0/16']);
  assert.equal(bad.errors.length, 2);
  assert.match(bad.errors[0], /^Line 2: not-a-range /);
  assert.match(bad.errors[1], /^Line 3: 1\.2\.3\.4\/40 /);
  assert.deepEqual(parseRanges('').ranges, []);
  assert.deepEqual(parseRanges(undefined).errors, []);
});

test('too many ranges are reported', () => {
  const many = Array.from({ length: MAX_RANGES + 1 }, (_, i) => `10.${Math.floor(i / 256)}.${i % 256}.0/24`).join('\n');
  const out = parseRanges(many);
  assert.equal(out.ranges.length, MAX_RANGES + 1);
  assert.match(out.errors[0], /at most 256/);
});

test('ranges round trip through text and describe what saving does', () => {
  assert.equal(rangesToText(['a', 'b']), 'a\nb');
  assert.equal(rangesToText(undefined), '');
  assert.equal(rangesSaveNote([]), 'No custom ranges, so the built-in list is used.');
  assert.equal(rangesSaveNote(['10.0.0.0/8']), 'Saves 1 custom range.');
  assert.equal(rangesSaveNote(['10.0.0.0/8', '11.0.0.0/8']), 'Saves 2 custom ranges.');
});

test('the HTTPS port is a whole number from 1 to 65535', () => {
  assert.equal(parsePort(' 443 ').value, 443);
  assert.equal(parsePort('65535').value, 65535);
  assert.equal(parsePort('1').value, 1);
  for (const bad of ['0', '65536', '-1', '4.5', 'abc', '', ' ', '123456']) assert.ok(parsePort(bad).error, bad);
});
