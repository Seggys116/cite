import test from 'node:test';
import assert from 'node:assert/strict';
import {
  BOT_CLASSES, buildExportParams, botClass, classBreakdown, exportFileName, exportPath, fmtSharePct, hasBotData, isIpAddress,
  parseLocalDateTime, parseSignals, retentionText, scoreBandClass, scoreBuckets, shareOf, signalHelp, signalLabel, toQuery, windowRange,
} from '../../web/js/botlib.js';

const NOW = Date.UTC(2025, 0, 15, 12, 0, 0);
const base = { kind: 'requests', top: 'paths', format: 'csv', rangeMode: 'window', window: '1h', limit: '500' };

test('every class has a distinct colour class and unknown values fall back safely', () => {
  const classes = BOT_CLASSES.map((c) => c.cls);
  assert.equal(new Set(classes).size, BOT_CLASSES.length);
  assert.equal(botClass('CRAWLER').key, 'crawler');
  assert.equal(botClass('nonsense').cls, 'bc-unknown');
  assert.equal(botClass(undefined).label, 'Unknown');
});

test('class breakdown keeps a stable order, fills gaps and keeps unexpected classes', () => {
  const out = classBreakdown([{ key: 'bot', count: 4 }, { key: 'human', count: 90 }, { key: 'weird', count: 2 }]);
  assert.deepEqual(out.map((c) => c.key), ['human', 'suspect', 'crawler', 'tool', 'bot', 'weird']);
  assert.deepEqual(out.map((c) => c.value), [90, 0, 0, 0, 4, 2]);
  assert.equal(out[5].cls, 'bc-unknown');
  assert.equal(classBreakdown(undefined).length, 5);
});

test('score buckets are always the five fixed bands in order', () => {
  const out = scoreBuckets([{ key: '80-100', count: 7 }, { key: '0-19', count: 3 }]);
  assert.deepEqual(out.map((b) => b.label), ['0-19', '20-39', '40-59', '60-79', '80-100']);
  assert.deepEqual(out.map((b) => b.value), [3, 0, 0, 0, 7]);
  assert.match(out[4].cls, /sb-4/);
});

test('score bands cover the edges and tolerate bad input', () => {
  assert.equal(scoreBandClass(0), 'sb-0');
  assert.equal(scoreBandClass(19), 'sb-0');
  assert.equal(scoreBandClass(20), 'sb-1');
  assert.equal(scoreBandClass(100), 'sb-4');
  assert.equal(scoreBandClass(250), 'sb-4');
  assert.equal(scoreBandClass('x'), 'sb-0');
});

test('signals are split, trimmed and deduplicated', () => {
  assert.deepEqual(parseSignals(' a, b ,,a,c '), ['a', 'b', 'c']);
  assert.deepEqual(parseSignals(''), []);
  assert.deepEqual(parseSignals(undefined), []);
  assert.equal(signalLabel('ua_generic_crawler'), 'UA generic crawler');
  assert.equal(signalLabel('missing_accept_language'), 'missing accept language');
  assert.match(signalHelp('missing_accept_language'), /Accept-Language/);
  assert.match(signalHelp('ua_curl'), /curl/);
  assert.ok(signalHelp('something_new').length > 0);
});

test('share formatting', () => {
  assert.equal(fmtSharePct(0), '0%');
  assert.equal(fmtSharePct(25), '25.0%');
  assert.equal(fmtSharePct(0.5), '0.50%');
  assert.equal(fmtSharePct('abc'), '0%');
  assert.equal(shareOf(1, 4), 0.25);
  assert.equal(shareOf(1, 0), 0);
});

test('bot data presence and retention text', () => {
  assert.equal(hasBotData({ bot_class: 'human' }), true);
  assert.equal(hasBotData({ bot_score: 0 }), true);
  assert.equal(hasBotData({ path: '/' }), false);
  assert.equal(hasBotData(null), false);
  assert.equal(retentionText(null), 'not reported');
  assert.equal(retentionText({ retention: { hour_buckets_days: 0, recent_events: 100 } }), 'hourly data kept forever, last 100 requests');
  assert.equal(retentionText({ retention: { hour_buckets_days: 30, archive_before_delete: true } }), '30 days of hourly data, archived before deletion');
  assert.equal(retentionText({ retention: { hour_buckets_days: 30, archive_before_delete: false } }), '30 days of hourly data, then deleted');
  assert.equal(retentionText({ retention: { minute_buckets_hours: 48, hour_buckets_days: 90, recent_events: 5000 } }), '48 h of minute data, 90 days of hourly data, last 5,000 requests');
});

test('windows map to a range ending now', () => {
  assert.deepEqual(windowRange('1h', NOW), { from: NOW - 3600000, to: NOW });
  assert.equal(windowRange('2y', NOW), null);
  const a = parseLocalDateTime('2025-01-15T10:00');
  const b = parseLocalDateTime('2025-01-15T11:00');
  assert.equal(b - a, 3600000);
  assert.equal(parseLocalDateTime(''), null);
  assert.equal(parseLocalDateTime('garbage'), null);
});

test('ip validation accepts v4 and v6 and rejects look-alikes', () => {
  for (const ok of ['203.0.113.7', '::1', '2001:db8::7a', '::ffff:192.0.2.1']) assert.equal(isIpAddress(ok), true, ok);
  for (const bad of ['', '256.1.1.1', '1.2.3', 'example.com', '1::2::3', 'fe80::g', '1.2.3.4/24']) assert.equal(isIpAddress(bad), false, bad);
});

test('a minimal export uses the current window and the typed limit', () => {
  const { params, error } = buildExportParams(base, NOW);
  assert.equal(error, undefined);
  assert.deepEqual(params, { kind: 'requests', format: 'csv', from: NOW - 3600000, to: NOW, limit: 500 });
});

test('a custom range must be complete and ordered', () => {
  const custom = { ...base, rangeMode: 'custom', from: '2025-01-15T10:00', to: '2025-01-15T09:00' };
  assert.match(buildExportParams(custom, NOW).error, /before/);
  assert.match(buildExportParams({ ...custom, to: '' }, NOW).error, /both/);
  const ok = buildExportParams({ ...custom, to: '2025-01-15T11:00' }, NOW);
  assert.equal(ok.params.to - ok.params.from, 3600000);
});

test('filters are validated and sent only for request level exports', () => {
  const filtered = {
    ...base, site: 'shop', statusMin: '400', statusMax: '499', botClass: 'tool', minScore: '60', host: 'example.com',
    pathPrefix: '/api/', clientIp: '203.0.113.7', method: 'POST',
  };
  const { params } = buildExportParams(filtered, NOW);
  assert.equal(params.site, 'shop');
  assert.equal(params.status_min, 400);
  assert.equal(params.status_max, 499);
  assert.equal(params.bot_class, 'tool');
  assert.equal(params.min_bot_score, 60);
  assert.equal(params.host, 'example.com');
  assert.equal(params.path_prefix, '/api/');
  assert.equal(params.client_ip, '203.0.113.7');
  assert.equal(params.method, 'POST');
  const hourly = buildExportParams({ ...filtered, kind: 'hourly' }, NOW).params;
  assert.equal(hourly.status_min, undefined);
  assert.equal(hourly.host, undefined);
  assert.equal(hourly.site, 'shop');
});

test('bad filters produce a specific message', () => {
  const bad = (patch) => buildExportParams({ ...base, ...patch }, NOW).error;
  assert.match(bad({ statusMin: '99' }), /Minimum status/);
  assert.match(bad({ statusMax: '600' }), /Maximum status/);
  assert.match(bad({ statusMin: '500', statusMax: '400' }), /above/);
  assert.match(bad({ minScore: '101' }), /bot score/);
  assert.match(bad({ minScore: '1.5' }), /whole number/);
  assert.match(bad({ botClass: 'robot' }), /bot class/);
  assert.match(bad({ clientIp: 'nope' }), /Client IP/);
  assert.match(bad({ pathPrefix: 'api' }), /slash/);
  assert.match(bad({ host: 'a b' }), /Host/);
  assert.match(bad({ method: 'FETCH' }), /method/);
  assert.match(bad({ limit: '0' }), /Row limit/);
  assert.match(bad({ limit: '99999999999' }), /Row limit/);
  assert.match(bad({ kind: 'everything' }), /export/);
  assert.match(bad({ format: 'xml' }), /CSV/);
  assert.match(bad({ window: '5y' }), /window/);
});

test('top exports need a known top list and an empty limit is allowed', () => {
  assert.match(buildExportParams({ ...base, kind: 'top', top: 'nope' }, NOW).error, /top list/);
  const ok = buildExportParams({ ...base, kind: 'top', top: 'languages', limit: '' }, NOW).params;
  assert.equal(ok.top, 'languages');
  assert.equal(ok.limit, undefined);
});

test('query strings skip empty values and escape the node name in the path', () => {
  assert.equal(toQuery({ a: 1, b: '', c: null, d: 'x y' }), '?a=1&d=x+y');
  assert.equal(toQuery({}), '');
  const path = exportPath('edge/1 a', { kind: 'bots', format: 'ndjson' });
  assert.equal(path, '/nodes/edge%2F1%20a/analytics/export?kind=bots&format=ndjson');
});

test('file names carry the kind, the top field and the right extension', () => {
  assert.equal(exportFileName({ kind: 'requests', format: 'csv' }, NOW), 'cite-requests-20250115-1200.csv');
  assert.equal(exportFileName({ kind: 'top', top: 'ips', format: 'ndjson' }, NOW), 'cite-top-ips-20250115-1200.ndjson');
});
