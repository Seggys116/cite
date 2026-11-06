import test from 'node:test';
import assert from 'node:assert/strict';
import {
  FLEXIBLE_WARNING, NO_BOT_BLOCKING, TLS_FULL_LABEL, botStatusLine, userAgentRulesFor, userAgentRulesLine,
  CLOUDFLARE_ONLY_HELP, CLOUDFLARE_ONLY_LABEL, TLS_FLEXIBLE_LABEL, ZONE_LOCK_HELP, ZONE_LOCK_LABEL, ZONE_LOCK_NEEDS_CLOUDFLARE, zoneLockOpenByDefault,
  BOT_POLICIES, FLEXIBLE_HELP, FULL_HELP, SEO_WARNING, ZONE_HEADER, ZONE_STEPS, accessForSave, accessOf, botWarning, flexibleWithoutCloudflare,
  SECRET_CLOSE_WARNING, ZONE_UNREADABLE_NOTE, createVerdict, isDefaultAccess, rotationFailureLines, rangesLine, secretCloseNeedsConfirm, tlsHelp, zoneLockTurnedOn, zoneStatusLine,
} from '../../web/js/accesslib.js';

test('a missing or partial access object means open access with the node TLS and no bot blocking', () => {
  const open = { cloudflare_only: false, tls: 'full', bots: 'allow', zone_lock: false };
  assert.deepEqual(accessOf(undefined), open);
  assert.deepEqual(accessOf({}), open);
  assert.deepEqual(accessOf({ access: {} }), open);
  assert.deepEqual(accessOf({ access: { cloudflare_only: true } }), { ...open, cloudflare_only: true });
  assert.deepEqual(accessOf({ access: { tls: 'flexible' } }), { ...open, tls: 'flexible' });
  assert.deepEqual(accessOf({ access: { tls: 'bogus', cloudflare_only: 'yes', bots: 'nope' } }), open);
  assert.equal(accessOf({ access: { bots: 'block_bad' } }).bots, 'block_bad');
  assert.equal(accessOf({ access: { bots: 'block_all' } }).bots, 'block_all');
});

test('the zone lock only counts while Cloudflare only is on', () => {
  assert.equal(accessOf({ access: { cloudflare_only: true, zone_lock: true } }).zone_lock, true);
  assert.equal(accessOf({ access: { cloudflare_only: false, zone_lock: true } }).zone_lock, false);
});

test('only the default combination counts as default', () => {
  assert.equal(isDefaultAccess({ cloudflare_only: false, tls: 'full' }), true);
  assert.equal(isDefaultAccess({ cloudflare_only: false, tls: 'full', bots: 'allow', zone_lock: false }), true);
  assert.equal(isDefaultAccess({ cloudflare_only: true, tls: 'full' }), false);
  assert.equal(isDefaultAccess({ cloudflare_only: false, tls: 'flexible' }), false);
  assert.equal(isDefaultAccess({ cloudflare_only: false, tls: 'full', bots: 'block_bad' }), false);
  assert.equal(isDefaultAccess({ cloudflare_only: true, tls: 'full', zone_lock: true }), false);
});

test('defaults are omitted unless the site already carries access', () => {
  const open = { cloudflare_only: false, tls: 'full' };
  assert.equal(accessForSave(open, undefined), undefined);
  assert.equal(accessForSave(open, null), undefined);
  assert.equal(accessForSave({ ...open, bots: 'allow', zone_lock: false }, undefined), undefined);
  assert.deepEqual(accessForSave(open, { cloudflare_only: true, tls: 'flexible' }), open);
  assert.deepEqual(accessForSave({ cloudflare_only: true, tls: 'flexible' }, undefined), { cloudflare_only: true, tls: 'flexible' });
  assert.deepEqual(accessForSave({ cloudflare_only: true, tls: 'weird' }, undefined), { cloudflare_only: true, tls: 'full' });
});

test('bots and the zone lock are sent only when they are not the default', () => {
  assert.deepEqual(accessForSave({ cloudflare_only: false, tls: 'full', bots: 'block_bad' }, undefined), { cloudflare_only: false, tls: 'full', bots: 'block_bad' });
  assert.deepEqual(accessForSave({ cloudflare_only: true, tls: 'full', bots: 'block_all', zone_lock: true }, undefined),
    { cloudflare_only: true, tls: 'full', bots: 'block_all', zone_lock: true });
  assert.deepEqual(accessForSave({ cloudflare_only: true, tls: 'full', bots: 'allow', zone_lock: false }, { cloudflare_only: true }),
    { cloudflare_only: true, tls: 'full' });
  assert.deepEqual(accessForSave({ cloudflare_only: false, tls: 'full', zone_lock: true }, undefined), undefined);
  assert.deepEqual(accessForSave({ cloudflare_only: true, tls: 'full', bots: 'bogus' }, undefined), { cloudflare_only: true, tls: 'full' });
});

test('the secret is only made when the lock goes from off to on', () => {
  assert.equal(zoneLockTurnedOn({ zone_lock: false }, { zone_lock: true }), true);
  assert.equal(zoneLockTurnedOn(undefined, { zone_lock: true }), true);
  assert.equal(zoneLockTurnedOn({ zone_lock: true }, { zone_lock: true }), false);
  assert.equal(zoneLockTurnedOn({ zone_lock: true }, { zone_lock: false }), false);
  assert.equal(zoneLockTurnedOn(undefined, { zone_lock: false }), false);
});

test('the zone status line separates no secret, a secret and an unreadable store', () => {
  const fmt = (v) => `<${v}>`;
  assert.match(zoneStatusLine({ configured: false, readable: true }, fmt), /No secret has been created yet/);
  assert.match(zoneStatusLine(null, fmt), /No secret has been created yet/);
  assert.equal(zoneStatusLine({ configured: true, created_at: 'T', fingerprint: 'ab12' }, fmt),
    'A secret was created on <T>, fingerprint ab12. It cannot be shown again; rotate it to get a new one.');
  assert.match(zoneStatusLine({ configured: true }, fmt), /^A secret was created\./);
  const unreadable = zoneStatusLine({ configured: false, readable: false }, fmt);
  assert.equal(unreadable, ZONE_UNREADABLE_NOTE);
  assert.match(unreadable, /could not be read/);
  assert.match(unreadable, /lock state is unknown/);
  assert.doesNotMatch(unreadable, /No secret has been created/);
  assert.equal(zoneStatusLine({ configured: true, readable: false }, fmt), ZONE_UNREADABLE_NOTE);
});

test('a create that fully succeeds rotates every node when the zone lock is on', () => {
  const v = createVerdict({ results: [{ node: 'a', ok: true }, { node: 'b', ok: true }], nodes: ['a', 'b'], zoneLock: true });
  assert.equal(v.ok, true);
  assert.equal(v.error, null);
  assert.deepEqual(v.rotate, ['a', 'b']);
  assert.deepEqual(v.failed, []);
  const open = createVerdict({ results: [{ node: 'a', ok: true }], nodes: ['a'], zoneLock: false });
  assert.deepEqual(open.rotate, []);
  assert.equal(open.ok, true);
});

test('a partial create still shows the secret for the nodes that took the site and names the failures', () => {
  const v = createVerdict({
    results: [{ node: 'a', ok: true }, { node: 'b', ok: false, error: 'site shop already exists' }, { node: 'c', ok: true }],
    nodes: ['a', 'b', 'c'],
    zoneLock: true,
  });
  assert.equal(v.ok, false);
  assert.deepEqual(v.rotate, ['a', 'c']);
  assert.deepEqual(v.failed, [{ node: 'b', error: 'site shop already exists' }]);
  assert.match(v.error, /b: site shop already exists/);
  assert.match(v.error, /zone secret for a, c is shown in the dialog/);
  const noLock = createVerdict({ results: [{ node: 'a', ok: true }, { node: 'b', error: 'x' }], nodes: ['a', 'b'], zoneLock: false });
  assert.deepEqual(noLock.rotate, []);
  assert.equal(noLock.error, 'b: x');
});

test('a create that fails everywhere rotates nothing and does not mention a dialog', () => {
  const v = createVerdict({ results: [{ node: 'a', ok: false, error: 'down' }, { node: 'b', error: 'full' }], nodes: ['a', 'b'], zoneLock: true });
  assert.equal(v.ok, false);
  assert.deepEqual(v.rotate, []);
  assert.equal(v.error, 'a: down; b: full');
  assert.doesNotMatch(v.error, /dialog/);
  const bare = createVerdict({ results: [{ ok: false }], nodes: ['a'], zoneLock: true });
  assert.equal(bare.error, 'node: failed');
});

test('an answer with no per-node results falls back to the nodes asked', () => {
  assert.deepEqual(createVerdict({ results: undefined, nodes: ['a', 'b'], zoneLock: true }).rotate, ['a', 'b']);
  assert.equal(createVerdict({ results: [], nodes: ['a'], zoneLock: true }).ok, true);
});

test('a rotate that fails on one node is reported with where to fix it', () => {
  const lines = rotationFailureLines([{ node: 'b', error: new Error('node returned 500') }], (e) => e.message);
  assert.equal(lines.length, 1);
  assert.match(lines[0], /^b: node returned 500\./);
  assert.match(lines[0], /Rotate the secret from that site's page/);
  assert.deepEqual(rotationFailureLines([], (e) => String(e)), []);
});

test('closing the secret dialog asks first only when nothing was copied', () => {
  assert.equal(secretCloseNeedsConfirm(false), true);
  assert.equal(secretCloseNeedsConfirm(true), false);
  assert.match(SECRET_CLOSE_WARNING, /cannot be shown again/);
});

test('bot policies have labels, and only block-all carries the search warning', () => {
  assert.deepEqual(BOT_POLICIES.map((p) => p.value), ['allow', 'block_bad', 'block_all']);
  assert.equal(botWarning('block_all'), SEO_WARNING);
  assert.equal(botWarning('block_bad'), '');
  assert.equal(botWarning('allow'), '');
  assert.match(SEO_WARNING, /search/);
});

test('the Cloudflare steps name the header and the Transform Rules path', () => {
  assert.equal(ZONE_HEADER, 'X-Cite-Origin-Secret');
  const text = ZONE_STEPS.join(' ');
  assert.match(text, /Rules, then Transform Rules/);
  assert.match(text, /Modify Request Header/);
  assert.match(text, /Set static/);
  assert.match(text, /X-Cite-Origin-Secret/);
});

test('flexible without Cloudflare only is the case that warns', () => {
  assert.equal(flexibleWithoutCloudflare({ cloudflare_only: false, tls: 'flexible' }), true);
  assert.equal(flexibleWithoutCloudflare({ cloudflare_only: true, tls: 'flexible' }), false);
  assert.equal(flexibleWithoutCloudflare({ cloudflare_only: false, tls: 'full' }), false);
  assert.equal(flexibleWithoutCloudflare({ cloudflare_only: true, tls: 'full' }), false);
});

test('each SSL mode has its own explanation', () => {
  assert.equal(tlsHelp('flexible'), FLEXIBLE_HELP);
  assert.equal(tlsHelp('full'), FULL_HELP);
  assert.match(FLEXIBLE_HELP, /plain http/);
  assert.match(FLEXIBLE_HELP, /no certificate is needed on the node/);
  assert.match(FULL_HELP, /node answers with its own certificate/);
});

test('the HTTPS choices and the proxy option are worded separately', () => {
  assert.equal(TLS_FULL_LABEL, 'Full (the node serves its own certificate)');
  assert.equal(TLS_FLEXIBLE_LABEL, 'Flexible SSL (Cloudflare serves HTTPS to visitors and talks to your server over plain http)');
  assert.equal(CLOUDFLARE_ONLY_HELP, 'When on, requests that do not arrive from Cloudflare\'s network are refused. Turn it on only for sites that are proxied by Cloudflare (orange cloud).');
  assert.doesNotMatch(CLOUDFLARE_ONLY_HELP, /every site|all sites/i);
  assert.match(FLEXIBLE_WARNING, /anyone can reach your server directly over plain http/);
});

test('allowing bots is never presented as protection', () => {
  assert.equal(botStatusLine('allow'), 'No bot blocking is active for this site');
  assert.equal(botStatusLine(undefined), NO_BOT_BLOCKING);
  assert.match(botStatusLine('block_bad'), /blocked/);
  assert.match(botStatusLine('block_all'), /search engines/);
});

test('firewall rules that look at user agents are listed for the site', () => {
  const rules = [
    { id: 'a', name: 'Scanners', enabled: true, action: 'tarpit', matchers: { user_agent_regexes: ['(sqlmap|nikto)'] }, site: null },
    { id: 'b', name: 'Old single', enabled: true, action: 'deny', matchers: { user_agent_regex: 'curl' }, site: 'shop' },
    { id: 'c', name: 'Other site', enabled: true, action: 'deny', matchers: { user_agent_regexes: ['x'] }, site: 'api' },
    { id: 'd', name: 'Paths only', enabled: true, action: 'deny', matchers: { path_prefixes: ['/x'] }, site: null },
    { id: 'e', name: 'Off', enabled: false, action: 'deny', matchers: { user_agent_regexes: ['bot'] }, site: 'shop' },
  ];
  const list = userAgentRulesFor(rules, 'shop');
  assert.deepEqual(list.map((r) => r.id), ['a', 'b', 'e']);
  assert.deepEqual(list.map((r) => r.scope), ['all sites', 'this site', 'this site']);
  assert.deepEqual(list[1].patterns, ['curl']);
  assert.equal(list[2].enabled, false);
  assert.deepEqual(userAgentRulesFor(null, 'shop'), []);
  assert.equal(userAgentRulesLine([]), 'No firewall rule looks at user agents for this site.');
  assert.match(userAgentRulesLine(list), /^2 firewall rules may block by user agent/);
  assert.match(userAgentRulesLine([list[2]]), /but it is switched off/);
  assert.match(userAgentRulesLine([list[0]]), /^1 firewall rule may block/);
});

test('the plain Cloudflare options use plain words and never mention rules, secrets or headers', () => {
  assert.equal(CLOUDFLARE_ONLY_LABEL, 'Only allow traffic through the Cloudflare proxy');
  assert.equal(ZONE_LOCK_LABEL, 'Also require that requests come from MY Cloudflare account (advanced)');
  for (const text of [CLOUDFLARE_ONLY_LABEL, CLOUDFLARE_ONLY_HELP, TLS_FLEXIBLE_LABEL, FLEXIBLE_HELP, FULL_HELP]) {
    assert.doesNotMatch(text, /transform|secret|header|X-Cite/i, text);
  }
  assert.match(ZONE_LOCK_HELP, /Transform Rule/);
  assert.match(ZONE_LOCK_NEEDS_CLOUDFLARE, /Only allow traffic through the Cloudflare proxy/);
});

test('the advanced account check stays folded away unless the site already uses it', () => {
  assert.equal(zoneLockOpenByDefault({ cloudflare_only: true, tls: 'full', zone_lock: true }), true);
  assert.equal(zoneLockOpenByDefault({ cloudflare_only: true, tls: 'full' }), false);
  assert.equal(zoneLockOpenByDefault(null), false);
});

test('the ranges line names the source, date and count', () => {
  assert.equal(rangesLine({ source: 'builtin', updated: '2026-11-06', ranges: new Array(22).fill('x') }),
    'Cloudflare ranges on this node: built-in list, updated 2026-11-06, 22 ranges.');
  assert.equal(rangesLine({ source: 'custom', updated: '', ranges: ['10.0.0.0/8'] }),
    'Cloudflare ranges on this node: custom list, 1 range.');
  assert.equal(rangesLine(null), '');
  assert.equal(rangesLine({ source: 'builtin' }), '');
});
