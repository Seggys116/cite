import test from 'node:test';
import assert from 'node:assert/strict';
import {
  HTTPS_TARGET, MAX_ROWS, WWW_TARGET, blankRow, describeFrom, diffRows, freeId, presetRow, rowForError, rowProblem, rowsProblems, rowToRule, rulesToRows,
} from '../../web/js/redirectlib.js';

const redirect = (id, matchers, to, status = 301, over = {}) => ({
  id, name: `Rule ${id}`, enabled: true, matchers, site: null, label: id, redirect: { to, status }, ...over,
});
const stored = () => [
  redirect('redirect-1', { path_prefixes: ['/blog'] }, 'https://blog.example.com/', 308, { site: 'shop' }),
  redirect('redirect-2', { path_regexes: ['^/shop/[0-9]+$'] }, '/products{query}'),
  redirect('redirect-3', { path_prefixes: ['/a', '/b'] }, '/c'),
  { id: 'r-block', name: 'Block', enabled: true, action: 'deny', matchers: { path_prefixes: ['/x'] }, site: null },
];

test('redirect rules become rows and other rules are left out', () => {
  const rows = rulesToRows(stored());
  assert.equal(rows.length, 3);
  assert.deepEqual([rows[0].simple, rows[0].mode, rows[0].value, rows[0].to, rows[0].status], [true, 'prefix', '/blog', 'https://blog.example.com/', 308]);
  assert.deepEqual([rows[1].simple, rows[1].mode, rows[1].value], [true, 'regex', '^/shop/[0-9]+$']);
  assert.equal(rows[2].simple, false);
  assert.deepEqual(rows[2].matchers, { path_prefixes: ['/a', '/b'] });
  assert.equal(new Set(rows.map((r) => r.key)).size, 3);
});

test('rows left alone produce no change at all', () => {
  const rows = rulesToRows(stored());
  const diff = diffRows(rows, stored());
  assert.deepEqual([diff.replace, diff.delete], [[], []]);
  rows[1].status = String(rows[1].status);
  assert.equal(diffRows(rows, stored()).replace.length, 0);
});

test('an edited row is replaced under its own id and keeps its scope and label', () => {
  const rows = rulesToRows(stored());
  rows[0].to = '/moved';
  rows[0].status = 302;
  const diff = diffRows(rows, stored());
  assert.equal(diff.replace.length, 1);
  assert.deepEqual(diff.delete, []);
  const [rule] = diff.replace;
  assert.equal(rule.id, 'redirect-1');
  assert.equal(rule.site, 'shop');
  assert.equal(rule.label, 'redirect-1');
  assert.equal(rule.name, 'Rule redirect-1');
  assert.deepEqual(rule.redirect, { to: '/moved', status: 302 });
  assert.deepEqual(rule.matchers, { path_prefixes: ['/blog'] });
  assert.equal(diff.owners.get('redirect-1'), rows[0].key);
  rows[0].enabled = false;
  assert.equal(diffRows(rows, stored()).replace[0].enabled, false);
});

test('a removed row is deleted and a block rule is never touched', () => {
  const rows = rulesToRows(stored());
  rows.splice(1, 1);
  const diff = diffRows(rows, stored());
  assert.deepEqual(diff.delete, ['redirect-2']);
  assert.deepEqual(diff.replace, []);
  assert.deepEqual(diffRows([], stored()).delete, ['redirect-1', 'redirect-2', 'redirect-3']);
});

test('new rows take the next free redirect-n id and a label to match', () => {
  const rows = rulesToRows(stored());
  const a = { ...blankRow(), value: '/new', to: '/n1' };
  const b = { ...blankRow(), mode: 'regex', value: '^/z', to: '/n2', status: 302 };
  rows.push(a, b);
  rows.splice(0, 1);
  const diff = diffRows(rows, stored());
  assert.deepEqual(diff.replace.map((r) => r.id), ['redirect-4', 'redirect-5']);
  assert.equal(diff.replace[0].label, 'redirect-4');
  assert.deepEqual(diff.replace[0].matchers, { path_prefixes: ['/new'] });
  assert.deepEqual(diff.replace[1].matchers, { path_regexes: ['^/z'] });
  assert.equal(diff.replace[1].redirect.status, 302);
  assert.equal(diff.replace[0].site, null);
  assert.equal(diff.replace[0].enabled, true);
  assert.deepEqual(diff.delete, ['redirect-1']);
  assert.equal(freeId(new Set()), 'redirect-1');
  assert.equal(freeId(new Set(['redirect-1', 'redirect-3'])), 'redirect-2');
  assert.equal(rowToRule(a, 'redirect-9').id, 'redirect-9');
});

test('the www and https quick rows use the placeholder targets', () => {
  const www = presetRow('www');
  assert.equal(www.to, WWW_TARGET);
  assert.equal(rowProblem(www), null);
  const https = presetRow('https');
  assert.equal(https.to, HTTPS_TARGET);
  assert.deepEqual(https.matchers, { scheme: 'http' });
  assert.equal(rowProblem(https), null);
  assert.equal(describeFrom(https), 'When the connection is http.');
  assert.equal(describeFrom(www), 'Every request');
  const rule = rowToRule(https, 'redirect-1');
  assert.deepEqual(rule.matchers, { scheme: 'http' });
  assert.equal(rule.name, 'Force HTTPS');
});

test('each row is checked as you type', () => {
  const row = (over) => ({ ...blankRow(), value: '/old', to: '/new', ...over });
  assert.equal(rowProblem(row({})), null);
  assert.match(rowProblem(row({ value: '' })), /path to redirect from/);
  assert.match(rowProblem(row({ value: 'old' })), /starts with \//);
  assert.match(rowProblem(row({ to: '' })), /address to redirect to/);
  assert.match(rowProblem(row({ to: '/old/new' })), /would loop/);
  assert.match(rowProblem(row({ to: 'javascript:alert(1)' })), /redirect target/);
  assert.match(rowProblem(row({ status: 303 })), /301, 302, 307 or 308/);
  assert.equal(rowProblem(row({ mode: 'regex', value: '^/old' })), null);
  assert.match(rowProblem(row({ mode: 'regex', value: '(' })), /regular expression/);
  assert.equal(rowProblem(row({ to: 'https://example.org/x' })), null);
});

test('two rows may not start from the same place and the table has a size limit', () => {
  const a = { ...blankRow(), value: '/old', to: '/n1' };
  const b = { ...blankRow(), value: '/old', to: '/n2' };
  const c = { ...blankRow(), mode: 'regex', value: '/old', to: '/n3' };
  const problems = rowsProblems([a, b, c]);
  assert.equal(problems.has(a.key), false);
  assert.match(problems.get(b.key), /Another row/);
  assert.equal(problems.has(c.key), false);
  const big = Array.from({ length: MAX_ROWS + 1 }, (_, i) => ({ ...blankRow(), value: `/p${i}`, to: '/x' }));
  assert.match(rowsProblems(big).get('*'), /at most 200/);
  assert.equal(rowsProblems(big.slice(0, MAX_ROWS)).size, 0);
});

test('a node error is matched to the row that sent that rule', () => {
  const owners = new Map([['redirect-1', 'k1'], ['redirect-10', 'k10']]);
  assert.equal(rowForError('rule redirect-1: the redirect loops', owners), 'k1');
  assert.equal(rowForError('rule redirect-10: bad target', owners), 'k10');
  assert.equal(rowForError('invalid rule "redirect-10"', owners), 'k10');
  assert.equal(rowForError('connection refused', owners), null);
  assert.equal(rowForError(undefined, owners), null);
});
