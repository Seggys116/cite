import test from 'node:test';
import assert from 'node:assert/strict';
import {
  LogBuffer, RING_SIZE, FIRST_TAIL, filterLines, levelCounts, levelOf, linesToText, nextQuery, normaliseLine, shouldPoll, splitMatches, stripAnsi,
} from '../../web/js/loglib.js';

const ESC = String.fromCharCode(27);
const BEL = String.fromCharCode(7);
const line = (text, over = {}) => ({ ts: '2026-11-06T10:00:00Z', stream: 'stdout', text, ...over });

test('terminal colour and cursor codes are removed', () => {
  assert.equal(stripAnsi(`${ESC}[31merror${ESC}[0m: bad`), 'error: bad');
  assert.equal(stripAnsi(`${ESC}[1;38;5;196mred${ESC}[0m`), 'red');
  assert.equal(stripAnsi(`${ESC}[2K${ESC}[1Gprogress 50%`), 'progress 50%');
  assert.equal(stripAnsi(`${ESC}]0;window title${BEL}text`), 'text');
  assert.equal(stripAnsi(`${ESC}]8;;https://x.example${ESC}\\link${ESC}]8;;${ESC}\\`), 'link');
  assert.equal(stripAnsi(`${ESC}(Bplain`), 'plain');
  assert.equal(stripAnsi('a\r\nb\tc'), 'a\nb\tc');
  assert.equal(stripAnsi(`bell${BEL}`), 'bell');
  assert.equal(stripAnsi(null), '');
  assert.equal(stripAnsi('no codes'), 'no codes');
});

test('levels come from the node or from the words in the line', () => {
  assert.equal(levelOf({ level: 'error', text: 'fine' }), 'error');
  assert.equal(levelOf({ level: 'WARNING', text: '' }), 'warn');
  assert.equal(levelOf({ level: 'fatal', text: '' }), 'error');
  assert.equal(levelOf({ level: 'trace', text: '' }), 'debug');
  assert.equal(levelOf({ text: 'npm ERR! code ELIFECYCLE' }), 'error');
  assert.equal(levelOf({ text: 'Build failed in 3s' }), 'error');
  assert.equal(levelOf({ text: 'warning: deprecated API' }), 'warn');
  assert.equal(levelOf({ text: 'DEBUG cache miss' }), 'debug');
  assert.equal(levelOf({ text: 'listening on 3000' }), 'info');
  assert.equal(levelOf({ level: 'odd', text: 'plain' }), 'info');
  assert.equal(levelOf(null), 'info');
});

test('a line is cleaned and labelled when it enters the viewer', () => {
  const n = normaliseLine(line(`${ESC}[31mError:${ESC}[0m boom`, { phase: 'building' }), 7);
  assert.deepEqual(n, { id: 7, ts: '2026-11-06T10:00:00Z', stream: 'stdout', phase: 'building', level: 'error', text: 'Error: boom' });
  assert.equal(normaliseLine({}, 1).text, '');
});

test('the buffer keeps the newest lines and the cursor', () => {
  const buf = new LogBuffer(5);
  assert.equal(buf.push({ lines: [line('a'), line('b'), line('c')], cursor: 'c-3' }), 3);
  assert.equal(buf.cursor, 'c-3');
  buf.push({ lines: [line('d'), line('e'), line('f'), line('g')], cursor: 'c-7', truncated: true });
  assert.deepEqual(buf.lines.map((l) => l.text), ['c', 'd', 'e', 'f', 'g']);
  assert.equal(buf.dropped, 2);
  assert.equal(buf.cursor, 'c-7');
  assert.equal(buf.truncated, true);
  assert.deepEqual(buf.lines.map((l) => l.id), [3, 4, 5, 6, 7]);
  buf.push({ lines: [] });
  assert.equal(buf.cursor, 'c-7');
  buf.push(null);
  assert.equal(buf.lines.length, 5);
  buf.reset();
  assert.deepEqual([buf.lines.length, buf.cursor, buf.dropped, buf.truncated], [0, null, 0, false]);
});

test('one huge batch keeps only the newest lines', () => {
  const buf = new LogBuffer();
  const lines = Array.from({ length: RING_SIZE + 250 }, (_, i) => line(`line ${i}`));
  buf.push({ lines });
  assert.equal(buf.lines.length, 5000);
  assert.equal(buf.lines[0].text, 'line 250');
  assert.equal(buf.lines.at(-1).text, `line ${RING_SIZE + 249}`);
  assert.equal(buf.dropped, 250);
});

test('search and level filters narrow the view', () => {
  const buf = new LogBuffer();
  buf.push({ lines: [line('Start server'), line('npm ERR! missing script', { level: 'error' }), line('warn: slow'), line('listening on PORT 3000')] });
  const all = buf.lines;
  assert.equal(filterLines(all, {}).length, 4);
  assert.deepEqual(filterLines(all, { search: 'port' }).map((l) => l.text), ['listening on PORT 3000']);
  assert.equal(filterLines(all, { search: '  ' }).length, 4);
  assert.deepEqual(filterLines(all, { levels: ['error'] }).map((l) => l.text), ['npm ERR! missing script']);
  assert.equal(filterLines(all, { levels: ['error', 'warn'], search: 'slow' }).length, 1);
  assert.deepEqual(levelCounts(all), { error: 1, warn: 1, info: 2, debug: 0 });
});

test('matches are split into plain pieces, never markup', () => {
  assert.deepEqual(splitMatches('Error: error', 'error'), [{ text: 'Error', hit: true }, { text: ': ', hit: false }, { text: 'error', hit: true }]);
  assert.deepEqual(splitMatches('abc', ''), [{ text: 'abc', hit: false }]);
  assert.deepEqual(splitMatches('abc', 'x'), [{ text: 'abc', hit: false }]);
  assert.deepEqual(splitMatches('a<b>c', '<b>'), [{ text: 'a', hit: false }, { text: '<b>', hit: true }, { text: 'c', hit: false }]);
  assert.deepEqual(splitMatches('', 'a'), [{ text: '', hit: false }]);
});

test('copied text has the time and the cleaned line', () => {
  const buf = new LogBuffer();
  buf.push({ lines: [line('one'), { text: 'two' }] });
  assert.equal(linesToText(buf.lines), '2026-11-06T10:00:00Z one\ntwo');
});

test('the first request asks for a tail and later ones for what is new', () => {
  assert.deepEqual(nextQuery({ source: 'manager', slot: '', cursor: null }), { source: 'manager', tail: FIRST_TAIL });
  assert.deepEqual(nextQuery({ source: 'executor', slot: 'blue', cursor: 'c-9' }), { source: 'executor', slot: 'blue', since: 'c-9' });
});

test('polling pauses when the tab is hidden or follow is off', () => {
  assert.equal(shouldPoll({ follow: true, hidden: false, loaded: true }), true);
  assert.equal(shouldPoll({ follow: true, hidden: true, loaded: true }), false);
  assert.equal(shouldPoll({ follow: false, hidden: false, loaded: true }), false);
  assert.equal(shouldPoll({ follow: false, hidden: false, loaded: false }), true);
  assert.equal(shouldPoll({ follow: false, hidden: true, loaded: false }), false);
});
