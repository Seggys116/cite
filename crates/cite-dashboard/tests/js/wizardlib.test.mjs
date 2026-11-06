import test from 'node:test';
import assert from 'node:assert/strict';
import {
  advance, back, canOpen, isLast, progressText, stepStates,
} from '../../web/js/wizardlib.js';

test('Next only moves past a clean step and never past the last', () => {
  assert.equal(advance(0, 5, null), 1);
  assert.equal(advance(0, 5, 'Fix this first.'), 0);
  assert.equal(advance(4, 5, null), 4);
});

test('Back stops at the first step', () => {
  assert.equal(back(3), 2);
  assert.equal(back(0), 0);
});

test('the last step is the one that finishes', () => {
  assert.equal(isLast(4, 5), true);
  assert.equal(isLast(3, 5), false);
});

test('earlier steps can always be opened and later ones only through clean steps', () => {
  const problems = [null, 'x', null, null, null];
  assert.equal(canOpen(0, 2, problems), true);
  assert.equal(canOpen(2, 2, problems), true);
  assert.equal(canOpen(-1, 2, problems), false);
  assert.equal(canOpen(2, 1, problems), false);
  assert.equal(canOpen(3, 2, problems), true);
  assert.equal(canOpen(4, 0, problems), false);
  assert.equal(canOpen(1, 0, problems), true);
});

test('progress is reported for people and for screen readers', () => {
  assert.deepEqual(stepStates(3, 1).map((s) => s.state), ['done', 'current', 'todo']);
  assert.equal(progressText(1, 5, 'Details'), 'Step 2 of 5: Details');
});
