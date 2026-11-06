import test from 'node:test';
import assert from 'node:assert/strict';
import { compileProblem, stripLeadingFlags } from '../../web/js/regexlib.js';
import { checkRegex } from '../../web/js/ui.js';
import { patternProblem } from '../../web/js/rulelib.js';

test('a leading (?i) flag is accepted everywhere a pattern is checked', () => {
  assert.equal(stripLeadingFlags('(?i)bot'), 'bot');
  assert.equal(stripLeadingFlags('a(?i)b'), 'a(?i)b');
  assert.equal(compileProblem('(?i)^/wp-(login|admin)'), null);
  assert.equal(checkRegex('(?i)(sqlmap|nikto)'), null);
  assert.equal(patternProblem('(?i)bot', 'Pattern'), null);
});

test('real syntax errors are still reported by every checker', () => {
  assert.ok(compileProblem('('));
  assert.ok(compileProblem('(?i)('));
  assert.ok(checkRegex('(?i)['));
  assert.ok(patternProblem('(?i)(', 'Pattern'));
  assert.equal(checkRegex('^/api/'), null);
  assert.doesNotMatch(checkRegex('('), /^Invalid regular expression/);
});
