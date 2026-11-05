import test from 'node:test';
import assert from 'node:assert/strict';
import { siteProblem } from '../../web/js/siteCheck.js';

const valid = {
  name: 'App', id: 'app', hostCount: 1, pathError: null, targetProblem: null, blueCount: 1, healthPath: '/', pickNodes: true, nodePicked: true,
};

test('a complete form has no problem so it can be submitted', () => {
  assert.equal(siteProblem(valid), null);
});

test('each missing or invalid field is reported', () => {
  assert.match(siteProblem({ ...valid, name: ' ' }), /name/);
  assert.match(siteProblem({ ...valid, id: 'Bad Id' }), /site id/);
  assert.match(siteProblem({ ...valid, hostCount: 0 }), /host/);
  assert.match(siteProblem({ ...valid, pathError: 'bad' }), /regex/);
  assert.equal(siteProblem({ ...valid, targetProblem: 'x is not a host:port address.' }), 'x is not a host:port address.');
  assert.match(siteProblem({ ...valid, blueCount: 0 }), /blue target/);
  assert.match(siteProblem({ ...valid, healthPath: 'health' }), /health check/);
});

test('node selection only matters when placing on chosen nodes', () => {
  assert.match(siteProblem({ ...valid, nodePicked: false }), /node/);
  assert.equal(siteProblem({ ...valid, pickNodes: false, nodePicked: false }), null);
});
