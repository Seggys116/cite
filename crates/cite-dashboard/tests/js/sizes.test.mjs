import test from 'node:test';
import assert from 'node:assert/strict';
import { perBucketSizes } from '../../web/js/sizes.js';

test('cumulative counts become per-bucket counts', () => {
  const cumulative = [{ le: 1024, count: 14 }, { le: 4096, count: 36 }, { le: null, count: 100 }];
  assert.deepEqual(perBucketSizes(cumulative).map((b) => b.count), [14, 22, 64]);
});

test('bounds are preserved and empty or missing input is safe', () => {
  assert.deepEqual(perBucketSizes([{ le: 8, count: 3 }, { le: null, count: 3 }]), [{ le: 8, count: 3 }, { le: null, count: 0 }]);
  assert.deepEqual(perBucketSizes(undefined), []);
});

test('a bucket that goes backwards never yields a negative bar', () => {
  assert.deepEqual(perBucketSizes([{ le: 1, count: 5 }, { le: 2, count: 3 }, { le: null, count: 9 }]).map((b) => b.count), [5, 0, 4]);
});
