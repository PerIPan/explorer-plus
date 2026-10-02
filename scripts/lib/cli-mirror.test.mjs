import { test } from 'node:test';
import assert from 'node:assert/strict';
import { collisions } from './cli-mirror.mjs';

test('a clean path set has no collisions', () => {
  assert.deepEqual(
    collisions([{ path: '/techniques' }, { path: '/techniques/{id}' }, { path: '/frameworks/csf' }]),
    [],
  );
});

test('a static and a dynamic child under one parent is reported', () => {
  // The ambiguity the generator refuses to build: is `scf` an id or a word?
  const out = collisions([{ path: '/frameworks/csf' }, { path: '/frameworks/{id}' }]);
  assert.equal(out.length, 1);
  assert.match(out[0], /^\/frameworks has both dynamic \({id}\) and static \(csf\)/);
});

test('collisions are detected at any depth', () => {
  const out = collisions([{ path: '/a/b/c' }, { path: '/a/b/{id}' }]);
  assert.equal(out.length, 1);
  assert.match(out[0], /^\/a\/b has both/);
});
