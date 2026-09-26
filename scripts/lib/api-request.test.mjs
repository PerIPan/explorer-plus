import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pathVariables, seedValues, composePath } from '../../src/lib/api-request.mjs';

test('pathVariables finds single segments and catch-alls', () => {
  assert.deepEqual(pathVariables('/techniques/{attackId}'), [
    { name: 'attackId', catchAll: false, index: 2 },
  ]);
  assert.deepEqual(pathVariables('/applications/{...slug}'), [
    { name: 'slug', catchAll: true, index: 2 },
  ]);
  assert.deepEqual(pathVariables('/sectors'), []);
});

test('seedValues lines the example up with the template', () => {
  const seeded = seedValues('/techniques/{attackId}', '/techniques/T1059?limit=5');
  assert.deepEqual(seeded.path, { attackId: 'T1059' });
  assert.deepEqual(seeded.query, { limit: '5' });
});

test('a catch-all seeds from EVERY remaining segment, not just the first', () => {
  const seeded = seedValues('/applications/{...slug}', '/applications/microsoft/windows_10');
  assert.deepEqual(seeded.path, { slug: 'microsoft/windows_10' });
});

test('seedValues survives an entry with no example', () => {
  assert.deepEqual(seedValues('/sectors', undefined), { path: {}, query: {} });
});

test('composePath drops blank query values rather than sending ?x=', () => {
  // A blank box means "I did not set this filter". Sent as an empty string it
  // becomes a value the route can reject, turning an untouched form into a 400.
  assert.equal(
    composePath('/cves', {}, [['severity', 'CRITICAL'], ['q', ''], ['app', '   ']]),
    '/cves?severity=CRITICAL',
  );
});

test('composePath encodes values but keeps a catch-all structural', () => {
  assert.equal(composePath('/search', {}, [['q', 'lazarus group']]), '/search?q=lazarus%20group');
  assert.equal(
    composePath('/applications/{...slug}', { slug: 'micro soft/windows 10' }, []),
    '/applications/micro%20soft/windows%2010',
  );
});

test('a blank path variable stays an empty segment', () => {
  // The 404 that follows is a true answer about the URL the reader built; a
  // silently dropped segment would be a different endpoint answering instead.
  assert.equal(composePath('/techniques/{attackId}', { attackId: '' }, []), '/techniques/');
});

test('round trip: seed then compose reproduces the example', () => {
  for (const [template, example] of [
    ['/techniques/{attackId}', '/techniques/T1059'],
    ['/cves', '/cves?severity=CRITICAL&limit=3'],
    ['/applications/{...slug}', '/applications/microsoft/windows_10'],
  ]) {
    const { path, query } = seedValues(template, example);
    assert.equal(composePath(template, path, Object.entries(query)), example);
  }
});
