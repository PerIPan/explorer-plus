// scripts/lib/db-session.test.mjs — run with `npm test`
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { directNeonUrl, advisoryKeyParts } from './db-session.mjs';

test('directNeonUrl: pooler host -> direct host; everything else untouched', () => {
  const pooled = 'postgresql://u:p%40ss@ep-cool-name-123456-pooler.eu-central-1.aws.neon.tech/db?sslmode=require';
  const d = directNeonUrl(pooled);
  assert.equal(d.switched, true);
  assert.equal(new URL(d.url).hostname, 'ep-cool-name-123456.eu-central-1.aws.neon.tech');
  assert.equal(new URL(d.url).password, 'p%40ss');
  assert.equal(new URL(d.url).search, '?sslmode=require');
  assert.equal(new URL(d.url).pathname, '/db');
  assert.deepEqual(directNeonUrl('postgresql://localhost/scf'), { url: 'postgresql://localhost/scf', switched: false, via: null });
  assert.equal(directNeonUrl(pooled, 'postgresql://direct/x').url, 'postgresql://direct/x');
  assert.equal(directNeonUrl('not a url').url, 'not a url');
});

test('advisoryKeyParts: bigint key split as pg_locks stores it', () => {
  assert.deepEqual(advisoryKeyParts(0x736366), { classid: 0, objid: 7562086 }); // sync-scf, observed in pg_locks
  assert.deepEqual(advisoryKeyParts(2n ** 32n + 5n), { classid: 1, objid: 5 });
});
