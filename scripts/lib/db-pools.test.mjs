// scripts/lib/db-pools.test.mjs
//
// Guards the two invariants of app/api/v1/lib/db.ts that are easy to undo by
// accident and impossible to notice in production:
//
//   1. The API pool carries a client-side ceiling and the maintenance pool
//      does not. If someone "tidies" these into one pool, every cron refresh
//      starts dying at 30s — or every API request becomes unbounded again.
//
//   2. `statementTimeoutMs` rejects a non-positive budget instead of silently
//      falling through to the unbounded path. `0` is falsy, so the obvious
//      `if (opts?.statementTimeoutMs)` did exactly that, and a caller asking
//      for a zero budget got no budget at all.
//
// Everything here is DB-free: pg's Pool is lazy, so a syntactically valid
// connection string is enough to inspect the options, and the budget
// validation throws before anything connects. The behaviours that DO need a
// database — that a 33s maintenance query survives the 30s API ceiling, that
// a 2s budget really cancels the statement server-side, and that it leaves no
// leaked setting behind — were verified against production on 2026-10-02 and
// are recorded in the header of db.ts.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import { existsSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';

registerHooks({
  resolve(spec, ctx, next) {
    try {
      return next(spec, ctx);
    } catch (err) {
      if (spec.startsWith('.') && ctx.parentURL?.endsWith('.ts')) {
        for (const ext of ['.ts', '.mjs']) {
          if (existsSync(new URL(spec + ext, ctx.parentURL))) return next(spec + ext, ctx);
        }
      }
      throw err;
    }
  },
});

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '../..');

// A well-formed string that is never dialled. Set before import: db.ts reads
// it when a pool is first requested. Not a `neon`/`vercel` host, so the module
// takes its non-production branch and we are not asserting prod-only values.
process.env.DATABASE_URL = 'postgres://u:p@127.0.0.1:5432/nodb';

const { getPool, getMaintenancePool, query } = await import(
  pathToFileURL(join(ROOT, 'app/api/v1/lib/db.ts')).href
);

test('the API pool carries a client-side query_timeout', () => {
  assert.equal(getPool().options.query_timeout, 30_000);
});

test('the maintenance pool carries none, so long refreshes are not cut off', () => {
  assert.equal(getMaintenancePool().options.query_timeout, undefined);
});

test('the two pools are distinct instances', () => {
  assert.notEqual(getPool(), getMaintenancePool());
});

test('each pool is memoised rather than rebuilt per call', () => {
  assert.equal(getPool(), getPool());
  assert.equal(getMaintenancePool(), getMaintenancePool());
});

test('statementTimeoutMs: 0 is refused, not treated as "no budget"', async () => {
  await assert.rejects(
    () => query('SELECT 1', [], { statementTimeoutMs: 0 }),
    /positive integer, got 0/,
  );
});

test('statementTimeoutMs rejects negative and non-integer budgets', async () => {
  for (const bad of [-1, 1.5, NaN]) {
    await assert.rejects(
      () => query('SELECT 1', [], { statementTimeoutMs: bad }),
      /positive integer/,
      `expected ${bad} to be refused`,
    );
  }
});

test('a positive budget passes validation and reaches the pool', async () => {
  // 127.0.0.1:5432 is not listening, so this fails on CONNECTION — which is
  // the proof that validation let it through rather than throwing first.
  await assert.rejects(
    () => query('SELECT 1', [], { statementTimeoutMs: 25_000 }),
    (err) => !/positive integer/.test(err.message),
  );
});
