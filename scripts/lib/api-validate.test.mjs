/**
 * The shared query-parameter validators in app/api/v1/lib/validate.ts.
 *
 * These three exist because each of them replaced a pattern that returned the
 * WRONG ANSWER or a 500 to an unauthenticated caller on the live API. They are
 * pure functions, so they belong under test.
 *
 * The module is TypeScript, which `node --test` cannot import on its own: Node
 * strips the types fine, but a `.ts` file's extensionless relative import does
 * not resolve. The hook below repairs exactly that, the same way
 * scripts/gen-cli.mjs reads the API catalogue.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import { existsSync, readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
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
const { boolQueryParam, sinceToIso, sortColumn, boolParam } = await import(
  pathToFileURL(join(ROOT, 'app/api/v1/lib/validate.ts')).href
);

test('a boolean query param is true only for 1 and true', () => {
  /* `z.coerce.boolean()` is Boolean(input), so every non-empty string was
     truthy: `?include_deprecated=false` meant TRUE. On production that turned
     a request to EXCLUDE revoked techniques into one that included them —
     475 rows became 679, with a 200 and no sign the opposite had been served.
     The site's own /open-apis Run button offers `true` and `false` as the only
     two choices for a boolean param, so `false` was two clicks into it. */
  for (const on of ['1', 'true']) assert.equal(boolQueryParam.parse(on), true, on);
  for (const off of ['false', '0', 'no', 'off', '', 'TRUE', undefined]) {
    assert.equal(boolQueryParam.parse(off), false, String(off));
  }
  // Must agree with the raw-.get() helper, or the two paths mean different things.
  for (const v of ['1', 'true', 'false', '0', '']) {
    assert.equal(boolQueryParam.parse(v), boolParam(v), v);
  }
});

test('since= never yields a timestamp Postgres cannot parse', () => {
  /* `new Date(x)` guarded only by isNaN is not enough: `+275760-01-01` is a
     VALID Date at the edge of the range, and its toISOString() is an
     extended-year literal that reached the driver and 500'd four routes. */
  assert.equal(sinceToIso('+275760-01-01'), null);
  assert.equal(sinceToIso('-271821-04-20'), null);
  assert.equal(sinceToIso('275760-09-13T00:00:00.000Z'), null);
  // Garbage is ignored rather than rejected, which is the behaviour callers have.
  assert.equal(sinceToIso('banana'), null);
  assert.equal(sinceToIso(''), null);
  assert.equal(sinceToIso(undefined), null);
  assert.equal(sinceToIso(null), null);
  // Real dates still work, and come back as something Postgres accepts.
  assert.equal(sinceToIso('2024-01-01'), '2024-01-01T00:00:00.000Z');
  assert.match(sinceToIso('2024-06-01T12:30:00Z'), /^2024-06-01T12:30:00\.000Z$/);
  for (const iso of [sinceToIso('2024-01-01'), sinceToIso('1999-12-31')]) {
    assert.match(iso, /^\d{4}-\d{2}-\d{2}T/, 'year must be four plain digits');
  }
});

test('a sort key cannot reach ORDER BY through the prototype chain', () => {
  /* `MAP[key] ?? fallback` looks safe and is not: MAP['constructor'] resolves
     to a function, which is truthy, so `??` never fires and the function was
     interpolated into the ORDER BY text — an unauthenticated 500 on
     /techniques and /external-actors. */
  const map = { name: 't.name', modified: 't.stix_modified' };
  assert.equal(sortColumn(map, 'name', 't.id'), 't.name');
  assert.equal(sortColumn(map, 'modified', 't.id'), 't.stix_modified');
  for (const hostile of ['constructor', '__proto__', 'toString', 'valueOf', 'hasOwnProperty']) {
    assert.equal(sortColumn(map, hostile, 't.id'), 't.id', hostile);
  }
  assert.equal(sortColumn(map, undefined, 't.id'), 't.id');
  assert.equal(sortColumn(map, '', 't.id'), 't.id');
  // The old expression, kept here to show the defect is real and not theoretical.
  assert.notEqual(map['constructor'] ?? 't.id', 't.id');
});

test('no v1 route resolves a sort key by indexing an object literal', () => {
  /* The helper above is only worth having if every route uses it. It was added
     for /techniques and /external-actors and /feed/reports was missed — the same
     `?sortBy=constructor` 500 stayed live there. This walks the route files so
     the next hand-rolled lookup fails here instead of in production.

     /applications is the one exemption: its `sort` is a z.enum, so zod 400s an
     unknown key before the lookup runs. An exemption needs that same proof. */
  const EXEMPT = new Set(['app/api/v1/applications/route.ts']);
  const UNSAFE = /\[\s*sort[A-Za-z]*\s*(?:\?\?[^\]]*)?\]\s*\?\?/;
  const routes = execFileSync(
    'git', ['ls-files', '-co', '--exclude-standard', 'app/api/v1'],
    { cwd: ROOT, encoding: 'utf8' },
  ).split('\n').filter((p) => p.endsWith('/route.ts'));
  assert.ok(routes.length > 50, `expected the whole v1 surface, got ${routes.length}`);

  const offenders = routes.filter(
    (p) => !EXEMPT.has(p) && UNSAFE.test(readFileSync(join(ROOT, p), 'utf8')),
  );
  assert.deepEqual(offenders, [], `use sortColumn() in: ${offenders.join(', ')}`);
});
