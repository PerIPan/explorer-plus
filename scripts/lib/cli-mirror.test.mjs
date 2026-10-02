import { test } from 'node:test';
import assert from 'node:assert/strict';
import { collisions } from './cli-mirror.mjs';
import { commandFor, invocationFor } from '../../src/lib/cli-command.mjs';

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


// ── the path -> command rule ──────────────────────────────────────────────────
// Shared by scripts/gen-cli.mjs and src/views/Cli.tsx since the /cli page
// started rendering commands. `check:cli` already exercises it over all 83 real
// entries; these pin the shapes that are easy to get wrong and rare enough in
// the catalogue that a regression could slip past.

test('a plain path is all words, no positionals', () => {
  assert.deepEqual(commandFor({ path: '/techniques' }), { words: ['techniques'], positionals: [] });
});

test('a placeholder becomes a positional, not a word', () => {
  const out = commandFor({ path: '/techniques/{attackId}' });
  assert.deepEqual(out.words, ['techniques']);
  assert.deepEqual(out.positionals, [{ name: 'attackId', catchAll: false, index: 2 }]);
});

test('two placeholders keep their order and 1-based segment index', () => {
  const out = commandFor({ path: '/applications/{vendor}/{product}' });
  assert.deepEqual(out.words, ['applications']);
  assert.deepEqual(out.positionals.map((p) => [p.name, p.index]), [['vendor', 2], ['product', 3]]);
});

test('a catch-all placeholder is flagged', () => {
  const [p] = commandFor({ path: '/compliance/{...slug}' }).positionals;
  assert.equal(p.catchAll, true);
  assert.equal(p.name, 'slug');
});

test('words and placeholders interleave without reordering', () => {
  const out = commandFor({ path: '/feed/{kind}/items' });
  assert.deepEqual(out.words, ['feed', 'items']);
  assert.deepEqual(out.positionals.map((p) => p.name), ['kind']);
});

test('invocationFor takes the binary name rather than hardcoding one', () => {
  const entry = { path: '/techniques/{attackId}' };
  assert.equal(invocationFor(entry, 'mitrex'), 'mitrex techniques attackId');
  // The name is not settled; a rename must not need an edit here.
  assert.equal(invocationFor(entry, 'zzz'), 'zzz techniques attackId');
});
