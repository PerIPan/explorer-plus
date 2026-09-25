// scripts/lib/profile-rank.test.mjs — run with `npm test`
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { splitBands, isDegenerate, MIN_GROUPS } from '../../src/lib/profile-rank.mjs';

// groupCount defaults to MIN_GROUPS so every pre-existing fixture clears the Band B
// floor unless a test overrides it to specifically exercise that floor.
const T = (id, lift, kev, groupCount = MIN_GROUPS) =>
  ({ attackId: id, lift, kevCount: kev, iocs: 0, reports: 0, groupCount });

test('splitBands: Band A is the metric sort, Band B is lift with A excluded', () => {
  const pool = [T('T1', 9, 1), T('T2', 2, 50), T('T3', 5, 20), T('T4', 1, 99)];
  const { bandA, bandB } = splitBands(pool, 'kev', 2);
  assert.deepEqual(bandA.map(t => t.attackId), ['T4', 'T2']);
  assert.deepEqual(bandB.map(t => t.attackId), ['T1', 'T3']);
});

test('splitBands: no technique appears in both bands', () => {
  const pool = [T('T1', 9, 99), T('T2', 2, 50), T('T3', 5, 20)];
  const { bandA, bandB } = splitBands(pool, 'kev', 2);
  const overlap = bandA.filter(a => bandB.some(b => b.attackId === a.attackId));
  assert.equal(overlap.length, 0);
});

test('isDegenerate: fewer than 6 distinct lift values means no defensible ranking', () => {
  assert.equal(isDegenerate([T('A',1,0), T('B',1,0), T('C',1,0)]), true);
  assert.equal(isDegenerate([T('A',1,0), T('B',2,0), T('C',3,0), T('D',4,0), T('E',5,0), T('F',6,0)]), false);
});

test('isDegenerate: an empty pool is degenerate, not a crash', () => {
  assert.equal(isDegenerate([]), true);
});

test('splitBands: candidates below the group floor never enter Band B, even when they would otherwise win on lift', () => {
  const pool = [
    T('A1', 1, 100, 3),  // Band A pick (top by kev)
    T('B1', 10, 1, 1),   // highest lift, but groupCount 1 < MIN_GROUPS -- excluded
    T('B2', 9, 1, 2),    // groupCount 2 < MIN_GROUPS -- excluded
    T('B3', 8, 1, 1),    // groupCount 1 < MIN_GROUPS -- excluded
  ];
  const { bandA, bandB, bandBShort } = splitBands(pool, 'kev', 1);
  assert.deepEqual(bandA.map(t => t.attackId), ['A1']);
  assert.deepEqual(bandB, [], 'every remaining candidate is below the floor, so Band B must be empty, not populated with noise');
  assert.equal(bandBShort, true);
});

test('splitBands: bandBShort is true when fewer than 6 candidates clear the floor (default n)', () => {
  // Six distinct-kev fillers unambiguously fill the default n=6 Band A, so the pool
  // isn't small enough for Band A itself to swallow the Band B candidates below.
  const pool = [
    T('F1', 0, 100, 5), T('F2', 0, 90, 5), T('F3', 0, 80, 5),
    T('F4', 0, 70, 5), T('F5', 0, 60, 5), T('F6', 0, 50, 5),
    T('B1', 10, 1, 5),  // clears the floor -- the only real Band B candidate
    T('B2', 9, 1, 1),   // below the floor
    T('B3', 8, 1, 2),   // below the floor
  ];
  const { bandB, bandBShort } = splitBands(pool, 'kev');
  assert.deepEqual(bandB.map(t => t.attackId), ['B1']);
  assert.equal(bandBShort, true);
});

test('splitBands: a full Band B (>= n candidates clear the floor) is not flagged short', () => {
  // Distinct kev values for the Band A picks so n=2 unambiguously takes A1+A2,
  // leaving both T1/T2 eligible for Band B (no kev ties to fight over the A/B boundary).
  const pool = [
    T('A1', 1, 100, 3), T('A2', 1, 90, 3),
    T('T1', 9, 1, 3), T('T2', 5, 1, 4),
  ];
  const { bandB, bandBShort } = splitBands(pool, 'kev', 2);
  assert.deepEqual(bandB.map(t => t.attackId), ['T1', 'T2']);
  assert.equal(bandBShort, false);
});

test('splitBands: ties on lift break deterministically by attackId', () => {
  // Four distinct-kev fillers unambiguously fill Band A (n=4), leaving the three
  // kev=1/lift=5 ties entirely outside Band A to exercise the Band B tie-break.
  const pool = [
    T('F1', 0, 100, 3), T('F2', 0, 90, 3), T('F3', 0, 80, 3), T('F4', 0, 70, 3),
    T('Z', 5, 1, 3), T('A', 5, 1, 3), T('M', 5, 1, 3),
  ];
  const { bandA, bandB } = splitBands(pool, 'kev', 4);
  assert.deepEqual(bandA.map(t => t.attackId), ['F1', 'F2', 'F3', 'F4']);
  assert.deepEqual(bandB.map(t => t.attackId), ['A', 'M', 'Z']);
});
