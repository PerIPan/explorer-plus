// scripts/lib/profile-rank.test.mjs — run with `npm test`
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { splitBands, isDegenerate } from '../../src/lib/profile-rank.mjs';

const T = (id, lift, kev) => ({ attackId: id, lift, kevCount: kev, iocs: 0, reports: 0 });

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
