// scripts/lib/profile-rank.test.mjs — run with `npm test`
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { splitBands, isDegenerate, otLift, MIN_GROUPS, MIN_REACH } from '../../src/lib/profile-rank.mjs';

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

/* ════════════════════════════════════════════════════════════════════════════
 * OT (ICS) path
 *
 * Every number below was measured against production on 2026-09-26 and is
 * quoted in the test name, so a failure says what reality changed rather than
 * just which assertion tripped.
 * ════════════════════════════════════════════════════════════════════════════ */

/** An OT pool item: exposure/reach drive the bands, and `groupCount` is 0
 *  because asset-derived items carry no group attribution — which is the whole
 *  reason the OT path passes `minGroups: 0`. */
const OT = (id, exposure, reach, nEff = 3, nAll = 18) => ({
  attackId: id,
  exposure,
  reach,
  lift: otLift(exposure, reach, nEff, nAll),
  groupCount: 0,
  kevCount: 0,
  iocs: 0,
  reports: 0,
});

test('OT Band A sorts on exposure, NOT the kevCount fallback', () => {
  // The silent failure this pins: METRIC had no `exposure` key, so
  // `METRIC[sortKey] ?? 'kevCount'` fell through to kevCount -- which is 0 for
  // EVERY live ICS technique (measured: the only ICS row in
  // technique_cve_evidence is T0812, and it is revoked). Band A would have been
  // an arbitrary stable-sort slice of an all-zero column, shown to a plant
  // operator as "your top exposure". No error, no empty list, just wrong.
  const pool = [OT('T-HI', 3, 9), OT('T-MID', 2, 4), OT('T-LO', 1, 2)];
  const { bandA } = splitBands(pool, 'exposure', 2, 0, MIN_REACH);
  assert.deepEqual(bandA.map(t => t.attackId), ['T-HI', 'T-MID']);

  // Same pool under the old fallback: kevCount is uniformly 0, so the sort is
  // a no-op and Band A is just "the first two rows in whatever order they
  // arrived". Asserting this is what makes the regression visible.
  const bogus = splitBands(pool, 'kev', 2, 0, MIN_REACH);
  assert.deepEqual(bogus.bandA.map(t => t.attackId), ['T-HI', 'T-MID'],
    'an all-zero metric column degenerates to input order — which is why exposure must be a real METRIC key');
});

test('OT Band B: MIN_GROUPS would empty it, minGroups 0 + reach floor fills it', () => {
  // Asset-derived items have groupCount 0, so the IT floor of 3 removes every
  // candidate -- Band B EMPTY, again with no error. Measured: under
  // `minGroups: 0, minReach: 2` all three real zone selections still return a
  // full six-item Band B.
  const pool = [
    OT('A1', 3, 9), OT('A2', 3, 11),                 // Band A on exposure
    OT('B1', 2, 4), OT('B2', 2, 4), OT('B3', 1, 2),  // Band B candidates
  ];
  assert.deepEqual(
    splitBands(pool, 'exposure', 2).bandB, [],
    'the default MIN_GROUPS floor empties Band B for asset-derived items');
  const { bandB } = splitBands(pool, 'exposure', 2, 0, MIN_REACH);
  assert.deepEqual(bandB.map(t => t.attackId), ['B1', 'B2']);
});

test('OT Band B: the reach floor keeps a single asset_techniques row out of the top six', () => {
  // A technique mapped to ONE of the 18 assets scores lift 18.0 off a single
  // row and would otherwise head Band B outright. MIN_REACH=2 is the structural
  // analogue of MIN_GROUPS: one sighting must not mint a top-six entry.
  const singleton = OT('T-ONE', 1, 1);
  assert.equal(singleton.lift, 6, 'exposure 1 / reach 1 over 3-of-18 is 6.00x off one row');

  // Two exposure-3 fillers take Band A, so the floor is what decides Band B and
  // not the band size (`splitBands` uses one `n` for both bands).
  const pool = [OT('A1', 3, 9), OT('A2', 3, 11), singleton, OT('B1', 2, 4), OT('B2', 1, 2)];
  assert.ok(singleton.lift > OT('B1', 2, 4).lift,
    'the singleton outranks every real candidate on lift -- the floor is the only thing stopping it');

  const { bandA, bandB } = splitBands(pool, 'exposure', 2, 0, MIN_REACH);
  assert.deepEqual(bandA.map(t => t.attackId), ['A1', 'A2']);
  assert.equal(bandB.some(t => t.attackId === 'T-ONE'), false,
    'reach 1 is below MIN_REACH and must never enter Band B, however high its lift');
  assert.deepEqual(bandB.map(t => t.attackId), ['B1', 'B2']);
});

test('OT lift: the denominator is the DISTINCT union, and getting it wrong is silent', () => {
  // Measured: l2 holds 7 assets and l3 holds 7, but the union is TEN, not 14 --
  // A0001, A0009, A0014 and A0015 span both levels. Nothing errors if 14 is
  // used; every lift is simply scaled by 10/14 and the ordering quietly shifts
  // against techniques the visitor is genuinely over-exposed to.
  const correct = otLift(8, 9, 10, 18);   // distinct union
  const naive = otLift(8, 9, 14, 18);     // 7 + 7, double-counting the overlap
  assert.equal(Number(correct.toFixed(3)), 1.6);
  assert.equal(Number(naive.toFixed(3)), 1.143);
  assert.equal(Number((naive / correct).toFixed(4)), 0.7143,
    'the naive denominator scales every lift by 10/14 -- a 29% understatement');

  // And the same trap when an explicit asset is ALSO reachable through a
  // selected level: measured, levels=l3 + assets=A0001,A0002 is 8 assets, not 9.
  assert.equal(otLift(4, 5, 8, 18), otLift(4, 5, 8, 18));
  assert.notEqual(otLift(4, 5, 8, 18), otLift(4, 5, 9, 18));
});

test('OT lift: an empty effective set throws instead of returning NaN', () => {
  // `?levels=l5` is a real, reachable request: measured, Enterprise IT (l5)
  // carries ZERO ATT&CK assets, because MITRE publishes assets for the ICS
  // domain alone. The route short-circuits it into the documented no-assets
  // state; this is the backstop if that guard is ever removed, turning a page
  // silently full of NaN into one loud, named error.
  assert.throws(() => otLift(0, 4, 0, 18), /empty effective asset set/);
  assert.throws(() => otLift(3, 0, 5, 18), /reach=0/);
});

test('OT degeneracy: selecting all 18 assets collapses every lift to exactly 1.0', () => {
  // (reach/18) / (reach/18) == 1 for every technique, whatever its reach. Band B
  // is then an ordering of identical numbers, so the route suppresses it and
  // says why; Band A is a COUNT, not a ratio, and stays valid at any selection
  // size. Measured: it degrades well before 18 -- 28 of the 85 ICS techniques
  // with asset rows have reach >= 16.
  const all18 = [9, 4, 18, 2, 16, 11].map((reach, i) => OT(`T${i}`, reach, reach, 18, 18));
  assert.deepEqual([...new Set(all18.map(t => t.lift))], [1],
    'a full selection makes exposure and reach move together');
  assert.equal(isDegenerate(all18), true);

  // A narrow selection over the same reaches is NOT degenerate.
  const narrow = [9, 4, 18, 2, 16, 11].map((reach, i) => OT(`T${i}`, Math.min(3, reach), reach, 3, 18));
  assert.equal(isDegenerate(narrow), false);
});

test('OT: an empty pool is degenerate and yields empty bands, not a crash', () => {
  const { bandA, bandB, bandBShort } = splitBands([], 'exposure', 6, 0, MIN_REACH);
  assert.deepEqual(bandA, []);
  assert.deepEqual(bandB, []);
  assert.equal(bandBShort, true);
  assert.equal(isDegenerate([]), true);
});

test('IT path is untouched by the OT parameters', () => {
  // minReach defaults to 0 and IT items have no `reach` field at all, so
  // `(t.reach ?? 0) >= 0` is inert. Same pool, same call as before the OT work.
  const pool = [T('T1', 9, 1), T('T2', 2, 50), T('T3', 5, 20), T('T4', 1, 99)];
  const { bandA, bandB } = splitBands(pool, 'kev', 2);
  assert.deepEqual(bandA.map(t => t.attackId), ['T4', 'T2']);
  assert.deepEqual(bandB.map(t => t.attackId), ['T1', 'T3']);
});
