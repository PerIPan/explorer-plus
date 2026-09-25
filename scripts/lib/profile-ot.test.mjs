import test from 'node:test';
import assert from 'node:assert/strict';

import {
  assetsAtLevel,
  groupLevelsByZone,
  resolveEffectiveAssets,
  describeSelection,
  emptyLevelKeys,
  OT_ZONE_ORDER,
} from '../../src/lib/profile-ot.mjs';

/* ────────────────────────────────────────────────────────────────────────────
 * Fixture
 *
 * The REAL placement, copied from production 2026-09-26 (`attack_assets` JOIN
 * `asset_purdue_placement`, 18 live rows, 0 revoked / 0 deprecated). Not an
 * invented shape: every count these tests assert — l1 8, l2 7, l3 7, l3_5 6,
 * l4 2, l5 0, and l2+l3 = 10 distinct rather than 14 — is a fact about the data
 * the engine actually ranks, and the point of pinning it here is that a change
 * to either the resolution rule or the placement data has to be noticed.
 * ──────────────────────────────────────────────────────────────────────────── */

const LEVELS = [
  { levelKey: 'l0', label: 'Physical Process', zone: 'ot', description: '', sortOrder: 0 },
  { levelKey: 'l1', label: 'Basic Control', zone: 'ot', description: '', sortOrder: 10 },
  { levelKey: 'l2', label: 'Supervisory Control', zone: 'ot', description: '', sortOrder: 20 },
  { levelKey: 'l3', label: 'Site Operations', zone: 'ot', description: '', sortOrder: 30 },
  { levelKey: 'l3_5', label: 'Industrial DMZ', zone: 'dmz', description: '', sortOrder: 35 },
  { levelKey: 'l4', label: 'Business Logistics', zone: 'it', description: '', sortOrder: 40 },
  { levelKey: 'l5', label: 'Enterprise IT', zone: 'it', description: '', sortOrder: 50 },
];

const A = (attackId, name, primaryLevel, spansLevels, isBoundary) => ({
  attackId,
  name,
  primaryLevel,
  spansLevels,
  isBoundary,
});

const ASSETS = [
  A('A0001', 'Workstation', 'l2', ['l2', 'l3'], false),
  A('A0002', 'Human-Machine Interface (HMI)', 'l2', ['l2'], false),
  A('A0003', 'Programmable Logic Controller (PLC)', 'l1', ['l1'], false),
  A('A0004', 'Remote Terminal Unit (RTU)', 'l1', ['l1'], false),
  A('A0005', 'Intelligent Electronic Device (IED)', 'l1', ['l1'], false),
  A('A0006', 'Data Historian', 'l3', ['l3', 'l3_5'], true),
  A('A0007', 'Control Server', 'l2', ['l2'], false),
  A('A0008', 'Application Server', 'l3', ['l3'], false),
  A('A0009', 'Data Gateway', 'l3_5', ['l2', 'l3', 'l3_5'], true),
  A('A0010', 'Safety Controller', 'l1', ['l1'], false),
  A('A0011', 'Virtual Private Network (VPN) Server', 'l3_5', ['l3_5'], true),
  A('A0012', 'Jump Host', 'l3_5', ['l3_5'], true),
  A('A0013', 'Field I/O', 'l0', ['l0', 'l1'], false),
  A('A0014', 'Routers', 'l3', ['l2', 'l3', 'l3_5', 'l4'], true),
  A('A0015', 'Switch', 'l2', ['l1', 'l2', 'l3'], false),
  A('A0016', 'Firewall', 'l3_5', ['l3', 'l3_5', 'l4'], true),
  A('A0017', 'Distributed Control System (DCS) Controller', 'l1', ['l1', 'l2'], false),
  A('A0018', 'Programmable Automation Controller (PAC)', 'l1', ['l1'], false),
];

const ids = (list) => list.map((a) => a.attackId);

test('assetsAtLevel: the measured per-level counts, over spansLevels', () => {
  assert.deepEqual(ids(assetsAtLevel(ASSETS, 'l0')), ['A0013']);
  assert.deepEqual(ids(assetsAtLevel(ASSETS, 'l1')), [
    'A0003', 'A0004', 'A0005', 'A0010', 'A0013', 'A0015', 'A0017', 'A0018',
  ]);
  assert.deepEqual(ids(assetsAtLevel(ASSETS, 'l2')), [
    'A0001', 'A0002', 'A0007', 'A0009', 'A0014', 'A0015', 'A0017',
  ]);
  assert.deepEqual(ids(assetsAtLevel(ASSETS, 'l3')), [
    'A0001', 'A0006', 'A0008', 'A0009', 'A0014', 'A0015', 'A0016',
  ]);
  assert.deepEqual(ids(assetsAtLevel(ASSETS, 'l3_5')), [
    'A0006', 'A0009', 'A0011', 'A0012', 'A0014', 'A0016',
  ]);
  assert.deepEqual(ids(assetsAtLevel(ASSETS, 'l4')), ['A0014', 'A0016']);
  assert.deepEqual(ids(assetsAtLevel(ASSETS, 'l5')), []);
});

test('assetsAtLevel: primary_level would silently drop over half of L3', () => {
  // The bug this rule exists to prevent, stated as a test rather than a
  // comment: filing assets by `primaryLevel` gives three, the honest answer is
  // seven, and two of the four missing ones (A0009, A0016) are boundary assets.
  const naive = ASSETS.filter((a) => a.primaryLevel === 'l3');
  assert.deepEqual(ids(naive), ['A0006', 'A0008', 'A0014']);
  assert.equal(assetsAtLevel(ASSETS, 'l3').length, 7);
});

test('emptyLevelKeys: l5 is the only level with no asset', () => {
  assert.deepEqual(emptyLevelKeys(LEVELS, ASSETS), ['l5']);
});

test('groupLevelsByZone: three zones, plant floor first, levels in sort order', () => {
  const groups = groupLevelsByZone(LEVELS, ASSETS);
  assert.deepEqual(groups.map((g) => g.zone), [...OT_ZONE_ORDER]);
  assert.deepEqual(groups[0].levels.map((l) => l.levelKey), ['l0', 'l1', 'l2', 'l3']);
  assert.deepEqual(groups[1].levels.map((l) => l.levelKey), ['l3_5']);
  assert.deepEqual(groups[2].levels.map((l) => l.levelKey), ['l4', 'l5']);
  // The empty level is still RETURNED — the view renders it disabled and says
  // why, rather than dropping a row the visitor came looking for.
  assert.equal(groups[2].levels[1].assets.length, 0);
});

test('groupLevelsByZone: an asset appears under every level it spans', () => {
  const groups = groupLevelsByZone(LEVELS, ASSETS);
  const appearances = groups
    .flatMap((g) => g.levels)
    .filter((l) => l.assets.some((a) => a.attackId === 'A0014'))
    .map((l) => l.levelKey);
  assert.deepEqual(appearances, ['l2', 'l3', 'l3_5', 'l4']);
});

test('resolveEffectiveAssets: a level resolves to its whole overlap set', () => {
  assert.deepEqual(ids(resolveEffectiveAssets(ASSETS, [], ['l3'])), [
    'A0001', 'A0006', 'A0008', 'A0009', 'A0014', 'A0015', 'A0016',
  ]);
});

test('resolveEffectiveAssets: two levels de-duplicate to 10, not 14', () => {
  const eff = resolveEffectiveAssets(ASSETS, [], ['l2', 'l3']);
  assert.equal(eff.length, 10);
  assert.deepEqual(ids(eff), [
    'A0001', 'A0002', 'A0006', 'A0007', 'A0008', 'A0009', 'A0014', 'A0015', 'A0016', 'A0017',
  ]);
});

test('resolveEffectiveAssets: an explicit pick already covered by a level is not counted twice', () => {
  const viaLevel = resolveEffectiveAssets(ASSETS, [], ['l3']);
  const withDuplicate = resolveEffectiveAssets(ASSETS, ['A0006'], ['l3']);
  assert.deepEqual(ids(withDuplicate), ids(viaLevel));
});

test('resolveEffectiveAssets: l5 alone resolves to nothing — the empty-selection state', () => {
  assert.deepEqual(resolveEffectiveAssets(ASSETS, [], ['l5']), []);
});

test('resolveEffectiveAssets: nothing selected resolves to nothing, never to everything', () => {
  // The failure that would hand a visitor who asked about their enterprise
  // network a full plant-floor briefing.
  assert.deepEqual(resolveEffectiveAssets(ASSETS, [], []), []);
});

test('describeSelection: reports the overlap it dropped', () => {
  const d = describeSelection(ASSETS, [], ['l2', 'l3'], LEVELS);
  assert.equal(d.memberships, 14);
  assert.equal(d.effectiveIds.length, 10);
  assert.equal(d.overlapDropped, 4);
  assert.deepEqual(d.viaLevels.map((v) => v.label), ['Supervisory Control', 'Site Operations']);
});

test('describeSelection: names what one level expanded to, and the boundary assets in it', () => {
  const d = describeSelection(ASSETS, [], ['l3'], LEVELS);
  assert.deepEqual(d.viaLevels[0].assetIds, [
    'A0001', 'A0006', 'A0008', 'A0009', 'A0014', 'A0015', 'A0016',
  ]);
  // A0006, A0009, A0014, A0016 — half of what "Site Operations" resolves to.
  assert.equal(d.boundaryCount, 4);
  assert.equal(d.overlapDropped, 0);
});

test('describeSelection: explicitOnly names the picks no chosen level covers', () => {
  const d = describeSelection(ASSETS, ['A0003', 'A0006'], ['l3'], LEVELS);
  assert.deepEqual(d.explicitOnly, ['A0003']);
  assert.equal(d.effectiveIds.length, 8);
});

test('describeSelection: all 18 assets is a valid selection with nothing dropped', () => {
  const all = ASSETS.map((a) => a.attackId);
  const d = describeSelection(ASSETS, all, [], LEVELS);
  assert.equal(d.effectiveIds.length, 18);
  assert.equal(d.memberships, 0);
  assert.equal(d.overlapDropped, 0);
  assert.equal(d.boundaryCount, 6);
});
