import test from 'node:test';
import assert from 'node:assert/strict';

import {
  TAXONOMY_ITEMS,
  INVENTORY_FIELDS,
  INVENTORY_STEPS,
  ICS_ASSET_NAMES,
  SECTORS,
  itemsForAsset,
  assetsForItems,
  sectorTable,
  sectorCoverage,
  otProfileHref,
  assetsForCriticality,
} from '../../src/lib/cisa-ot-inventory.mjs';

/* The crosswalk is curation, so these tests guard its INTEGRITY, not its
 * judgements: every row is well-formed, the match kind agrees with the asset
 * list, and the counts match the PDF's tables (oil & gas 24 rows across
 * Tables 3-5, electricity 26 across 7-9, water 25 across 11-13), so a row lost
 * or duplicated in an edit fails here rather than on the page. */

const ASSET_IDS = new Set(Object.keys(ICS_ASSET_NAMES));

test('there are exactly the 18 ATT&CK ICS assets, A0001-A0018', () => {
  const expected = Array.from({ length: 18 }, (_, i) => `A${String(i + 1).padStart(4, '0')}`);
  assert.deepEqual([...ASSET_IDS].sort(), expected);
});

test('row counts per sector match the PDF tables', () => {
  const count = (s) => TAXONOMY_ITEMS.filter((it) => it.sector === s).length;
  assert.equal(count('oil-gas'), 24);
  assert.equal(count('electricity'), 26);
  assert.equal(count('water'), 25);
});

test('keys are unique and prefixed with their sector', () => {
  const keys = TAXONOMY_ITEMS.map((it) => it.key);
  assert.equal(new Set(keys).size, keys.length);
  for (const it of TAXONOMY_ITEMS) assert.ok(it.key.startsWith(`${it.sector}:`), it.key);
});

test('match kind agrees with the asset list', () => {
  for (const it of TAXONOMY_ITEMS) {
    if (it.match === 'none') assert.equal(it.assets.length, 0, it.key);
    else assert.ok(it.assets.length > 0, it.key);
    for (const a of it.assets) assert.ok(ASSET_IDS.has(a), `${it.key}: ${a}`);
    assert.equal(new Set(it.assets).size, it.assets.length, `${it.key}: duplicate asset`);
  }
});

test('every row carries a rationale and a known criticality', () => {
  for (const it of TAXONOMY_ITEMS) {
    assert.ok(it.rationale && it.rationale.length > 10, it.key);
    assert.ok(['high', 'medium', 'low'].includes(it.criticality), it.key);
    assert.ok(SECTORS.some((s) => s.key === it.sector), it.key);
  }
});

test('Appendix A has 32 fields: 14 high, 8 medium, 10 low', () => {
  assert.equal(INVENTORY_FIELDS.length, 32);
  const by = (p) => INVENTORY_FIELDS.filter((f) => f.priority === p).length;
  assert.deepEqual([by('high'), by('medium'), by('low')], [14, 8, 10]);
});

test('five inventory steps, numbered 1-5', () => {
  assert.deepEqual(INVENTORY_STEPS.map((s) => s.n), [1, 2, 3, 4, 5]);
});

test('itemsForAsset: protection relays land on IED, sorted sector then criticality', () => {
  const ied = itemsForAsset('A0005');
  assert.ok(ied.length > 0);
  assert.ok(ied.every((it) => it.assets.includes('A0005')));
  assert.equal(ied[0].key, 'electricity:protection-relays');
});

test('itemsForAsset: an asset no CISA row reaches returns an empty list', () => {
  // Jump Host and VPN Server sit in the DMZ; none of CISA's example rows names them.
  assert.deepEqual(itemsForAsset('A0012'), []);
  assert.deepEqual(itemsForAsset('A0011'), []);
});

test('assetsForItems de-duplicates and sorts', () => {
  const rows = TAXONOMY_ITEMS.filter((it) => it.key === 'water:ot-comms' || it.key === 'water:switches');
  assert.deepEqual(assetsForItems(rows), ['A0009', 'A0014', 'A0015']);
});

test('sectorTable keeps criticality order and drops nothing', () => {
  for (const s of SECTORS) {
    const table = sectorTable(s.key);
    assert.deepEqual(table.map((g) => g.criticality), ['high', 'medium', 'low']);
    const n = table.flatMap((g) => g.categories.flatMap((c) => c.items)).length;
    assert.equal(n, TAXONOMY_ITEMS.filter((it) => it.sector === s.key).length);
  }
});

test('sectorCoverage adds up', () => {
  for (const s of SECTORS) {
    const c = sectorCoverage(s.key);
    assert.equal(c.direct + c.partial + c.none, c.total);
  }
});

test('otProfileHref writes the ICS domain and a sorted CSV of assets', () => {
  assert.equal(otProfileHref(['A0005', 'A0003']), '/profile?assets=A0003%2CA0005&domain=ics-attack');
});

test('assetsForCriticality: oil & gas high-criticality rows reach ESD/safety, DCS, PLC and field I/O', () => {
  assert.deepEqual(assetsForCriticality('oil-gas', 'high'), ['A0003', 'A0010', 'A0013', 'A0017']);
});

test('assetsForCriticality: no criticality level reaches more than half the assets', () => {
  // The reason links are per criticality, not per sector: lift needs a
  // selection well short of all 18.
  for (const s of SECTORS) for (const c of ['high', 'medium', 'low']) {
    assert.ok(assetsForCriticality(s.key, c).length <= 9, `${s.key}/${c}`);
  }
});
