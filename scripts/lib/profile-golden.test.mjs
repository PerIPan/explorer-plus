// scripts/lib/profile-golden.test.mjs
// Requires DATABASE_URL. Not part of the no-DB CI gate — run from the ingest
// harness after an ATT&CK update, alongside the snapshot diff.
//
// This is the regression gate for the Threat Profile's whole premise: sectors
// are ranked by "lift" (how disproportionately a sector's groups use a
// technique vs. all groups). If a future ATT&CK ingest flattens that signal,
// every sector starts seeing the same Band B list and nothing else in the
// codebase would notice. These two tests notice.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import { MIN_GROUPS } from '../../src/lib/profile-rank.mjs';

const NEEDS_DB = !process.env.DATABASE_URL && 'requires DATABASE_URL — run from the ingest harness';

let pool;
before(() => {
  // Guarded: with DATABASE_URL unset, both tests below are skipped, so this must
  // not attempt a connection (or even construct a Pool that could surprise later).
  if (process.env.DATABASE_URL) pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
});

const SECTORS = ['defense','education','energy','financial','government','healthcare',
  'manufacturing','media','retail','technology','telecommunications','transportation'];

async function bandB(slug) {
  const { rows } = await pool.query(
    `SELECT t.attack_id FROM sector_technique_lift l
     JOIN techniques t ON t.id = l.technique_id
     WHERE l.sector_slug = $1 AND l.group_count >= $2
     ORDER BY l.lift DESC, t.attack_id LIMIT 6`, [slug, MIN_GROUPS]);
  return rows.map(r => r.attack_id).join(',');
}

test('every sector produces a distinct Band B, and all 12 are distinct', { skip: NEEDS_DB }, async () => {
  const seen = new Map();
  for (const slug of SECTORS) {
    const sig = await bandB(slug);
    assert.notEqual(sig, '', `${slug} produced an empty Band B — no technique clears the ${MIN_GROUPS}-group floor`);
    assert.ok(!seen.has(sig),
      `${slug} and ${seen.get(sig)} produce an identical Band B — the sector signal has flattened`);
    seen.set(sig, slug);
  }
  assert.equal(seen.size, 12, `expected 12 distinct lift-ranked lists, got ${seen.size}`);
});

test('CTI sightings cannot rank: ordering by iocs collapses the 12 sectors', { skip: NEEDS_DB }, async () => {
  // Documents WHY lift does the ORDER BY. If this ever stops collapsing, the
  // premise changed and the sort default should be revisited.
  //
  // The io-count aggregate is computed ONCE here, not per sector: technique_iocs
  // is ~680k rows, and the original per-sector LEFT JOIN re-aggregated all of it
  // 12 times (~1.7s). Hoisting it to a single GROUP BY plus an in-memory sort per
  // sector is equivalent — same ORDER BY COALESCE(n,0) DESC, attack_id, same
  // LIMIT 6 — and drops the whole test to sub-300ms.
  const { rows: ioRows } = await pool.query(
    `SELECT technique_id, count(*)::int AS n FROM technique_iocs GROUP BY 1`);
  const ioCounts = new Map(ioRows.map(r => [r.technique_id, r.n]));

  const sigs = new Set();
  for (const slug of SECTORS) {
    const { rows } = await pool.query(
      `SELECT t.id AS technique_id, t.attack_id FROM sector_technique_lift l
       JOIN techniques t ON t.id = l.technique_id
       WHERE l.sector_slug = $1`, [slug]);
    const sig = rows
      .sort((a, b) => (ioCounts.get(b.technique_id) ?? 0) - (ioCounts.get(a.technique_id) ?? 0)
        || (a.attack_id < b.attack_id ? -1 : 1))
      .slice(0, 6)
      .map(r => r.attack_id)
      .join(',');
    sigs.add(sig);
  }
  assert.equal(sigs.size, 1,
    `expected IOC-ranking to collapse all 12 sectors to one list, got ${sigs.size}`);
});
