#!/usr/bin/env node
// scripts/verify-ics-assets.mjs
//
// Assertion script for the ICS assets + Purdue layer. The repo has no test
// runner (`npm test` is a stub), so structural invariants are checked the same
// way scripts/check-catchall-threshold.mjs does it: query, assert, exit non-zero.
//
// Covers the invariants a CHECK constraint cannot express — Postgres rejects
// subqueries in CHECK, so anything about cardinality, completeness, or
// cross-table agreement has to live here.
//
// Usage:
//   DATABASE_URL=... node --experimental-strip-types scripts/verify-ics-assets.mjs
//
// Exit 0 = all invariants hold. Exit 1 = at least one failed.

import pg from 'pg';

const DATABASE_URL = process.env.DATABASE_URL || process.env.POSTGRES_URL;
if (!DATABASE_URL) {
  console.error('DATABASE_URL (or POSTGRES_URL) required');
  process.exit(1);
}

const failures = [];
const warnings = [];
const notes = [];

function check(label, ok, detail) {
  if (ok) console.log(`  PASS  ${label}`);
  else { console.log(`  FAIL  ${label}${detail ? ` — ${detail}` : ''}`); failures.push(label); }
}
function warn(label, detail) {
  console.log(`  WARN  ${label}${detail ? ` — ${detail}` : ''}`);
  warnings.push(label);
}

const pool = new pg.Pool({ connectionString: DATABASE_URL, max: 2 });

try {
  const reg = await import('../src/lib/purdue-registry.ts');

  // --- 1. Registry is internally consistent ------------------------------
  console.log('\nregistry');
  const regErrors = reg.validateRegistry();
  check('src/lib/purdue-registry.ts validates', regErrors.length === 0, regErrors.join('; '));

  // --- 2. Curated tables match the registry ------------------------------
  console.log('\ncurated layer');
  const levels = await pool.query('SELECT count(*)::int AS n FROM purdue_levels');
  check(`purdue_levels = ${reg.PURDUE_LEVELS.length}`,
    levels.rows[0].n === reg.PURDUE_LEVELS.length, `found ${levels.rows[0].n}`);

  const rules = await pool.query('SELECT count(*)::int AS n FROM purdue_flow_rules');
  check(`purdue_flow_rules = ${reg.PURDUE_FLOW_RULES.length}`,
    rules.rows[0].n === reg.PURDUE_FLOW_RULES.length, `found ${rules.rows[0].n}`);

  // Every ordered pair present — the design commits to an explicit matrix,
  // not "absent means denied".
  const missingPairs = await pool.query(
    `SELECT a.level_key AS f, b.level_key AS t
       FROM purdue_levels a CROSS JOIN purdue_levels b
      WHERE a.level_key <> b.level_key
        AND NOT EXISTS (SELECT 1 FROM purdue_flow_rules r
                         WHERE r.from_level = a.level_key AND r.to_level = b.level_key)`,
  );
  check('flow-rule matrix is complete', missingPairs.rowCount === 0,
    missingPairs.rows.map((r) => `${r.f}->${r.t}`).join(', '));

  const placements = await pool.query('SELECT count(*)::int AS n FROM asset_purdue_placement');
  check(`asset_purdue_placement = ${reg.ASSET_PLACEMENTS.length}`,
    placements.rows[0].n === reg.ASSET_PLACEMENTS.length, `found ${placements.rows[0].n}`);

  // --- 3. Assets ---------------------------------------------------------
  console.log('\nassets');
  const assets = await pool.query(
    "SELECT count(*)::int AS n FROM attack_assets WHERE NOT is_revoked AND NOT is_deprecated",
  );
  check('attack_assets has rows', assets.rows[0].n > 0, `found ${assets.rows[0].n}`);
  notes.push(`live assets: ${assets.rows[0].n}`);

  // Every live asset must carry a curated placement. This is the forward guard
  // that fires when a MITRE release adds an asset nobody has placed yet.
  const unplaced = await pool.query(
    `SELECT a.attack_id, a.name FROM attack_assets a
      WHERE NOT a.is_revoked AND NOT a.is_deprecated
        AND NOT EXISTS (SELECT 1 FROM asset_purdue_placement p WHERE p.asset_id = a.id)`,
  );
  check('every live asset has a Purdue placement', unplaced.rowCount === 0,
    unplaced.rows.map((r) => `${r.attack_id} ${r.name}`).join(', '));

  // Reverse guard: curation describing an asset that no longer exists.
  const orphaned = await pool.query(
    `SELECT p.attack_id FROM asset_purdue_placement p
      WHERE NOT EXISTS (SELECT 1 FROM attack_assets a WHERE a.id = p.asset_id)`,
  );
  check('no orphaned placements', orphaned.rowCount === 0,
    orphaned.rows.map((r) => r.attack_id).join(', '));

  // The composite FK already prevents drift, but assert it so a future schema
  // change that drops the constraint is caught rather than silently tolerated.
  const drifted = await pool.query(
    `SELECT p.attack_id AS placement_id, a.attack_id AS asset_id
       FROM asset_purdue_placement p JOIN attack_assets a ON a.id = p.asset_id
      WHERE p.attack_id <> a.attack_id`,
  );
  check('placement.attack_id agrees with attack_assets.attack_id', drifted.rowCount === 0);

  // --- 4. spans_levels referential integrity -----------------------------
  // The spans_valid CHECK compares against a literal vocabulary, which cannot
  // drift from purdue_levels on its own. An array column cannot carry an FK, so
  // this cross-table assertion is the drift check — deliberately here rather
  // than in a runtime trigger on an 18-row, write-once table.
  console.log('\nspans_levels integrity');
  const badSpans = await pool.query(
    `SELECT p.attack_id, s AS bad_level
       FROM asset_purdue_placement p, unnest(p.spans_levels) AS s
      WHERE NOT EXISTS (SELECT 1 FROM purdue_levels l WHERE l.level_key = s)`,
  );
  check('every spans_levels element exists in purdue_levels', badSpans.rowCount === 0,
    badSpans.rows.map((r) => `${r.attack_id}:${r.bad_level}`).join(', '));

  const badPrimary = await pool.query(
    `SELECT attack_id FROM asset_purdue_placement WHERE NOT (primary_level = ANY(spans_levels))`,
  );
  check('primary_level is always within spans_levels', badPrimary.rowCount === 0,
    badPrimary.rows.map((r) => r.attack_id).join(', '));

  // is_boundary is generated, so this asserts the definition rather than the data.
  const boundary = await pool.query(
    `SELECT count(*)::int AS n FROM asset_purdue_placement WHERE is_boundary`,
  );
  const expectedBoundary = reg.ASSET_PLACEMENTS.filter(reg.isBoundaryAsset).length;
  check(`boundary assets = ${expectedBoundary} (registry and DB agree)`,
    boundary.rows[0].n === expectedBoundary, `DB says ${boundary.rows[0].n}`);

  // --- 5. Technique edges ------------------------------------------------
  console.log('\ntechnique edges');
  const icsTech = await pool.query(
    "SELECT count(*)::int AS n FROM techniques WHERE domain = 'ics-attack'",
  );
  const edges = await pool.query('SELECT count(*)::int AS n FROM asset_techniques');

  if (icsTech.rows[0].n === 0) {
    // Distinguish "database is stale" from "ingest is broken" — otherwise a
    // fresh clone looks like a failure when it is only unseeded.
    warn('no ics-attack techniques in this database',
      'asset_techniques cannot resolve; run the ATT&CK seed/update for ics-attack, then re-run the backfill');
  } else {
    check('asset_techniques has rows', edges.rows[0].n > 0, `found ${edges.rows[0].n}`);
    const dangling = await pool.query(
      `SELECT count(*)::int AS n FROM asset_techniques at
         JOIN techniques k ON k.id = at.technique_id
        WHERE k.domain <> 'ics-attack'`,
    );
    check('all asset_techniques point at ics-attack techniques', dangling.rows[0].n === 0,
      `${dangling.rows[0].n} edges reference a non-ICS technique`);
  }
  notes.push(`ics techniques: ${icsTech.rows[0].n}, asset_techniques: ${edges.rows[0].n}`);

  // --- summary -----------------------------------------------------------
  console.log('\n' + '-'.repeat(60));
  notes.forEach((n) => console.log(`  ${n}`));
  if (warnings.length) console.log(`  ${warnings.length} warning(s)`);
  if (failures.length) {
    console.error(`\nFAILED: ${failures.length} invariant(s) violated:\n  - ${failures.join('\n  - ')}`);
    process.exitCode = 1;
  } else {
    console.log('\nAll invariants hold.');
  }
} catch (err) {
  console.error('verify-ics-assets error:', err instanceof Error ? err.message : err);
  process.exitCode = 1;
} finally {
  await pool.end();
}
