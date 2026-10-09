/**
 * check-fair-cam-coverage.mjs
 * READ-ONLY. Lists D3FEND countermeasures and ATT&CK mitigations in the
 * database that src/lib/fair-cam-mappings.mjs does not classify yet.
 *
 * Why it exists: the weekly D3FEND sync and the ATT&CK update write new ids
 * straight into defensive_mappings / mitigations. Until someone classifies
 * them, the coverage API files a new D3FEND id under its tactic's default
 * function (flagged "default rule, not reviewed") and a new mitigation under
 * "unclassified". This script is how someone finds them. Run it after
 * scripts/update-attack.mjs or a D3FEND sync (docs/mitre_update.md).
 *
 * Usage: DATABASE_URL=... node scripts/check-fair-cam-coverage.mjs
 * Exit 1 when an Enterprise/ICS mitigation or any D3FEND id is unclassified,
 * or when a classified id is no longer in the database (a dead link).
 * Mobile and ATLAS mitigations are reported but expected (not classified by
 * design yet).
 */

import pg from 'pg';
import { D3FEND_TO_FAIR_CAM, MITIGATION_TO_FAIR_CAM } from '../src/lib/fair-cam-mappings.mjs';

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL environment variable is required');
  process.exit(2);
}

const isProduction = /neon|vercel/.test(process.env.DATABASE_URL);
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  max: 1,
  ssl: isProduction ? { rejectUnauthorized: true } : undefined,
  // Belt and braces: the session cannot write even if this file ever tried to.
  options: '-c default_transaction_read_only=on',
});

try {
  const [d3, mit, mitAll] = await Promise.all([
    pool.query(`SELECT d3fend_id AS id, MIN(d3fend_tactic) AS tactic, MIN(d3fend_name) AS name
                FROM defensive_mappings WHERE d3fend_id ~ '^D3-' GROUP BY d3fend_id ORDER BY d3fend_id`),
    pool.query(`SELECT attack_id AS id, name, domain FROM mitigations
                WHERE NOT is_revoked AND NOT is_deprecated ORDER BY attack_id`),
    // Every row, revoked or not: /mitigations/{id} still renders those.
    pool.query(`SELECT attack_id AS id FROM mitigations`),
  ]);
  const d3Missing = d3.rows.filter((r) => !D3FEND_TO_FAIR_CAM[r.id]);
  // Reverse direction: a classified id the database no longer has is a dead
  // link on /frameworks/fair-cam (its D3FEND / mitigation page 404s).
  const d3InDb = new Set(d3.rows.map((r) => r.id));
  const mitInDb = new Set(mitAll.rows.map((r) => r.id));
  const stale = [
    ...Object.keys(D3FEND_TO_FAIR_CAM).filter((id) => !d3InDb.has(id)),
    ...Object.keys(MITIGATION_TO_FAIR_CAM).filter((id) => !mitInDb.has(id)),
  ];
  const mitMissing = mit.rows.filter((r) => !MITIGATION_TO_FAIR_CAM[r.id]);
  const expected = mitMissing.filter((r) => r.domain === 'mobile-attack' || r.domain === 'atlas-attack');
  const actionable = mitMissing.filter((r) => !expected.includes(r));

  console.log(`D3FEND: ${d3.rows.length} in DB, ${d3Missing.length} unclassified`);
  for (const r of d3Missing) console.log(`  ${r.id}  ${r.tactic ?? '?'}  ${r.name ?? ''}`);
  console.log(`Mitigations: ${mit.rows.length} live, ${actionable.length} Enterprise/ICS unclassified, ${expected.length} Mobile/ATLAS (not classified by design)`);
  for (const r of actionable) console.log(`  ${r.id}  ${r.domain}  ${r.name}`);
  console.log(`Classified but not in the DB (dead links on /frameworks/fair-cam): ${stale.length}`);
  for (const id of stale) console.log(`  ${id}`);
  process.exitCode = d3Missing.length + actionable.length + stale.length > 0 ? 1 : 0;
} finally {
  await pool.end();
}
