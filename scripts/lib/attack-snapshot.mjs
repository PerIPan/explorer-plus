// scripts/lib/attack-snapshot.mjs
//
// Capture an invariant snapshot of the ATT&CK tables. Used pre+post the
// update-attack run to verify nothing regressed. See spec section
// "Verification harness" in docs/mitre_update.md.
//
// What's captured:
//   - counts: row count per entity table (class A invariant — must not drop)
//   - ids:    every UUID per entity table (class B invariant — must be a
//             subset of post; no UUIDs may disappear)
//   - relationCounts: row count per join table (informational delta only)
//   - orphanSubtechniques: count of techniques marked is_subtechnique with
//             a NULL parent_technique_id (must be zero)
//   - perDomainTechniqueCounts: techniques grouped by domain
//
// Why no FK-dangling check: every FK column has a real Postgres FOREIGN KEY
// constraint, so dangling references are physically impossible — the DB
// itself enforces the invariant. The snapshot still captures every UUID so
// the diff can prove "no UUIDs disappeared" which is what UPSERT-by-stix_id
// guarantees in theory.

const ENTITY_TABLES = [
  'tactics',
  'techniques',
  'threat_groups',
  'attack_software',
  'mitigations',
  'campaigns',
  'data_sources',
  'data_components',
];

const RELATION_TABLES = [
  'technique_tactics',
  'group_techniques',
  'group_software',
  'software_techniques',
  'mitigation_techniques',
  'campaign_techniques',
  'campaign_software',
  'group_campaigns',
  'technique_data_components',
];

export async function captureSnapshot(pool) {
  const snap = { capturedAt: new Date().toISOString(), counts: {}, ids: {}, relationCounts: {}, perDomainTechniqueCounts: {} };

  for (const t of ENTITY_TABLES) {
    const r = await pool.query(`SELECT COUNT(*)::int AS n FROM ${t}`);
    snap.counts[t] = r.rows[0].n;
  }

  for (const t of ENTITY_TABLES) {
    const r = await pool.query(`SELECT id FROM ${t} ORDER BY id`);
    snap.ids[t] = r.rows.map((row) => row.id);
  }

  for (const t of RELATION_TABLES) {
    const r = await pool.query(`SELECT COUNT(*)::int AS n FROM ${t}`);
    snap.relationCounts[t] = r.rows[0].n;
  }

  // Per-domain technique count — a sanity check after the Defense Evasion
  // split (Enterprise should pick up new tactics, ICS gains sub-techniques).
  const dom = await pool.query(
    `SELECT domain, COUNT(*)::int AS n FROM techniques WHERE domain IS NOT NULL GROUP BY domain ORDER BY domain`,
  );
  for (const row of dom.rows) snap.perDomainTechniqueCounts[row.domain] = row.n;

  // Sub-technique orphan invariant — every is_subtechnique=true row must
  // have a non-null parent_technique_id.
  const orphan = await pool.query(
    `SELECT COUNT(*)::int AS n FROM techniques WHERE is_subtechnique = true AND parent_technique_id IS NULL`,
  );
  snap.orphanSubtechniques = orphan.rows[0].n;

  return snap;
}

export { ENTITY_TABLES, RELATION_TABLES };
