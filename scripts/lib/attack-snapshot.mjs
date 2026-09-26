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
//   - sectorCoverage: linked / live group COVERAGE, not a row count (class D
//             invariant — must not decay materially; see attack-diff.mjs)
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
  // Not written by update-attack.mjs — extract_sectors lives only in the
  // destructive seed. Snapshotted for the delta summary only: the ROW COUNT
  // cannot detect the failure mode that matters here (see `sectorCoverage`
  // below, and the coverage rule in attack-diff.mjs).
  'group_sectors',
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

  /* ──────────────────────────────────────────────────────────────────────────
   * Sector COVERAGE, not group_sectors row count.
   *
   * The named failure mode is an ATT&CK release that adds threat groups WITHOUT
   * sector links. `group_sectors` is written ONLY by extract_sectors in the
   * destructive seed, never by update-attack.mjs, so such a release leaves the
   * table at exactly its pre-run row count — 396 today. A row-count rule (even
   * the 50% relation_count_collapsed rule) can never fire on it: nothing was
   * lost, the denominator simply grew underneath.
   *
   * What moves is the sector_technique_lift matview. Measured 2026-09-26:
   * coverage is 149 linked / 180 live groups = 82.8%. Fifteen unlinked new
   * groups take the lift denominator `all_n` from 180 to 195 — and because the
   * new groups DO carry group_techniques rows, the global `glob.c` per technique
   * rises only for the techniques THEY use. The result is not a uniform rescale
   * that leaves the order alone: it is real re-ranking inside every sector,
   * ungated and invisible.
   *
   * Definitions, both scoped to LIVE groups so a release that merely revokes a
   * group does not read as decay:
   *   liveGroups   = non-revoked, non-deprecated threat_groups
   *   linkedGroups = of those, the ones with >= 1 group_sectors row
   * ────────────────────────────────────────────────────────────────────────── */
  const coverage = await pool.query(
    `WITH live AS (
       SELECT id FROM threat_groups WHERE is_revoked = false AND is_deprecated = false
     ),
     linked AS (
       SELECT DISTINCT gs.group_id FROM group_sectors gs JOIN live l ON l.id = gs.group_id
     )
     SELECT (SELECT count(*)::int FROM live)   AS live_groups,
            (SELECT count(*)::int FROM linked) AS linked_groups`,
  );
  const { live_groups: liveGroups, linked_groups: linkedGroups } = coverage.rows[0];
  snap.sectorCoverage = {
    liveGroups,
    linkedGroups,
    ratio: liveGroups > 0 ? linkedGroups / liveGroups : 0,
  };

  // Sub-technique orphan invariant — every is_subtechnique=true row must
  // have a non-null parent_technique_id.
  const orphan = await pool.query(
    `SELECT COUNT(*)::int AS n FROM techniques WHERE is_subtechnique = true AND parent_technique_id IS NULL`,
  );
  snap.orphanSubtechniques = orphan.rows[0].n;

  return snap;
}

export { ENTITY_TABLES, RELATION_TABLES };
