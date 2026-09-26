// scripts/lib/attack-diff.mjs
//
// Compare pre and post snapshots from attack-snapshot.mjs. Returns
// { passed, failures }. Each failure is { kind, ...detail } so the caller
// can format/log without coupling.
//
// Failure kinds:
//   - count_dropped: an entity table lost rows (UPSERT-by-stix_id should
//     never delete; this fires if a parent was hard-deleted)
//   - uuids_missing: pre-existing UUIDs aren't in post (FK-dangling risk if
//     custom mapping tables held that UUID — Postgres FKs prevent this in
//     theory, this is a belt-and-braces check)
//   - orphan_subtechniques: techniques.is_subtechnique=true with NULL
//     parent_technique_id (data inconsistency)
//   - relation_count_collapsed: a relation table dropped > 50% of rows
//     (likely buggy reconciler, abort the run for review)
//   - sector_coverage_dropped: the share of LIVE groups carrying >= 1
//     group_sectors row fell by more than SECTOR_COVERAGE_DROP_PP. This is a
//     COVERAGE assertion, not a row count — see the block comment on the rule.
//
// Tolerances:
//   - count: must be ≥ pre (additions OK, drops fail)
//   - uuids: every pre UUID must be in post (additions OK)
//   - relations: 50% drop threshold (orphan-delete should typically remove
//     a small minority; large drops indicate the reconciler scoped wrong)
//   - sector coverage: 3 percentage points (see below)

const RELATION_DROP_THRESHOLD = 0.5;

/**
 * Sector-coverage decay tolerance, in PERCENTAGE POINTS of coverage.
 *
 * Why a coverage rule at all: `group_sectors` is written only by
 * extract_sectors in the destructive seed, never by update-attack.mjs. An
 * ATT&CK release that adds threat groups WITHOUT sector links therefore leaves
 * the row count untouched (396 today) while the denominator grows underneath
 * it, so neither `count_dropped` nor the 50% `relation_count_collapsed` rule
 * can ever fire on the one failure mode this table actually has. Only the ratio
 * moves. Measured 2026-09-26: 149 linked / 180 live = 82.8%.
 *
 * Why 3 points, and why absolute points rather than a relative drop:
 *
 *   - It catches the scenario the spec names with ~2x margin. Fifteen unlinked
 *     new groups take coverage to 149/195 = 76.4%, a 6.4-point drop.
 *   - At today's denominator 3 points is ~7 unlinked new groups, which moves
 *     the lift denominator `all_n` by ~3.9% AND re-ranks every technique those
 *     seven groups use (their group_techniques rows raise the global count for
 *     those techniques only, so it is not a uniform rescale). Seven is the
 *     smallest addition worth stopping a human for.
 *   - It is not noise. A routine release adding one to three groups costs at
 *     most ~1.3 points and passes untouched, so this does not cry wolf on every
 *     ATT&CK version bump.
 *   - ABSOLUTE points, not a relative drop, because a relative rule gets
 *     LOOSER as coverage decays: at 82.8% a 5% relative rule tolerates 4.1
 *     points, but at an already-degraded 50% it would tolerate only 2.5 — the
 *     opposite of what is wanted. Points keep the trigger constant.
 *
 * The remedy when it fires is not to relax the threshold: it is to re-run
 * extract_sectors so the new groups get their sector links, then re-snapshot.
 */
const SECTOR_COVERAGE_DROP_PP = 0.03;

export function diffSnapshots(pre, post) {
  const failures = [];

  // Class A: row counts must not regress.
  for (const [table, preCount] of Object.entries(pre.counts ?? {})) {
    const postCount = post.counts?.[table] ?? 0;
    if (postCount < preCount) {
      failures.push({ kind: 'count_dropped', table, pre: preCount, post: postCount });
    }
  }

  // Class B: every pre UUID must still be present.
  for (const [table, preIds] of Object.entries(pre.ids ?? {})) {
    const postSet = new Set(post.ids?.[table] ?? []);
    const missing = preIds.filter((id) => !postSet.has(id));
    if (missing.length > 0) {
      failures.push({
        kind: 'uuids_missing',
        table,
        count: missing.length,
        sample: missing.slice(0, 5),
      });
    }
  }

  // Sub-technique orphan — must be zero.
  if ((post.orphanSubtechniques ?? 0) > 0) {
    failures.push({ kind: 'orphan_subtechniques', count: post.orphanSubtechniques });
  }

  // Relation tables — flag if > 50% drop. Some shrink is expected when
  // STIX revokes/deprecates relations; a large collapse usually means the
  // reconciler's scope is wrong (e.g. DELETEd rows belonging to entities
  // not in this run's bundles).
  for (const [table, preCount] of Object.entries(pre.relationCounts ?? {})) {
    const postCount = post.relationCounts?.[table] ?? 0;
    if (preCount > 0 && postCount < preCount * (1 - RELATION_DROP_THRESHOLD)) {
      failures.push({
        kind: 'relation_count_collapsed',
        table,
        pre: preCount,
        post: postCount,
        dropRatio: ((preCount - postCount) / preCount).toFixed(3),
      });
    }
  }

  // Class D: sector coverage. Skipped when the pre snapshot predates this
  // field (an in-flight upgrade) rather than read as a drop to zero.
  const preCov = pre.sectorCoverage;
  const postCov = post.sectorCoverage;
  if (preCov && postCov) {
    const drop = preCov.ratio - postCov.ratio;
    if (drop > SECTOR_COVERAGE_DROP_PP) {
      failures.push({
        kind: 'sector_coverage_dropped',
        table: 'group_sectors',
        preLinked: preCov.linkedGroups,
        preLive: preCov.liveGroups,
        postLinked: postCov.linkedGroups,
        postLive: postCov.liveGroups,
        preRatio: preCov.ratio.toFixed(4),
        postRatio: postCov.ratio.toFixed(4),
        dropPoints: drop.toFixed(4),
        thresholdPoints: SECTOR_COVERAGE_DROP_PP.toFixed(4),
        remedy: 'new groups arrived without sector links — re-run extract_sectors, '
          + 'then re-verify. sector_technique_lift is re-ranked until you do.',
      });
    }
  }

  return { passed: failures.length === 0, failures };
}

export function summarizeDiff(pre, post) {
  // Human-readable delta summary — "what changed" rather than "what failed".
  // Useful in feed_sync_log.metadata for forensic review.
  const summary = { entities: {}, relations: {}, perDomain: {} };
  for (const [t, preCount] of Object.entries(pre.counts ?? {})) {
    summary.entities[t] = { pre: preCount, post: post.counts?.[t] ?? 0, delta: (post.counts?.[t] ?? 0) - preCount };
  }
  for (const [t, preCount] of Object.entries(pre.relationCounts ?? {})) {
    summary.relations[t] = { pre: preCount, post: post.relationCounts?.[t] ?? 0, delta: (post.relationCounts?.[t] ?? 0) - preCount };
  }
  for (const [d, preCount] of Object.entries(pre.perDomainTechniqueCounts ?? {})) {
    summary.perDomain[d] = { pre: preCount, post: post.perDomainTechniqueCounts?.[d] ?? 0 };
  }
  if (pre.sectorCoverage || post.sectorCoverage) {
    summary.sectorCoverage = { pre: pre.sectorCoverage ?? null, post: post.sectorCoverage ?? null };
  }
  return summary;
}
