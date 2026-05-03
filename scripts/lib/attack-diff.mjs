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
//
// Tolerances:
//   - count: must be ≥ pre (additions OK, drops fail)
//   - uuids: every pre UUID must be in post (additions OK)
//   - relations: 50% drop threshold (orphan-delete should typically remove
//     a small minority; large drops indicate the reconciler scoped wrong)

const RELATION_DROP_THRESHOLD = 0.5;

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
  return summary;
}
