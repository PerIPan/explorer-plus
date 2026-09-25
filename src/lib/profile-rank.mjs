/**
 * Pure ranking functions for the Threat Profile. Kept out of the route so they
 * can be unit-tested without a database — the repo has no jsdom/DB test harness.
 */

const METRIC = { io: 'iocs', rp: 'reports', kev: 'kevCount', cv: 'cveCount', lift: 'lift' };

/** Band B's group-count floor. A technique attributed to <3 groups is one sighting away
 * from noise — six single-sighting techniques tied at the same lift is not a defensible
 * "disproportionately aimed at you" list. */
export const MIN_GROUPS = 3;

/**
 * Band A = top N by the chosen evidence metric, unrestricted (reach stays valid at any
 * selection size). Band B = top N by lift among techniques with >= minGroups attributed
 * groups, Band A excluded. `bandBShort` is true whenever fewer than N candidates clear
 * the floor — the caller (the route) is responsible for the documented fallback: drop
 * the platform constraint, re-select, and label the widening.
 */
export function splitBands(pool, sortKey, n = 6, minGroups = MIN_GROUPS) {
  const field = METRIC[sortKey] ?? 'kevCount';
  const bandA = [...pool].sort((a, b) => (b[field] ?? 0) - (a[field] ?? 0)).slice(0, n);
  const taken = new Set(bandA.map(t => t.attackId));
  const eligible = pool.filter(t => !taken.has(t.attackId) && (t.groupCount ?? 0) >= minGroups);
  const bandB = eligible
    .sort((a, b) => (b.lift ?? 0) - (a.lift ?? 0) || (a.attackId < b.attackId ? -1 : 1))
    .slice(0, n);
  return { bandA, bandB, bandBShort: bandB.length < n };
}

/**
 * True when the candidate set cannot produce a defensible lift ordering.
 * Fires on the COMPUTED RESULT, not on missing input: a full OT asset
 * selection is valid input that still collapses every lift to 1.0.
 */
export function isDegenerate(pool, minDistinct = 6) {
  const distinct = new Set(pool.map(t => Math.round((t.lift ?? 0) * 1000)));
  return distinct.size < minDistinct;
}
