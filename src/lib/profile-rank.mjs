/**
 * Pure ranking functions for the Threat Profile. Kept out of the route so they
 * can be unit-tested without a database — the repo has no jsdom/DB test harness.
 */

const METRIC = { io: 'iocs', rp: 'reports', kev: 'kevCount', cv: 'cveCount', lift: 'lift' };

/** Band A = top N by the chosen evidence metric. Band B = top N by lift, A excluded. */
export function splitBands(pool, sortKey, n = 6) {
  const field = METRIC[sortKey] ?? 'kevCount';
  const bandA = [...pool].sort((a, b) => (b[field] ?? 0) - (a[field] ?? 0)).slice(0, n);
  const taken = new Set(bandA.map(t => t.attackId));
  const bandB = pool
    .filter(t => !taken.has(t.attackId))
    .sort((a, b) => (b.lift ?? 0) - (a.lift ?? 0))
    .slice(0, n);
  return { bandA, bandB };
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
