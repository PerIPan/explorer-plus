/**
 * Pure ranking functions for the Threat Profile. Kept out of the route so they
 * can be unit-tested without a database — the repo has no jsdom/DB test harness.
 *
 * Shared by BOTH engines. The IT path ranks enterprise techniques for a sector;
 * the OT path ranks ICS techniques for a set of ATT&CK assets. They differ in
 * what they measure, not in how bands are cut, so the band logic lives here once
 * and each path supplies its own metric and its own structural floor.
 */

/**
 * Band A's sort field, keyed by the `sort` the caller asked for.
 *
 * `exposure` is the OT path's metric and is NOT a visitor-selectable `sort`
 * value (`sortKeySchema` deliberately does not offer it): Band A on the OT path
 * is exposure by definition, and the route passes the literal.
 *
 * It MUST be present here. Without it `METRIC['exposure'] ?? 'kevCount'` falls
 * back to kevCount — and kevCount is 0 for every live ICS technique (measured
 * 2026-09-26: the only ICS row in `technique_cve_evidence` is T0812, which is
 * revoked). Band A would then be an arbitrary stable-sort slice of an all-zero
 * column, presented to a plant operator as "your top exposure". That is a
 * silent wrong answer, not a crash, which is why it is called out here.
 */
const METRIC = {
  io: 'iocs',
  rp: 'reports',
  kev: 'kevCount',
  cv: 'cveCount',
  lift: 'lift',
  exposure: 'exposure',
};

/** Band B's group-count floor. A technique attributed to <3 groups is one sighting away
 * from noise — six single-sighting techniques tied at the same lift is not a defensible
 * "disproportionately aimed at you" list. */
export const MIN_GROUPS = 3;

/**
 * Band B's REACH floor, the OT analogue of `MIN_GROUPS`.
 *
 * Asset-derived items carry no group attribution at all, so `MIN_GROUPS` would
 * empty Band B entirely rather than filter it — again silently. The structural
 * intent MIN_GROUPS encodes ("one sighting must not mint a top-six entry")
 * transfers to reach: a technique mapped to a single one of the 18 assets can
 * reach lift 18.0 off one `asset_techniques` row. Requiring reach >= 2 costs
 * nothing real — measured 2026-09-26, all three zone selections still produce a
 * full six-item Band B under this floor.
 */
export const MIN_REACH = 2;

/**
 * Band A = top N by the chosen evidence metric, unrestricted (reach stays valid at any
 * selection size). Band B = top N by lift among techniques that clear BOTH floors,
 * Band A excluded. `bandBShort` is true whenever fewer than N candidates clear
 * the floors — on the IT path the caller (the route) is responsible for the documented
 * fallback: drop the platform constraint, re-select, and label the widening.
 *
 * Band A's comparator has no explicit tie-break ON PURPOSE. `Array.prototype.sort` is
 * stable, so ties resolve to the pool's incoming order, and BOTH routes order their pool
 * query deterministically (IT: `lift DESC, attack_id ASC`; OT: `exposure DESC,
 * attack_id ASC`). Adding a tie-break here would silently re-order the IT path's
 * existing Band A, which is in production use.
 *
 * @param {Array<object>} pool         candidate techniques
 * @param {string} sortKey             a key of METRIC; anything else falls back to kevCount
 * @param {number} [n=6]               band size
 * @param {number} [minGroups=MIN_GROUPS] group-attribution floor for Band B. The OT path
 *   passes 0: its items have no group attribution, so the default would empty Band B.
 * @param {number} [minReach=0]        reach floor for Band B. Defaults to 0 so it is
 *   inert for the IT path (whose items have no `reach` field at all); the OT path
 *   passes MIN_REACH.
 */
export function splitBands(pool, sortKey, n = 6, minGroups = MIN_GROUPS, minReach = 0) {
  const field = METRIC[sortKey] ?? 'kevCount';
  const bandA = [...pool].sort((a, b) => (b[field] ?? 0) - (a[field] ?? 0)).slice(0, n);
  const taken = new Set(bandA.map(t => t.attackId));
  return { bandA, ...selectBandB(pool, taken, n, minGroups, minReach) };
}

/**
 * Band B alone, over an arbitrary pool, excluding an arbitrary set of ids.
 *
 * Extracted from `splitBands` for the IT path's platform fallback. The spec
 * (design doc line 120) frames that fallback as filling BAND B, but the route
 * implemented it by re-running `splitBands` over the widened pool and taking
 * BOTH bands from it — so a narrow platform pick produced a briefing identical
 * in both bands to answering nothing at all, and the visitor's environment
 * answer was discarded entirely and silently. Band A must stay on the
 * platform-filtered pool so the answer still shows somewhere, which means Band B
 * has to be selectable over a DIFFERENT pool from the Band A it excludes — and
 * that is exactly what `splitBands` cannot express, because it always excludes
 * the Band A it just computed from the same pool.
 *
 * The exclusion is BY ID, so it works across pools: Band A's ids come from the
 * platform pool, the candidates come from the full sector pool, and the six
 * Band A techniques are still kept out of Band B.
 *
 * @param {Array<object>} pool        candidates
 * @param {Set<string>} excludeIds    attackIds to keep out (normally Band A's)
 * @param {number} [n=6]              band size
 * @param {number} [minGroups=MIN_GROUPS] group-attribution floor
 * @param {number} [minReach=0]       reach floor (inert on the IT path)
 */
export function selectBandB(pool, excludeIds, n = 6, minGroups = MIN_GROUPS, minReach = 0) {
  const eligible = pool.filter(t =>
    !excludeIds.has(t.attackId)
    && (t.groupCount ?? 0) >= minGroups
    && (t.reach ?? 0) >= minReach);
  const bandB = eligible
    .sort((a, b) => (b.lift ?? 0) - (a.lift ?? 0) || (a.attackId < b.attackId ? -1 : 1))
    .slice(0, n);
  return { bandB, bandBShort: bandB.length < n };
}

/**
 * True when the column Band A is SORTED BY is entirely zero across the pool —
 * i.e. the band is an arbitrary stable-sort slice of nothing, presented under a
 * heading that names evidence.
 *
 * This is the generalisation of the ICS problem the OT engine exists for.
 * Measured 2026-09-26, the same shape holds elsewhere: all 155 live ATLAS
 * techniques and every live mobile technique carry no CVE/KEV/EPSS evidence at
 * all, so `?domain=atlas-attack&sort=kev` ranks a column of zeroes under "Most
 * KEV evidence" and nothing in the response says so. The route surfaces this as
 * `meta.evidenceUnavailable` so the page can say it instead of implying the
 * opposite.
 *
 * An EMPTY pool returns false, deliberately: there is no column to make a claim
 * about, and the empty-pool states already carry their own `reason`. Only a
 * populated pool whose metric is uniformly zero is a silent wrong answer.
 *
 * @param {Array<object>} pool
 * @param {string} sortKey a key of METRIC; anything else resolves to kevCount,
 *   matching `splitBands`, so the flag describes the column actually sorted on.
 */
export function isEvidenceUnavailable(pool, sortKey) {
  if (pool.length === 0) return false;
  const field = METRIC[sortKey] ?? 'kevCount';
  return pool.every(t => !(t[field] > 0));
}

/**
 * OT lift: how much more of the VISITOR's asset surface a technique covers than
 * it covers of the whole ATT&CK ICS asset surface.
 *
 *     (exposure / nEffective) / (reach / nAll)
 *
 * `nEffective` is the cardinality of the DISTINCT union of the explicitly named
 * assets and the assets expanded from the selected Purdue levels. Distinct is
 * not a detail — measured 2026-09-26, l2 holds 7 assets and l3 holds 7, but
 * their union is 10, because A0001, A0009, A0014 and A0015 span both. Passing
 * 14 here instead of 10 scales every lift by 0.71 and nothing anywhere
 * complains.
 *
 * THROWS rather than returning `NaN`/`Infinity` when the denominator is empty.
 * `nEffective` is 0 for a real, reachable request — `?levels=l5`, since
 * Enterprise IT carries no ATT&CK asset — and the route is responsible for
 * short-circuiting that into the documented no-assets state before it gets
 * here. If that guard is ever removed, this turns a page silently full of
 * `NaN` into one loud, named error.
 *
 * @param {number} exposure   effective assets targeted by the technique
 * @param {number} reach      ALL live assets targeted by the technique
 * @param {number} nEffective size of the distinct effective asset union
 * @param {number} nAll       total live assets (18 in production)
 * @returns {number}
 */
export function otLift(exposure, reach, nEffective, nAll) {
  if (!(nEffective > 0)) {
    throw new Error(
      `otLift: empty effective asset set (nEffective=${nEffective}). The caller must ` +
      'short-circuit an empty selection into the no-assets state before ranking.');
  }
  if (!(reach > 0)) {
    throw new Error(`otLift: technique has reach=${reach}; it should not be in the pool at all.`);
  }
  return (exposure / nEffective) / (reach / nAll);
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
