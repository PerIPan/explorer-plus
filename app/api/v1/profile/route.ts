import { NextRequest, NextResponse } from 'next/server';
import { query } from '../lib/db';
import { jsonResponse, errorResponse } from '../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../lib/cors';
import { profileQuerySchema, profileDomainSchema, PROFILE_DOMAIN_ALL } from '../lib/validate';
import {
  splitBands, selectBandB, isDegenerate, isEvidenceUnavailable, otLift, MIN_REACH,
} from '../../../../src/lib/profile-rank.mjs';

export { OPTIONS };

// `domain` is not part of `profileQuerySchema` (Task 5 brief §1 lists sector/
// platform/sort only — a later task owns widening the schema). It is still a
// legitimate filter for this assembler, so it is composed on locally, the
// same way app/api/v1/search/route.ts and app/api/v1/dashboard/route.ts pull
// in the shared domain piece rather than duplicating the enum.
//
// `profileDomainSchema`, NOT the shared `domainSchema`: it DEFAULTS to
// enterprise-attack instead of being `.optional()`, and it accepts the explicit
// `all`. See its doc comment in app/api/v1/lib/validate.ts — an absent
// `?domain=` used to mean no filter at all, and four of six Band A slots for
// `?sector=energy&sort=lift` came back ICS.
const querySchema = profileQuerySchema.extend({ domain: profileDomainSchema });

// Raw shape straight off the wire. `numeric` columns (lift, max_epss) come back
// from node-postgres as strings, not numbers -- coerced below before anything
// downstream (this route's own JSON, and Tasks 11/12's consumers) has to
// `parseFloat` them itself. `platforms` rides along only to do the Band-B
// platform-fallback filtering in JS; it is stripped before the pool is turned
// into response items (it is not part of the bandA/bandB item shape).
interface RawPoolRow {
  attackId: string;
  name: string;
  lift: string;
  groupCount: number;
  iocs: number;
  reports: number;
  cveCount: number;
  kevCount: number;
  maxEpss: string | null;
  platforms: string[] | null;
}

interface PoolItem {
  attackId: string;
  name: string;
  lift: number;
  groupCount: number;
  iocs: number;
  reports: number;
  cveCount: number;
  kevCount: number;
  maxEpss: number | null;
}

function toPoolItem(r: RawPoolRow): PoolItem {
  return {
    attackId: r.attackId,
    name: r.name,
    lift: Number(r.lift),
    groupCount: r.groupCount,
    iocs: r.iocs,
    reports: r.reports,
    cveCount: r.cveCount,
    kevCount: r.kevCount,
    maxEpss: r.maxEpss === null ? null : Number(r.maxEpss),
  };
}

interface GroupRow {
  attackId: string;
  name: string;
  aliases: string[] | null;
  /** Pre-LIMIT total from `count(*) OVER ()` — identical on every row, and
   *  absent entirely when there are no rows. Stripped before the response. */
  totalGroups: number;
}

/* ════════════════════════════════════════════════════════════════════════════
 * OT (ICS) ENGINE
 *
 * A genuinely different engine, not the IT one with a different filter, because
 * ATT&CK for ICS carries none of the signals the IT engine ranks on. Measured
 * against production 2026-09-26 over the 97 live ICS techniques:
 *
 *   platforms        every technique is the literal 'None' (73) or NULL (24).
 *                    All seven ICS values in PLATFORMS match ZERO live
 *                    techniques, so a platform filter returns an empty pool.
 *   IOC sightings    0        CTI report mentions  0
 *   CVE evidence     0        KEV / EPSS           0   (the sole ICS row in
 *                    technique_cve_evidence is T0812, which is revoked)
 *
 * What ICS DOES model is ASSETS — A0001-A0018 — and this repo places each on
 * the Purdue model (`asset_purdue_placement`). So the OT engine ranks on the
 * visitor's asset surface instead:
 *
 *   effective assets = explicit `assets` UNION assets whose spans_levels
 *                      overlaps `levels`, DISTINCT
 *   exposure(t)      = effective assets targeted by t
 *   reach(t)         = ALL live assets targeted by t
 *   lift(t)          = (exposure / n_effective) / (reach / n_all)
 *
 * Band A = top 6 by exposure. Band B = top 6 by lift, Band A excluded,
 * reach >= MIN_REACH.
 *
 * NO MATVIEW, deliberately. The IT engine precomputes `sector_technique_lift`
 * because it spans 396 group_sectors x group_techniques x 697 techniques under
 * a global denominator. This reads 842 `asset_techniques` rows against indexes
 * that already exist in both directions (PK(asset_id,technique_id) and
 * idx_asset_techniques_tech). Decisively: exposure is NOT precomputable — it
 * depends on the visitor's arbitrary selection, of which there are 2^18 =
 * 262,144. Only `reach` is selection-independent, and that is a GROUP BY over
 * 842 rows. A matview would cost a migration, a MATVIEWS registration, a cron
 * slot and a staleness surface, and buy nothing.
 * ════════════════════════════════════════════════════════════════════════════ */

const ICS_DOMAIN = 'ics-attack';

interface EffectiveAsset {
  attackId: string;
  name: string;
  primaryLevel: string;
  spansLevels: string[];
  isBoundary: boolean;
}

interface RawOtRow {
  attackId: string;
  name: string;
  exposure: number;
  reach: number;
  groupCount: number;
  mitigationCount: number;
  d3fendCount: number;
}

/**
 * An OT band item. A strict SUPERSET of the IT `PoolItem` shape: `iocs`,
 * `reports`, `cveCount`, `kevCount` and `maxEpss` are carried as the MEASURED
 * zeros they are for every live ICS technique (see the block comment above),
 * not as padding — so a consumer written against the IT shape reads honest
 * zeroes rather than `undefined`.
 */
interface OtItem {
  attackId: string;
  name: string;
  exposure: number;
  reach: number;
  lift: number;
  /** Context only. The OT path does NOT floor Band B on group attribution —
   *  it floors on `reach` — but 37 of the 97 live ICS techniques do carry a
   *  named group, and suppressing that would be its own kind of lie. */
  groupCount: number;
  mitigationCount: number;
  d3fendCount: number;
  iocs: number;
  reports: number;
  cveCount: number;
  kevCount: number;
  maxEpss: number | null;
}

interface ImpactRow {
  attackId: string;
  name: string;
  tactics: string[];
  mitigationCount: number;
  d3fendCount: number;
}

/**
 * Lift is computed in JS, not in SQL. `numeric` comes back from node-postgres as
 * a string (the IT path has to `Number()` it), and the division needs `n_eff`,
 * which is just `effective.length` — already in hand. Keeping it out of SQL
 * leaves the pool query a plain integer GROUP BY, and puts the arithmetic in
 * `otLift` where scripts/lib/profile-rank.test.mjs can pin it directly.
 */
function toOtItem(r: RawOtRow, nEffective: number, nAll: number): OtItem {
  return {
    attackId: r.attackId,
    name: r.name,
    exposure: r.exposure,
    reach: r.reach,
    lift: otLift(r.exposure, r.reach, nEffective, nAll),
    groupCount: r.groupCount,
    mitigationCount: r.mitigationCount,
    d3fendCount: r.d3fendCount,
    iocs: 0,
    reports: 0,
    cveCount: 0,
    kevCount: 0,
    maxEpss: null,
  };
}

/** The unranked Impact collection. Selection-independent, so it is the same
 *  query whether or not the visitor has chosen anything yet. */
const IMPACT_SQL = `
  SELECT t.attack_id AS "attackId",
         t.name,
         COALESCE(
           array_agg(DISTINCT ta.name) FILTER (WHERE ta.name IS NOT NULL),
           '{}'
         ) AS tactics,
         (SELECT count(*) FROM mitigation_techniques mt WHERE mt.technique_id = t.id)::int
           AS "mitigationCount",
         (SELECT count(DISTINCT d.d3fend_id) FROM defensive_mappings d WHERE d.technique_id = t.id)::int
           AS "d3fendCount"
  FROM techniques t
  LEFT JOIN technique_tactics tt ON tt.technique_id = t.id
  LEFT JOIN tactics ta           ON ta.id = tt.tactic_id
  WHERE t.domain = $1 AND NOT t.is_revoked AND NOT t.is_deprecated
    -- "No LIVE, PLACED asset targets this" -- the exact complement of the
    -- JOIN live_assets in OT_POOL_SQL. A bare EXISTS over asset_techniques
    -- alone would let a technique mapped only to a deprecated asset fall out of
    -- BOTH collections and vanish from the briefing without a trace.
    AND NOT EXISTS (
      SELECT 1
      FROM asset_techniques at
      JOIN attack_assets a            ON a.id = at.asset_id
      JOIN asset_purdue_placement p   ON p.asset_id = a.id
      WHERE at.technique_id = t.id
        AND NOT a.is_revoked AND NOT a.is_deprecated
    )
  GROUP BY t.id, t.attack_id, t.name
  ORDER BY t.attack_id ASC`;

/**
 * Resolve the visitor's selection to its EFFECTIVE asset set.
 *
 * Two things here are load-bearing and both fail silently if got wrong.
 *
 * 1. Purdue matching is `spans_levels && $2::text[]`, NEVER `primary_level`.
 *    Measured: 8 of the 18 assets span more than one level and 6 are boundary
 *    assets. `primary_level = 'l3'` returns A0006, A0008, A0014 — three assets.
 *    `spans_levels && ARRAY['l3']` returns A0001, A0006, A0008, A0009, A0014,
 *    A0015, A0016 — seven. Naive matching silently drops over half the real L3
 *    surface, including the boundary assets someone asking about L3 most cares
 *    about. This is the OT analogue of the repo's `$n = ANY(domain)` rule.
 *
 * 2. The union must be DISTINCT, because it feeds the lift DENOMINATOR.
 *    Measured: l2 has 7 assets and l3 has 7, but l2+l3 is 10 distinct, not 14
 *    — A0001, A0009, A0014 and A0015 span both. Counting 14 would scale every
 *    lift by 0.71 with nothing to show for it. The `OR` below is what makes it
 *    distinct for free: `asset_purdue_placement` is keyed PK(asset_id), so the
 *    join is strictly 1:1 and the two arms are a row-level predicate rather
 *    than a `UNION ALL` of two row sets. The same applies when an explicit
 *    `assets` member is also reachable through a selected level.
 */
const EFFECTIVE_ASSETS_SQL = `
  SELECT a.attack_id                    AS "attackId",
         a.name,
         p.primary_level                AS "primaryLevel",
         COALESCE(p.spans_levels, '{}') AS "spansLevels",
         p.is_boundary                  AS "isBoundary"
  FROM attack_assets a
  JOIN asset_purdue_placement p ON p.asset_id = a.id
  WHERE NOT a.is_revoked AND NOT a.is_deprecated
    AND (a.attack_id = ANY($1::text[]) OR p.spans_levels && $2::text[])
  ORDER BY a.attack_id ASC`;

/**
 * The ranking pool.
 *
 * `NOT t.is_subtechnique` is OT-ONLY and is not a tidiness filter. In ICS a
 * sub-technique's asset mappings are IDENTICAL to its parent's, so it adds zero
 * signal to an engine whose only signal IS the asset mapping. Measured on the
 * plant-floor selection without it, Band B comes back T0821, T0835, T0843,
 * T0843.001, T0843.002, T0843.003 — a parent and its three children occupying
 * four of six slots, all tied at reach 4 / lift 3.000. One finding, shown four
 * times. With it: T0821, T0835, T0843, T0845, T0858, T0860 — six distinct
 * techniques. The IT path is untouched.
 *
 * `JOIN live_assets` is what makes `reach` mean the same thing as the other two
 * terms of the lift ratio. It is the LIVENESS/PLACEMENT filter the numerator
 * (`sel`) and the denominator (`nAll`) already applied and `reach` did not:
 * `count(DISTINCT at.asset_id)` over raw `asset_techniques` counts a deprecated
 * or unplaced asset as reachable surface. Zero impact today — all 18 assets are
 * live and all 18 are placed — but it is the kind of inconsistency that only
 * shows up as wrong numbers: a deprecated asset inflates `reach` and therefore
 * DEFLATES every lift that touches it, and it would do so with no error
 * anywhere. The join is an inner one, so a technique whose only asset mappings
 * are to non-live assets leaves the pool entirely rather than arriving with
 * reach = 0 (which `otLift` throws on, by design). `IMPACT_SQL` uses the same
 * definition, so the two collections stay an exhaustive partition.
 *
 * `ORDER BY exposure DESC, attack_id ASC` is what makes Band A deterministic:
 * `splitBands` sorts stably and deliberately carries no tie-break of its own
 * (adding one would re-order the IT path's production Band A), and exposure
 * ties are the common case here, not the exception.
 */
const OT_POOL_SQL = `
  WITH live_assets AS (
    SELECT a.id, a.attack_id, p.spans_levels
    FROM attack_assets a
    JOIN asset_purdue_placement p ON p.asset_id = a.id
    WHERE NOT a.is_revoked AND NOT a.is_deprecated
  ),
  sel AS (
    SELECT id AS asset_id
    FROM live_assets
    WHERE attack_id = ANY($1::text[]) OR spans_levels && $2::text[]
  )
  SELECT t.attack_id AS "attackId",
         t.name,
         count(DISTINCT at.asset_id) FILTER (
           WHERE at.asset_id IN (SELECT asset_id FROM sel)
         )::int AS exposure,
         count(DISTINCT at.asset_id)::int AS reach,
         (SELECT count(DISTINCT g.group_id) FROM group_techniques g WHERE g.technique_id = t.id)::int
           AS "groupCount",
         (SELECT count(*) FROM mitigation_techniques mt WHERE mt.technique_id = t.id)::int
           AS "mitigationCount",
         (SELECT count(DISTINCT d.d3fend_id) FROM defensive_mappings d WHERE d.technique_id = t.id)::int
           AS "d3fendCount"
  FROM techniques t
  JOIN asset_techniques at ON at.technique_id = t.id
  JOIN live_assets la      ON la.id = at.asset_id
  WHERE t.domain = $3 AND NOT t.is_revoked AND NOT t.is_deprecated
    AND NOT t.is_subtechnique
  GROUP BY t.id, t.attack_id, t.name
  ORDER BY exposure DESC, t.attack_id ASC`;

/**
 * The OT briefing. Fires on `domain=ics-attack`.
 *
 * Note what it does NOT read: `sector`, and `platforms`. Neither can rank an
 * ICS pool (no ICS technique carries a usable platform, and the sector lift
 * matview is built from enterprise group attribution), and letting either
 * quietly narrow the pool would be a wrong answer dressed as a filter. They are
 * echoed back in `profile` so the caller can see they were received and
 * ignored, and `meta.ignoredParams` names them.
 */
async function otHandler(
  assets: string[] | undefined,
  levels: string[] | undefined,
  sector: string | null,
  platforms: string[] | undefined,
): Promise<NextResponse> {
  const assetList = assets ?? [];
  const levelList = levels ?? [];

  const [effectiveResult, poolResult, impactResult, totalResult] = await Promise.all([
    query<EffectiveAsset>(EFFECTIVE_ASSETS_SQL, [assetList, levelList]),
    query<RawOtRow>(OT_POOL_SQL, [assetList, levelList, ICS_DOMAIN]),
    query<ImpactRow>(IMPACT_SQL, [ICS_DOMAIN]),
    // The lift DENOMINATOR's asset count. Joined to `asset_purdue_placement`
    // for the same reason `reach` now is: an asset with no placement is not part
    // of the surface either query can see, so counting it here would shift every
    // lift by 1/nAll (a new unplaced A0019 alone: +5.6%) while changing no
    // technique's exposure or reach. All three terms of the ratio — `sel`,
    // `reach`, `nAll` — are now live AND placed.
    query<{ totalAssets: number }>(
      `SELECT count(*)::int AS "totalAssets"
       FROM attack_assets a
       JOIN asset_purdue_placement p ON p.asset_id = a.id
       WHERE NOT a.is_revoked AND NOT a.is_deprecated`,
    ),
  ]);

  const effective = effectiveResult.rows;
  const nEffective = effective.length;
  const nAll = totalResult.rows[0]?.totalAssets ?? 0;
  const impact = impactResult.rows;

  const profile = {
    domain: ICS_DOMAIN,
    assets: assets ?? null,
    levels: levels ?? null,
    sector: sector ?? null,
    platforms: platforms ?? null,
    sort: 'exposure' as const,
  };

  // The no-assets state, reached two ways, both of them valid input rather
  // than an error:
  //
  //   nothing-selected      no `assets` and no `levels` at all.
  //   empty-selection       a selection was made that resolves to ZERO assets.
  //                         `levels=l5` is the real case: Enterprise IT carries
  //                         no ATT&CK asset (measured: l5 -> 0 assets), which is
  //                         an honest absence, not missing data.
  //
  // Both MUST land here. Falling through would divide by zero (every lift
  // `NaN`) or, worse, treat "no filter" as "all 18 assets" and hand a visitor
  // who asked about their enterprise network a full plant-floor briefing.
  if (nEffective === 0) {
    const nothingSelected = assetList.length === 0 && levelList.length === 0;
    return withCors(jsonResponse({
      profile,
      groups: [],
      bandA: [],
      bandB: [],
      impact,
      effectiveAssets: [],
      meta: {
        poolSize: 0,
        groupCount: 0,
        assetCount: 0,
        totalAssets: nAll,
        degenerate: true,
        bandBShort: true,
        bandBSuppressed: true,
        platformDropped: false,
        // Carried on every response shape, always. The OT path never filters by
        // platform (there is nothing to filter on) and is pinned to one domain
        // by definition, so these two are structurally false here rather than
        // merely happening to be.
        platformPoolEmpty: false,
        mixedDomain: false,
        // No pool, so no column to make a claim about — see isEvidenceUnavailable.
        evidenceUnavailable: false,
        subTechniquesExcluded: true,
        minReach: MIN_REACH,
        ignoredParams: ['sector', 'platforms'],
        reason: nothingSelected ? 'no-assets' : 'empty-selection',
        reasonDetail: nothingSelected
          ? 'No assets or Purdue levels were selected, so there is no surface to rank against.'
          : 'The selected Purdue levels carry no ATT&CK assets, so there is no surface to rank against. MITRE publishes assets for the ICS domain only — Enterprise IT (L5) legitimately has none.',
      },
    }, 3600));
  }

  const pool = poolResult.rows.map((r) => toOtItem(r, nEffective, nAll));

  // `minGroups: 0` — asset-derived items have no group attribution driving the
  // ranking, so the IT floor of 3 would empty Band B outright rather than
  // filter it. `MIN_REACH` is the structural analogue: it stops a single
  // `asset_techniques` row minting a top-six entry at lift 18.0.
  const { bandA, bandB, bandBShort } = splitBands(pool, 'exposure', 6, 0, MIN_REACH);

  // Degeneracy fires on the COMPUTED RESULT, not on missing input. At 18/18
  // assets every lift collapses to exactly 1.0 — (reach/18)/(reach/18) — and it
  // degrades well before that: 28 of the 85 ICS techniques with asset rows have
  // reach >= 16. Band A stays valid at any selection size, because exposure is
  // a count and not a ratio; only the lift ordering stops meaning anything.
  const degenerate = isDegenerate(pool);

  return withCors(jsonResponse({
    profile,
    groups: [],
    bandA,
    bandB: degenerate ? [] : bandB,
    impact,
    effectiveAssets: effective,
    meta: {
      poolSize: pool.length,
      groupCount: 0,
      assetCount: nEffective,
      totalAssets: nAll,
      degenerate,
      bandBShort: degenerate ? true : bandBShort,
      bandBSuppressed: degenerate,
      platformDropped: false,
      platformPoolEmpty: false,
      mixedDomain: false,
      // Computed, not hardcoded false. Band A here is sorted on `exposure`, and
      // an all-zero exposure column is the same silent wrong answer the IT path
      // gets from `sort=kev` over mobile or ATLAS: it would mean the visitor's
      // asset selection touches nothing in the pool, and the band would be an
      // arbitrary slice presented as "your top exposure".
      evidenceUnavailable: isEvidenceUnavailable(pool, 'exposure'),
      subTechniquesExcluded: true,
      minReach: MIN_REACH,
      ignoredParams: ['sector', 'platforms'],
      reason: degenerate ? 'degenerate-lift' : null,
      reasonDetail: degenerate
        ? `Every technique in this pool has the same lift, or nearly so: selecting ${nEffective} of ${nAll} assets makes exposure and reach move together, and lift collapses toward 1.00x. Band A (exposure) is unaffected — narrow the selection to get a meaningful Band B.`
        : null,
    },
  }, 3600));
}

async function handler(req: NextRequest): Promise<NextResponse> {
  const rawParams: Record<string, string> = {};
  req.nextUrl.searchParams.forEach((v, k) => { rawParams[k] = v; });

  const parsed = querySchema.safeParse(rawParams);
  if (!parsed.success) {
    // Covers an unrecognised `sector` slug (must 400, never a silently empty
    // Band B — see task-5-brief §1) as well as a bad `platform`/`sort` value.
    return withCors(errorResponse(400, 'Invalid profile query parameters', 'VALIDATION_ERROR'));
  }

  const { sector, platforms, assets, levels, sort, domain } = parsed.data;

  // `domain` is now ALWAYS a value: `profileDomainSchema` defaults it to
  // enterprise-attack, so the old "absent means no filter" hole is closed at
  // the schema. `all` is the one remaining no-filter case, and it is explicit —
  // so it is allowed to produce a mixed pool, but never a silent one.
  const mixedDomain = domain === PROFILE_DOMAIN_ALL;
  const domainFilter: string | null = mixedDomain ? null : domain;

  // ICS gets its own engine, unconditionally on the domain rather than on
  // "were assets supplied". The IT engine cannot answer an ICS question: it
  // sorts Band A on kevCount, which is 0 for every live ICS technique, so
  // `?domain=ics-attack&sort=kev` today returns a stable-sort slice of an
  // all-zero column presented as "your top exposure". Routing every ICS
  // request here means the worst case is an honest "nothing selected yet"
  // state instead of that. See the OT ENGINE block above.
  if (domain === ICS_DOMAIN) {
    return otHandler(assets, levels, sector ?? null, platforms);
  }

  // Sector carries the whole IT ranking engine (lift is meaningless without
  // one). No sector selected -> no pool, no groups, nothing to rank; this is
  // a valid, non-error state (Optionality table: "Sector empty (IT)").
  if (!sector) {
    return withCors(jsonResponse({
      profile: { sector: null, platforms: platforms ?? null, domain, sort },
      groups: [],
      bandA: [],
      bandB: [],
      meta: {
        poolSize: 0,
        groupCount: 0,
        degenerate: true,
        bandBShort: true,
        platformDropped: false,
        platformPoolEmpty: false,
        mixedDomain,
        evidenceUnavailable: false,
        reason: 'no-sector',
      },
    }, 3600));
  }

  const [poolResult, groupsResult, sectorResult] = await Promise.all([
    // Technique pool for this sector: lift + group_count from the
    // precomputed matview, joined against live evidence (IOC sightings, CTI
    // report mentions, CVE/KEV/EPSS).
    //
    // `iocs` and `reports` are CORRELATED subqueries, not LEFT JOINed derived
    // tables. The derived-table form aggregated the WHOLE of `technique_iocs`
    // -- 681,122 rows -- on every single request, for the ~205 technique_ids
    // this sector actually needs: measured 493ms cold / 175-196ms warm, of which
    // 170-193ms was that one node (a parallel seq scan, three workers). The
    // correlated form does 205 index-only probes of the ALREADY EXISTING
    // idx_technique_iocs_technique_id and comes in at 94ms warm. No index was
    // added and none is warranted -- both indexes this plan uses were already
    // there. `report_techniques` moves with it for symmetry (it is only 5,155
    // rows and cost 1.4ms either way; two different idioms for the same shape is
    // how one of them rots). A count subquery returns 0 for no rows, so the
    // COALESCE the LEFT JOINs needed is gone rather than merely unused.
    //
    // `platforms` rides along unfiltered --
    // the platform constraint is applied in JS below, not in SQL, so that the
    // documented Band-B fallback ("drop the platform constraint and
    // re-select") can re-run splitBands() over the same fetched pool instead
    // of firing a second query. `techniques.domain` is a scalar `varchar`
    // (NOT `text[]`) -- plain equality, via the `$n::type IS NULL OR ...`
    // form precedented in
    // app/api/v1/packages/[ecosystem]/[nameEncoded]/route.ts. Secondary
    // `ORDER BY` on attack_id makes row order deterministic on tied lift.
    query<RawPoolRow>(
      `SELECT
         t.attack_id AS "attackId",
         t.name,
         stl.lift,
         stl.group_count AS "groupCount",
         (SELECT count(*) FROM technique_iocs ti
           WHERE ti.technique_id = stl.technique_id)::int AS iocs,
         (SELECT count(*) FROM report_techniques rt
           WHERE rt.technique_id = stl.technique_id)::int AS reports,
         COALESCE(ev.cve_count, 0)::int AS "cveCount",
         COALESCE(ev.kev_count, 0)::int AS "kevCount",
         ev.max_epss AS "maxEpss",
         t.platforms
       FROM sector_technique_lift stl
       JOIN techniques t ON t.id = stl.technique_id
       LEFT JOIN technique_cve_evidence ev ON ev.attack_id = t.attack_id
       WHERE stl.sector_slug = $1
         AND t.is_revoked = false AND t.is_deprecated = false
         AND ($2::text IS NULL OR t.domain = $2)
       ORDER BY stl.lift DESC, t.attack_id ASC`,
      [sector, domainFilter],
    ),

    // Groups active in this sector. threat_groups.domain is text[] --
    // `= $n` raises 22P02 (fixed in 4d4d1ac); must be `$n = ANY(tg.domain)`.
    // Secondary `ORDER BY` on attack_id keeps ordering deterministic.
    //
    // `count(*) OVER ()` is the PRE-LIMIT total: window functions are
    // evaluated before LIMIT, so this is the true number of groups in scope
    // even though only the first 20 rows come back. It rides on the query
    // that is already running rather than costing a second round trip, and
    // it exists so the briefing page can state "N groups in scope" honestly
    // instead of reporting the cap (20) as if it were the count.
    query<GroupRow>(
      `SELECT tg.attack_id AS "attackId", tg.name, tg.aliases,
              count(*) OVER ()::int AS "totalGroups"
       FROM group_sectors gs
       JOIN sectors s ON s.id = gs.sector_id
       JOIN threat_groups tg ON tg.id = gs.group_id
       WHERE s.slug = $1
         AND tg.is_revoked = false AND tg.is_deprecated = false
         AND ($2::text IS NULL OR $2 = ANY(tg.domain))
       ORDER BY tg.name ASC, tg.attack_id ASC
       LIMIT 20`,
      [sector, domainFilter],
    ),

    query<{ name: string }>(`SELECT name FROM sectors WHERE slug = $1`, [sector]),
  ]);

  const rawPool = poolResult.rows;
  const fullPool = rawPool.map(toPoolItem);

  // Platforms are a SET, and the constraint is an INTERSECTION test: keep a
  // technique if it runs on ANY of the platforms the visitor named. A `Set`
  // rather than `selected.includes(p)` for two reasons -- it is O(1) per
  // membership test over a ~200-row pool x up to 24 values, and `r.platforms`
  // is `string[]` while `platforms` is `Platform[]`, so `includes` would need
  // a cast to compile.
  const selected = new Set<string>(platforms ?? []);
  const platformPool = selected.size > 0
    ? rawPool.filter((r) => Array.isArray(r.platforms) && r.platforms.some((p) => selected.has(p))).map(toPoolItem)
    : fullPool;

  let { bandA, bandB, bandBShort } = splitBands(platformPool, sort, 6);
  // The pool each band was actually drawn from. They can differ, which is the
  // whole point of the fallback below.
  let bandAPool = platformPool;
  let bandBPool = platformPool;
  let platformDropped = false;

  // A platform constraint that matches NOTHING in this sector's pool. Distinct
  // from "Band B came up short", and it must not be treated the same way: there
  // is no platform-filtered Band A to keep, so the choice is between a blank
  // briefing and a widened one. It widens -- but says so, via
  // `meta.platformPoolEmpty`, instead of handing back a full-sector briefing
  // that looks exactly like an unanswered one.
  const platformPoolEmpty = selected.size > 0 && platformPool.length === 0;

  // Spec fallback (design doc line 120): if Band B has fewer than 6 candidates,
  // drop the platform constraint and re-select over the full sector pool,
  // labelling the widening in `meta` so the UI can say so.
  //
  // BAND B ONLY. This previously re-ran `splitBands(fullPool, …)` and took BOTH
  // bands from it, so a narrow platform pick produced a briefing identical in
  // both bands to answering the environment question with nothing at all -- the
  // visitor's answer was not widened, it was DISCARDED, silently. Band A now
  // stays on the platform-filtered pool, so the answer still shows somewhere,
  // and `selectBandB` takes the exclusion by id, which is what lets Band A come
  // from one pool and Band B from another while the six Band A techniques are
  // still kept out of Band B.
  //
  // `platformDropped` still means "the whole platform constraint was dropped"
  // for the purpose it was dropped for -- there is no partial widening. Only
  // fires when a constraint was actually applied; otherwise platformPool ===
  // fullPool already and re-selecting would be a no-op.
  if (selected.size > 0 && (bandBShort || platformPoolEmpty)) {
    if (platformPoolEmpty) {
      const widened = splitBands(fullPool, sort, 6);
      bandA = widened.bandA;
      bandB = widened.bandB;
      bandBShort = widened.bandBShort;
      bandAPool = fullPool;
    } else {
      // `splitBands` is JSDoc-typed over `Array<object>`, so `bandA` arrives
      // here as `object[]`; the cast is to the shape this route put in.
      const bandAIds = new Set((bandA as PoolItem[]).map((t) => t.attackId));
      const widened = selectBandB(fullPool, bandAIds, 6);
      bandB = widened.bandB;
      bandBShort = widened.bandBShort;
    }
    bandBPool = fullPool;
    platformDropped = true;
  }

  return withCors(jsonResponse({
    profile: {
      sector,
      sectorName: sectorResult.rows[0]?.name ?? null,
      platforms: platforms ?? null,
      // The RESOLVED domain, never null. It used to echo `domain ?? null`, so a
      // caller who omitted the parameter was handed `null` alongside a pool that
      // had silently been left unfiltered -- the one case where knowing the
      // filter mattered most was the one case the response would not state.
      domain,
      sort,
    },
    // `totalGroups` is a per-row artefact of the window function, not part of
    // the group shape -- strip it here and carry the number once, in `meta`.
    groups: groupsResult.rows.map(({ attackId, name, aliases }) => ({ attackId, name, aliases })),
    bandA,
    bandB,
    meta: {
      // The pool BAND B was selected from -- which is the full sector pool
      // whenever `platformDropped`, exactly as before this change. Band A may
      // now have come from a narrower pool; `platformDropped` is what says so.
      poolSize: bandBPool.length,
      // Total groups attributed to this sector, NOT `groups.length` (capped
      // at 20 by the query's LIMIT).
      groupCount: groupsResult.rows[0]?.totalGroups ?? 0,
      degenerate: isDegenerate(bandBPool),
      bandBShort,
      platformDropped,
      // No technique in this sector runs on the platforms the visitor named, so
      // both bands were widened rather than returned blank.
      platformPoolEmpty,
      // `?domain=all` -- a deliberate cross-domain pool. The caller asked for
      // it; this is how they can tell they got it, because a mixed pool ranks
      // ICS and ATLAS techniques (which carry no CTI or CVE evidence at all)
      // against enterprise ones in bands that are sorted by exactly that.
      mixedDomain,
      // The column Band A is sorted by is zero for every technique in the pool
      // Band A was drawn from -- so the band is an arbitrary stable-sort slice
      // under a heading that names evidence. `sort=kev` over mobile-attack or
      // atlas-attack is the live case.
      evidenceUnavailable: isEvidenceUnavailable(bandAPool, sort),
    },
  }, 3600));
}

// Bare Promise.all is what produced the 500 fixed in 4d4d1ac (one rejecting
// sub-query took the whole request with it). `withErrorHandler` in
// app/api/lib/handler.ts exists for exactly this, but its signature is
// `(...args: Parameters<typeof fetch>) => Promise<NextResponse>` -- i.e. it
// expects `(input: RequestInfo | URL, init?: RequestInit)`, not
// `(req: NextRequest)`. Wrapping this handler in it fails `tsc --noEmit`:
// "Type 'string | URL | Request' is not assignable to type 'NextRequest'."
// It has no other caller in the repo to have caught this. Verified empirically
// before writing this route; using a plain try/catch instead rather than
// bending the route to a broken helper.
export async function GET(req: NextRequest): Promise<NextResponse> {
  try {
    return await handler(req);
  } catch (err) {
    console.error('API error:', err);
    return withCors(errorResponse(500, 'Internal server error', 'INTERNAL_ERROR'));
  }
}
