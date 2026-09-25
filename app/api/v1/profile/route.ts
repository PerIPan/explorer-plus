import { NextRequest, NextResponse } from 'next/server';
import { query } from '../lib/db';
import { jsonResponse, errorResponse } from '../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../lib/cors';
import { profileQuerySchema, domainSchema } from '../lib/validate';
import { splitBands, isDegenerate } from '../../../../src/lib/profile-rank.mjs';

export { OPTIONS };

// `domain` is not part of `profileQuerySchema` (Task 5 brief §1 lists sector/
// platform/sort only — a later task owns widening the schema). It is still a
// legitimate filter for this assembler, so it is composed on locally, the
// same way app/api/v1/search/route.ts and app/api/v1/dashboard/route.ts pull
// in the shared `domainSchema` piece rather than duplicating the enum.
const querySchema = profileQuerySchema.extend({ domain: domainSchema });

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

  const { sector, platform, sort, domain } = parsed.data;

  // Sector carries the whole IT ranking engine (lift is meaningless without
  // one). No sector selected -> no pool, no groups, nothing to rank; this is
  // a valid, non-error state (Optionality table: "Sector empty (IT)").
  if (!sector) {
    return withCors(jsonResponse({
      profile: { sector: null, platform: platform ?? null, domain: domain ?? null, sort },
      groups: [],
      bandA: [],
      bandB: [],
      meta: { poolSize: 0, degenerate: true, bandBShort: true, platformDropped: false, reason: 'no-sector' },
    }, 3600));
  }

  const [poolResult, groupsResult, sectorResult] = await Promise.all([
    // Technique pool for this sector: lift + group_count from the
    // precomputed matview, joined against live evidence (IOC sightings, CTI
    // report mentions, CVE/KEV/EPSS). `platforms` rides along unfiltered --
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
         COALESCE(io.iocs, 0)::int AS iocs,
         COALESCE(rp.reports, 0)::int AS reports,
         COALESCE(ev.cve_count, 0)::int AS "cveCount",
         COALESCE(ev.kev_count, 0)::int AS "kevCount",
         ev.max_epss AS "maxEpss",
         t.platforms
       FROM sector_technique_lift stl
       JOIN techniques t ON t.id = stl.technique_id
       LEFT JOIN technique_cve_evidence ev ON ev.attack_id = t.attack_id
       LEFT JOIN (
         SELECT technique_id, count(*)::int AS iocs
         FROM technique_iocs GROUP BY 1
       ) io ON io.technique_id = stl.technique_id
       LEFT JOIN (
         SELECT technique_id, count(*)::int AS reports
         FROM report_techniques GROUP BY 1
       ) rp ON rp.technique_id = stl.technique_id
       WHERE stl.sector_slug = $1
         AND t.is_revoked = false AND t.is_deprecated = false
         AND ($2::text IS NULL OR t.domain = $2)
       ORDER BY stl.lift DESC, t.attack_id ASC`,
      [sector, domain ?? null],
    ),

    // Groups active in this sector. threat_groups.domain is text[] --
    // `= $n` raises 22P02 (fixed in 4d4d1ac); must be `$n = ANY(tg.domain)`.
    // Secondary `ORDER BY` on attack_id keeps ordering deterministic.
    query<GroupRow>(
      `SELECT tg.attack_id AS "attackId", tg.name, tg.aliases
       FROM group_sectors gs
       JOIN sectors s ON s.id = gs.sector_id
       JOIN threat_groups tg ON tg.id = gs.group_id
       WHERE s.slug = $1
         AND tg.is_revoked = false AND tg.is_deprecated = false
         AND ($2::text IS NULL OR $2 = ANY(tg.domain))
       ORDER BY tg.name ASC, tg.attack_id ASC
       LIMIT 20`,
      [sector, domain ?? null],
    ),

    query<{ name: string }>(`SELECT name FROM sectors WHERE slug = $1`, [sector]),
  ]);

  const rawPool = poolResult.rows;
  const fullPool = rawPool.map(toPoolItem);
  const platformPool = platform
    ? rawPool.filter((r) => Array.isArray(r.platforms) && r.platforms.includes(platform)).map(toPoolItem)
    : fullPool;

  let { bandA, bandB, bandBShort } = splitBands(platformPool, sort, 6);
  let effectivePool = platformPool;
  let platformDropped = false;

  // Spec fallback: if Band B has fewer than 6 candidates, drop the platform
  // constraint and re-select over the full sector pool, labelling the
  // widening in `meta` so the UI can say so. Only fires when a platform was
  // actually applied -- otherwise platformPool === fullPool already and
  // re-selecting would be a no-op.
  if (bandBShort && platform) {
    const widened = splitBands(fullPool, sort, 6);
    bandA = widened.bandA;
    bandB = widened.bandB;
    bandBShort = widened.bandBShort;
    effectivePool = fullPool;
    platformDropped = true;
  }

  return withCors(jsonResponse({
    profile: {
      sector,
      sectorName: sectorResult.rows[0]?.name ?? null,
      platform: platform ?? null,
      domain: domain ?? null,
      sort,
    },
    groups: groupsResult.rows,
    bandA,
    bandB,
    meta: {
      poolSize: effectivePool.length,
      degenerate: isDegenerate(effectivePool),
      bandBShort,
      platformDropped,
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
