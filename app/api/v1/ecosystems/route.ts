import { NextRequest } from 'next/server';
import { query } from '../lib/db';
import { jsonResponse } from '../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../lib/cors';
import {
  ECOSYSTEM_BY_CANONICAL,
  type EcosystemMeta,
} from '../../../../src/lib/ecosystems';

export { OPTIONS };

/**
 * GET /api/v1/ecosystems — aggregate stats per known ecosystem.
 *
 * Returns one row per ecosystem present in the registry at
 * `src/lib/ecosystems.ts`. DB ecosystems unknown to the registry are
 * excluded from this response (drift surfaces in the FeedStatus
 * "Ecosystem registry coverage" row).
 *
 * Hard-coded LIMIT 200 as a defense against registry bloat / DoS.
 * No client-controllable LIMIT or ORDER.
 *
 * ── PERFORMANCE SHAPE ─────────────────────────────────────────────────────
 *
 * This used to recompute the whole aggregate per request: GHSA branch + OSV
 * branch UNION ALLed, GROUP BY ecosystem, top-3 packages via ROW_NUMBER() OVER
 * PARTITION. Measured 48,671 ms through the production server, of which 40,893 ms
 * was one CTE — `GROUP BY (ecosystem, package_name)` over 8,718,078
 * osv_affected rows, spilling 7,536 kB per worker past Neon's 4 MB work_mem.
 *
 * It is now two queries:
 *
 *   1. `ecosystem_advisory_stats` — the matview
 *      (scripts/migrate-ecosystem-stats.sql). Holds every column that is
 *      time-independent: totals, the severity breakdown, and top-3 packages.
 *      `ORDER BY ord` is load-bearing: the response is a JSON array whose order
 *      was the natural output of the old UNION ALL, and REFRESH … CONCURRENTLY
 *      reshuffles matview heap order. `ord` pins it. See the migration header.
 *
 *   2. `last14d` — EXACT, not frozen at refresh time, and still cheap. It is a
 *      `NOW() - INTERVAL '14 days'` window, so it cannot live in a matview
 *      as a single number. Computing it live in full measured 32,895 ms: the
 *      index-only scan over the recent tail degrades to ~54k heap fetches
 *      because only 50% of osv_advisories pages are all-visible, and the
 *      recent tail is precisely the least-visible part. So it is split, using
 *      the identity
 *
 *        count(published >= B)
 *          = count(published >= date_trunc('day', B))     <- day matview
 *          - count(date_trunc('day', B) <= published < B) <- live remainder
 *
 *      The remainder is one sub-day slice (measured 807 rows / 1,247 ms under
 *      contention, ~100 ms quiet). Arithmetically identical to the old
 *      `FILTER (WHERE published >= NOW() - INTERVAL '14 days')`.
 *
 * Both are keyed by (src, canonical), not canonical alone, because the old
 * query computed every column per branch BEFORE the UNION ALL. If a name ever
 * appeared in both branches, summing across them would be wrong.
 */

interface RawAggRow {
  ord: number;
  src: string;
  canonical: string;
  total: string;
  crit: string;
  high: string;
  med: string;
  low: string;
  unrated: string;
  top_packages: string[] | null;
  top_counts: number[] | null;
}

interface Last14dRow {
  src: string;
  canonical: string;
  last14d: string;
}

export async function GET(_req: NextRequest) {
  // Pre-migration safety: if osv_advisories / the matview don't exist yet,
  // degrade to an empty list rather than 500ing.
  const degrade = (err: unknown) => {
    const msg = err instanceof Error ? err.message : '';
    if (!msg.includes('does not exist')) throw err;
    return { rows: [] };
  };

  const [statsRes, recentRes] = await Promise.all([
    query<RawAggRow>(
      `
      SELECT
        s.ord,
        s.src,
        s.canonical,
        s.total::text    AS total,
        s.crit::text     AS crit,
        s.high::text     AS high,
        s.med::text      AS med,
        s.low::text      AS low,
        s.unrated::text  AS unrated,
        s.top_packages,
        s.top_counts
      FROM ecosystem_advisory_stats s
      ORDER BY s.ord
      LIMIT 200
      `,
    ).catch(degrade) as Promise<{ rows: RawAggRow[] }>,

    // Per-branch 14-day counts: whole UTC days from the day matview, minus the
    // part of the boundary day that falls before the exact cutoff. A group with
    // no recent advisories simply doesn't come back here, and the `?? 0` below
    // supplies the zero the old FILTER clause produced.
    //
    // `day` is NULL for advisories with no published date; `day >= …` excludes
    // them, exactly as `published_at >= NOW() - INTERVAL '14 days'` did.
    query<Last14dRow>(
      `
      WITH b AS (SELECT NOW() - INTERVAL '14 days' AS ts),
      full_days AS (
        SELECT d.src, d.canonical, SUM(d.n)::bigint AS n
        FROM ecosystem_advisory_days d CROSS JOIN b
        WHERE d.day >= date_trunc('day', b.ts, 'UTC')
        GROUP BY d.src, d.canonical
      ),
      before_cutoff AS (
        SELECT 'GHSA'::text AS src, LOWER(p.ecosystem) AS canonical,
               COUNT(DISTINCT g.ghsa_id)::bigint AS n
        FROM ghsa_advisories g
        JOIN ghsa_packages gp ON gp.ghsa_id = g.ghsa_id
        JOIN packages p ON p.id = gp.package_id
        CROSS JOIN b
        WHERE g.withdrawn_at IS NULL
          AND g.published_at >= date_trunc('day', b.ts, 'UTC')
          AND g.published_at <  b.ts
        GROUP BY LOWER(p.ecosystem)
        UNION ALL
        SELECT 'OSV'::text AS src, o.ecosystem AS canonical, COUNT(*)::bigint AS n
        FROM osv_advisories o CROSS JOIN b
        WHERE o.published >= date_trunc('day', b.ts, 'UTC')
          AND o.published <  b.ts
        GROUP BY o.ecosystem
      )
      SELECT f.src, f.canonical, (f.n - COALESCE(x.n, 0))::text AS last14d
      FROM full_days f
      LEFT JOIN before_cutoff x ON x.src = f.src AND x.canonical = f.canonical
      `,
    ).catch(degrade) as Promise<{ rows: Last14dRow[] }>,
  ]);

  const last14dBy = new Map<string, number>();
  for (const r of recentRes.rows) {
    last14dBy.set(`${r.src}\u0000${r.canonical}`, parseInt(r.last14d, 10));
  }

  // Join each DB row to its registry entry. Rows without a registry entry
  // are silently dropped — drift surfaces in Feed Status, not here.
  const data = statsRes.rows
    .map((r) => {
      const meta: EcosystemMeta | undefined = ECOSYSTEM_BY_CANONICAL.get(r.canonical);
      if (!meta) return null;
      const topNames = r.top_packages ?? [];
      const topN = r.top_counts ?? [];
      return {
        slug: meta.slug,
        displayName: meta.displayName,
        canonical: meta.canonical,
        category: meta.category,
        totalAdvisories: parseInt(r.total, 10),
        last14dCount: last14dBy.get(`${r.src}\u0000${r.canonical}`) ?? 0,
        severityBreakdown: {
          CRITICAL: parseInt(r.crit, 10),
          HIGH: parseInt(r.high, 10),
          MEDIUM: parseInt(r.med, 10),
          LOW: parseInt(r.low, 10),
          UNRATED: parseInt(r.unrated, 10),
        },
        topPackages: topNames.slice(0, 3).map((name, i) => ({
          name,
          advisoryCount: topN[i] ?? 0,
        })),
      };
    })
    .filter(<T,>(x: T | null): x is T => x !== null);

  return withCors(jsonResponse({ data }, 300));
}
