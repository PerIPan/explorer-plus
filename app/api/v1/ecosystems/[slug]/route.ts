import { NextRequest } from 'next/server';
import { z } from 'zod';
import { query } from '../../lib/db';
import { jsonResponse, errorResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';
import { ECOSYSTEM_REGISTRY, safeHref } from '../../../../../src/lib/ecosystems';

export { OPTIONS };

/**
 * GET /api/v1/ecosystems/[slug] — per-ecosystem dashboard payload.
 *
 * Resolves slug → registry metadata → canonical DB name. Returns stats,
 * severity breakdown, top packages, and recent advisories in a single
 * bundle for the detail page.
 *
 * All LIMITs are hard-coded constants (no env / query-param knobs) —
 * DoS defense.
 */

const slugSchema = z.string().regex(/^[a-z0-9-]+$/).min(1).max(64);

const TOP_PACKAGES = 10;
const RECENT_ADVISORIES = 20;

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ slug: string }> },
) {
  const { slug: rawSlug } = await params;

  const parsed = slugSchema.safeParse(rawSlug);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Invalid slug', 'VALIDATION_ERROR'));
  }
  const meta = ECOSYSTEM_REGISTRY.get(parsed.data);
  if (!meta) {
    return withCors(errorResponse(404, 'Ecosystem not found', 'NOT_FOUND'));
  }

  // From here on, queries bind `meta.canonical` (our own code, safe) —
  // never the raw user input.
  const isGhsaEco = meta.category === 'package-manager';

  // --- Stats strip -----------------------------------------------------------

  interface StatsRow {
    total: string;
    last14d: string;
    last30d: string;
    critLast30d: string;
    crit: string;
    high: string;
    med: string;
    low: string;
    unrated: string;
  }

  // Stats / top-packages / recent-advisories are independent queries — run them
  // in parallel to cut wall-clock by ~2-3× (was sequential awaits).
  const statsPromise = isGhsaEco
    ? query<StatsRow>(
        `SELECT
           COUNT(DISTINCT g.ghsa_id)::text AS total,
           COUNT(DISTINCT g.ghsa_id) FILTER (WHERE g.published_at >= NOW() - INTERVAL '14 days')::text AS last14d,
           COUNT(DISTINCT g.ghsa_id) FILTER (WHERE g.published_at >= NOW() - INTERVAL '30 days')::text AS last30d,
           COUNT(DISTINCT g.ghsa_id) FILTER (WHERE g.published_at >= NOW() - INTERVAL '30 days' AND g.severity = 'CRITICAL')::text AS "critLast30d",
           COUNT(DISTINCT g.ghsa_id) FILTER (WHERE g.severity = 'CRITICAL')::text AS crit,
           COUNT(DISTINCT g.ghsa_id) FILTER (WHERE g.severity = 'HIGH')::text AS high,
           COUNT(DISTINCT g.ghsa_id) FILTER (WHERE g.severity = 'MEDIUM')::text AS med,
           COUNT(DISTINCT g.ghsa_id) FILTER (WHERE g.severity = 'LOW')::text AS low,
           COUNT(DISTINCT g.ghsa_id) FILTER (WHERE g.severity IS NULL)::text AS unrated
         FROM ghsa_advisories g
         JOIN ghsa_packages gp ON gp.ghsa_id = g.ghsa_id
         JOIN packages p ON p.id = gp.package_id
         WHERE g.withdrawn_at IS NULL AND LOWER(p.ecosystem) = $1`,
        [meta.canonical],
      )
    : // Read from osv_advisory_rank, not osv_advisories. `sev_rank` there IS
      // `COALESCE(o.cvss_severity, cve.cvss_severity)` already materialised
      // (scripts/migrate-advisory-rank.sql), so this drops the per-row LATERAL
      // into cve_details that made the old version scan the whole ecosystem.
      // osv_advisory_rank_eco_order_idx leads on `ecosystem`, so all nine
      // counts come from one index scan of this ecosystem's slice.
      //
      // Measured 2026-10-02, this query vs the LATERAL version it replaces:
      // Julia 0.15s · Alpine 0.05s · Linux 0.18s · Ubuntu 0.38s · Debian 0.41s,
      // against 16-43s end-to-end for the route before the change (Ubuntu's
      // old top-packages query could not complete at all).
      //
      // Verified equal to the live LATERAL counts for Julia:
      // 1717/158/653/754/110/42 from both.
      //
      // sev_rank is as of the last refresh of osv_advisory_rank (daily, see
      // .github/workflows/refresh-matview.yml) while `recentAdvisories` below
      // still reports live severity, so a row whose cve_details severity moved
      // since the refresh can be counted in one bucket and displayed as
      // another. That trade is already made and documented in
      // scripts/migrate-advisory-rank.sql; it is not new here.
      query<StatsRow>(
        `SELECT
           COUNT(*)::text AS total,
           COUNT(*) FILTER (WHERE r.published >= NOW() - INTERVAL '14 days')::text AS last14d,
           COUNT(*) FILTER (WHERE r.published >= NOW() - INTERVAL '30 days')::text AS last30d,
           COUNT(*) FILTER (WHERE r.published >= NOW() - INTERVAL '30 days' AND r.sev_rank = 4)::text AS "critLast30d",
           COUNT(*) FILTER (WHERE r.sev_rank = 4)::text AS crit,
           COUNT(*) FILTER (WHERE r.sev_rank = 3)::text AS high,
           COUNT(*) FILTER (WHERE r.sev_rank = 2)::text AS med,
           COUNT(*) FILTER (WHERE r.sev_rank = 1)::text AS low,
           COUNT(*) FILTER (WHERE r.sev_rank = 0)::text AS unrated
         FROM osv_advisory_rank r
         WHERE r.ecosystem = $1`,
        [meta.canonical],
      );

  // --- Top packages query (parallel) ---------------------------------------

  interface TopPkgRow {
    packageName: string;
    advisoryCount: string;
  }

  const topPkgsPromise = isGhsaEco
    ? query<TopPkgRow>(
        `SELECT p.package_name AS "packageName",
                COUNT(DISTINCT g.ghsa_id)::text AS "advisoryCount"
         FROM ghsa_advisories g
         JOIN ghsa_packages gp ON gp.ghsa_id = g.ghsa_id
         JOIN packages p ON p.id = gp.package_id
         WHERE g.withdrawn_at IS NULL AND LOWER(p.ecosystem) = $1
         GROUP BY p.package_name
         ORDER BY COUNT(DISTINCT g.ghsa_id) DESC, p.package_name ASC
         LIMIT ${TOP_PACKAGES}`,
        [meta.canonical],
      )
    : // `GROUP BY package_name` over osv_affected has no index to use:
      // idx_osv_affected_pkg leads on `package_ecosystem`, which is a DIFFERENT
      // taxonomy from `ecosystem` (169,525 of 200,000 sampled rows differ, and
      // `package_ecosystem = 'Ubuntu'` matches nothing). So the old query was a
      // full aggregate over 8.7M rows: measured 19.0s for Alpine and no
      // completion at all for Ubuntu.
      //
      // ecosystem_advisory_stats already materialises this exact ranking. Two
      // caveats, both deliberate:
      //   - it currently stores the top 3, not TOP_PACKAGES; raising it is a
      //     one-line change in scripts/migrate-ecosystem-stats.sql, and until
      //     that migration runs this returns 3. Fewer rows, not wrong rows.
      //   - it refreshes weekly (vercel.json, `0 3 * * 0`), so the counts lag
      //     the stats strip above, which reads the daily osv_advisory_rank.
      // Both beat an endpoint that cannot answer.
      query<TopPkgRow>(
        `SELECT pkg AS "packageName", n::text AS "advisoryCount"
         FROM ecosystem_advisory_stats s
         CROSS JOIN LATERAL unnest(s.top_packages, s.top_counts) AS u(pkg, n)
         WHERE s.src = 'OSV' AND s.canonical = $1
         ORDER BY n DESC, pkg ASC
         LIMIT ${TOP_PACKAGES}`,
        [meta.canonical],
      );

  // --- Recent advisories query (parallel) ----------------------------------

  interface RecentRow {
    advisoryId: string;
    source: 'GHSA' | 'OSV';
    cveId: string | null;
    summary: string | null;
    severity: string | null;
    cvssScore: string | null;
    publishedAt: string | null;
  }

  const recentPromise = isGhsaEco
    ? query<RecentRow>(
        `SELECT
            g.ghsa_id         AS "advisoryId",
            'GHSA'::text      AS source,
            g.cve_id          AS "cveId",
            g.summary         AS summary,
            g.severity        AS severity,
            g.cvss_score::text AS "cvssScore",
            g.published_at    AS "publishedAt"
         FROM ghsa_advisories g
         WHERE g.withdrawn_at IS NULL
           AND EXISTS (
             SELECT 1 FROM ghsa_packages gp
             JOIN packages p ON p.id = gp.package_id
             WHERE gp.ghsa_id = g.ghsa_id AND LOWER(p.ecosystem) = $1
           )
         ORDER BY
           CASE g.severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3
                           WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END DESC,
           g.published_at DESC NULLS LAST
         LIMIT ${RECENT_ADVISORIES}`,
        [meta.canonical],
      )
    : // Two stages, for the same reason /api/v1/advisories uses them: the old
      // single-stage query ORDER BY'd a value computed from a LATERAL, which is
      // not an indexable sort key, so Postgres had to evaluate the lateral for
      // every advisory in the ecosystem before it could apply LIMIT 20.
      //
      // Stage 1 takes the 20 keys straight off osv_advisory_rank_eco_order_idx
      // -- (ecosystem, sev_rank DESC, published DESC NULLS LAST, osv_id DESC)
      // is exactly this ORDER BY, so it is a 20-row index walk (0.01s measured
      // for Ubuntu). Stage 2 joins back for the display columns and pays the
      // LATERAL on 20 rows instead of ~69,000.
      //
      // osv_id DESC is a deliberate addition: the previous ORDER BY had no
      // tiebreaker, so rows of equal severity and timestamp came back in an
      // arbitrary order that could change between requests. Matching the index
      // makes the page stable as well as fast.
      //
      // Ubuntu/distro OSV rows often have a NULL summary; fall back to the
      // first 240 chars of details so the inline preview + tooltip have copy.
      query<RecentRow>(
        `WITH keys AS (
           SELECT r.osv_id, r.ecosystem, r.sev_rank, r.published
           FROM osv_advisory_rank r
           WHERE r.ecosystem = $1
           ORDER BY r.sev_rank DESC, r.published DESC NULLS LAST, r.osv_id DESC
           LIMIT ${RECENT_ADVISORIES}
         )
         SELECT
           o.osv_id          AS "advisoryId",
           'OSV'::text       AS source,
           (SELECT a FROM unnest(o.aliases) a WHERE a LIKE 'CVE-%' LIMIT 1) AS "cveId",
           LEFT(COALESCE(NULLIF(o.summary, ''), o.details), 240) AS summary,
           COALESCE(o.cvss_severity, cve.cvss_severity) AS severity,
           COALESCE(o.cvss_score, cve.cvss_score)::text AS "cvssScore",
           o.published       AS "publishedAt"
         FROM keys k
         JOIN osv_advisories o
           ON o.osv_id = k.osv_id AND o.ecosystem = k.ecosystem
         LEFT JOIN LATERAL (
           SELECT cd.cvss_severity, cd.cvss_score FROM cve_details cd
           WHERE cd.cve_id = ANY(o.aliases) LIMIT 1
         ) cve ON true
         ORDER BY k.sev_rank DESC, k.published DESC NULLS LAST, k.osv_id DESC`,
        [meta.canonical],
      );

  const [statsRes, topPkgsRes, recentRes] = await Promise.all([
    statsPromise,
    topPkgsPromise,
    recentPromise,
  ]);

  const s = statsRes.rows[0];
  const stats = s
    ? {
        total: parseInt(s.total, 10),
        last14d: parseInt(s.last14d, 10),
        last30d: parseInt(s.last30d, 10),
        criticalLast30d: parseInt(s.critLast30d, 10),
      }
    : { total: 0, last14d: 0, last30d: 0, criticalLast30d: 0 };

  const severityBreakdown = s
    ? {
        CRITICAL: parseInt(s.crit, 10),
        HIGH: parseInt(s.high, 10),
        MEDIUM: parseInt(s.med, 10),
        LOW: parseInt(s.low, 10),
        UNRATED: parseInt(s.unrated, 10),
      }
    : { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNRATED: 0 };

  const topPackages = topPkgsRes.rows.map((r) => ({
    packageName: r.packageName,
    advisoryCount: parseInt(r.advisoryCount, 10),
  }));

  const recentAdvisories = recentRes.rows.map((r) => ({
    advisoryId: r.advisoryId,
    source: r.source,
    cveId: r.cveId,
    summary: r.summary,
    severity: r.severity,
    cvssScore: r.cvssScore ? parseFloat(r.cvssScore) : null,
    publishedAt: r.publishedAt,
  }));

  return withCors(
    jsonResponse(
      {
        slug: meta.slug,
        meta: {
          displayName: meta.displayName,
          canonical: meta.canonical,
          category: meta.category,
          homepage: safeHref(meta.homepage),
          description: meta.description,
        },
        stats,
        severityBreakdown,
        topPackages,
        recentAdvisories,
      },
      3600,
    ),
  );
}
