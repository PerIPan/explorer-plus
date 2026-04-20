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
 * Query shape: GHSA branch + OSV branch UNION ALLed, GROUP BY ecosystem,
 * top-3 packages via a CTE with ROW_NUMBER() OVER PARTITION.
 *
 * Hard-coded LIMIT 200 as a defense against registry bloat / DoS.
 * No client-controllable LIMIT or ORDER.
 */

interface RawAggRow {
  canonical: string;
  total: string;
  last14d: string;
  crit: string;
  high: string;
  med: string;
  low: string;
  unrated: string;
  top_packages: string[] | null;
  top_counts: number[] | null;
}

export async function GET(_req: NextRequest) {
  const rows = await query<RawAggRow>(
    `
    WITH ghsa_pkg_counts AS (
      SELECT LOWER(p.ecosystem) AS eco, p.package_name AS pkg, COUNT(*)::int AS n
      FROM ghsa_advisories g
      JOIN ghsa_packages gp ON gp.ghsa_id = g.ghsa_id
      JOIN packages p ON p.id = gp.package_id
      WHERE g.withdrawn_at IS NULL
      GROUP BY LOWER(p.ecosystem), p.package_name
    ),
    osv_pkg_counts AS (
      SELECT oa.ecosystem AS eco, oa.package_name AS pkg, COUNT(*)::int AS n
      FROM osv_affected oa
      GROUP BY oa.ecosystem, oa.package_name
    ),
    combined_pkg_counts AS (
      SELECT eco, pkg, SUM(n)::int AS n FROM (
        SELECT * FROM ghsa_pkg_counts
        UNION ALL
        SELECT * FROM osv_pkg_counts
      ) u GROUP BY eco, pkg
    ),
    top_pkgs AS (
      SELECT eco, pkg, n,
             ROW_NUMBER() OVER (PARTITION BY eco ORDER BY n DESC, pkg ASC) AS rk
      FROM combined_pkg_counts
    ),
    top3 AS (
      SELECT eco,
             ARRAY_AGG(pkg ORDER BY rk) FILTER (WHERE rk <= 3)  AS top_packages,
             ARRAY_AGG(n   ORDER BY rk) FILTER (WHERE rk <= 3)  AS top_counts
      FROM top_pkgs
      GROUP BY eco
    ),
    ghsa_agg AS (
      SELECT
        LOWER(p.ecosystem) AS canonical,
        COUNT(DISTINCT g.ghsa_id)::int AS total,
        COUNT(DISTINCT g.ghsa_id) FILTER (WHERE g.published_at >= NOW() - INTERVAL '14 days')::int AS last14d,
        COUNT(DISTINCT g.ghsa_id) FILTER (WHERE g.severity = 'CRITICAL')::int AS crit,
        COUNT(DISTINCT g.ghsa_id) FILTER (WHERE g.severity = 'HIGH')::int AS high,
        COUNT(DISTINCT g.ghsa_id) FILTER (WHERE g.severity = 'MEDIUM')::int AS med,
        COUNT(DISTINCT g.ghsa_id) FILTER (WHERE g.severity = 'LOW')::int AS low,
        COUNT(DISTINCT g.ghsa_id) FILTER (WHERE g.severity IS NULL)::int AS unrated
      FROM ghsa_advisories g
      JOIN ghsa_packages gp ON gp.ghsa_id = g.ghsa_id
      JOIN packages p ON p.id = gp.package_id
      WHERE g.withdrawn_at IS NULL
      GROUP BY LOWER(p.ecosystem)
    ),
    osv_agg AS (
      SELECT
        o.ecosystem AS canonical,
        COUNT(*)::int AS total,
        COUNT(*) FILTER (WHERE o.published >= NOW() - INTERVAL '14 days')::int AS last14d,
        COUNT(*) FILTER (WHERE COALESCE(o.cvss_severity, cve.cvss_severity) = 'CRITICAL')::int AS crit,
        COUNT(*) FILTER (WHERE COALESCE(o.cvss_severity, cve.cvss_severity) = 'HIGH')::int AS high,
        COUNT(*) FILTER (WHERE COALESCE(o.cvss_severity, cve.cvss_severity) = 'MEDIUM')::int AS med,
        COUNT(*) FILTER (WHERE COALESCE(o.cvss_severity, cve.cvss_severity) = 'LOW')::int AS low,
        COUNT(*) FILTER (WHERE COALESCE(o.cvss_severity, cve.cvss_severity) IS NULL)::int AS unrated
      FROM osv_advisories o
      LEFT JOIN LATERAL (
        SELECT cd.cvss_severity FROM cve_details cd
        WHERE cd.cve_id = ANY(o.aliases) LIMIT 1
      ) cve ON true
      GROUP BY o.ecosystem
    ),
    all_agg AS (
      SELECT * FROM ghsa_agg
      UNION ALL
      SELECT * FROM osv_agg
    )
    SELECT
      a.canonical,
      a.total::text AS total,
      a.last14d::text AS last14d,
      a.crit::text AS crit,
      a.high::text AS high,
      a.med::text AS med,
      a.low::text AS low,
      a.unrated::text AS unrated,
      t.top_packages,
      t.top_counts
    FROM all_agg a
    LEFT JOIN top3 t ON t.eco = a.canonical
    LIMIT 200
    `,
  ).catch((err: unknown) => {
    // Pre-migration safety: if osv_advisories doesn't exist yet, degrade.
    const msg = err instanceof Error ? err.message : '';
    if (!msg.includes('does not exist')) throw err;
    return { rows: [] as RawAggRow[] };
  });

  // Join each DB row to its registry entry. Rows without a registry entry
  // are silently dropped — drift surfaces in Feed Status, not here.
  const data = rows.rows
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
        last14dCount: parseInt(r.last14d, 10),
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
