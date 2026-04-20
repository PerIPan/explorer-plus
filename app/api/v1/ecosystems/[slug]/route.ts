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

  const statsRes = isGhsaEco
    ? await query<StatsRow>(
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
    : await query<StatsRow>(
        `SELECT
           COUNT(*)::text AS total,
           COUNT(*) FILTER (WHERE o.published >= NOW() - INTERVAL '14 days')::text AS last14d,
           COUNT(*) FILTER (WHERE o.published >= NOW() - INTERVAL '30 days')::text AS last30d,
           COUNT(*) FILTER (WHERE o.published >= NOW() - INTERVAL '30 days' AND COALESCE(o.cvss_severity, cve.cvss_severity) = 'CRITICAL')::text AS "critLast30d",
           COUNT(*) FILTER (WHERE COALESCE(o.cvss_severity, cve.cvss_severity) = 'CRITICAL')::text AS crit,
           COUNT(*) FILTER (WHERE COALESCE(o.cvss_severity, cve.cvss_severity) = 'HIGH')::text AS high,
           COUNT(*) FILTER (WHERE COALESCE(o.cvss_severity, cve.cvss_severity) = 'MEDIUM')::text AS med,
           COUNT(*) FILTER (WHERE COALESCE(o.cvss_severity, cve.cvss_severity) = 'LOW')::text AS low,
           COUNT(*) FILTER (WHERE COALESCE(o.cvss_severity, cve.cvss_severity) IS NULL)::text AS unrated
         FROM osv_advisories o
         LEFT JOIN LATERAL (
           SELECT cd.cvss_severity FROM cve_details cd
           WHERE cd.cve_id = ANY(o.aliases) LIMIT 1
         ) cve ON true
         WHERE o.ecosystem = $1`,
        [meta.canonical],
      );
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

  // --- Top packages ---------------------------------------------------------

  interface TopPkgRow {
    packageName: string;
    advisoryCount: string;
  }

  const topPkgsRes = isGhsaEco
    ? await query<TopPkgRow>(
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
    : await query<TopPkgRow>(
        `SELECT oa.package_name AS "packageName",
                COUNT(*)::text AS "advisoryCount"
         FROM osv_affected oa
         WHERE oa.ecosystem = $1
         GROUP BY oa.package_name
         ORDER BY COUNT(*) DESC, oa.package_name ASC
         LIMIT ${TOP_PACKAGES}`,
        [meta.canonical],
      );

  const topPackages = topPkgsRes.rows.map((r) => ({
    packageName: r.packageName,
    advisoryCount: parseInt(r.advisoryCount, 10),
  }));

  // --- Recent advisories ----------------------------------------------------

  interface RecentRow {
    advisoryId: string;
    source: 'GHSA' | 'OSV';
    cveId: string | null;
    summary: string | null;
    severity: string | null;
    cvssScore: string | null;
    publishedAt: string | null;
  }

  const recentRes = isGhsaEco
    ? await query<RecentRow>(
        `SELECT DISTINCT
                g.ghsa_id         AS "advisoryId",
                'GHSA'::text      AS source,
                g.cve_id          AS "cveId",
                g.summary         AS summary,
                g.severity        AS severity,
                g.cvss_score::text AS "cvssScore",
                g.published_at    AS "publishedAt"
         FROM ghsa_advisories g
         JOIN ghsa_packages gp ON gp.ghsa_id = g.ghsa_id
         JOIN packages p ON p.id = gp.package_id
         WHERE g.withdrawn_at IS NULL AND LOWER(p.ecosystem) = $1
         ORDER BY
           CASE g.severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3
                           WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END DESC,
           g.published_at DESC NULLS LAST
         LIMIT ${RECENT_ADVISORIES}`,
        [meta.canonical],
      )
    : await query<RecentRow>(
        `SELECT
           o.osv_id          AS "advisoryId",
           'OSV'::text       AS source,
           (SELECT a FROM unnest(o.aliases) a WHERE a LIKE 'CVE-%' LIMIT 1) AS "cveId",
           o.summary         AS summary,
           COALESCE(o.cvss_severity, cve.cvss_severity) AS severity,
           COALESCE(o.cvss_score, cve.cvss_score)::text AS "cvssScore",
           o.published       AS "publishedAt"
         FROM osv_advisories o
         LEFT JOIN LATERAL (
           SELECT cd.cvss_severity, cd.cvss_score FROM cve_details cd
           WHERE cd.cve_id = ANY(o.aliases) LIMIT 1
         ) cve ON true
         WHERE o.ecosystem = $1
         ORDER BY
           CASE COALESCE(o.cvss_severity, cve.cvss_severity)
             WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3
             WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END DESC,
           o.published DESC NULLS LAST
         LIMIT ${RECENT_ADVISORIES}`,
        [meta.canonical],
      );

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
