import { NextRequest } from 'next/server';
import { query } from '../../lib/db';
import { jsonResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';

export { OPTIONS };

export async function GET(req: NextRequest) {
  const daysRaw = parseInt(req.nextUrl.searchParams.get('days') ?? '10', 10);
  // Cap at 30 days — this endpoint aggregates uncached across 3-way joins on every request.
  const days = Number.isFinite(daysRaw) && daysRaw > 0 && daysRaw <= 30 ? daysRaw : 10;
  const limit = 7;

  // DST-safe: step back N calendar days rather than N × 86400000 ms.
  const sinceDate = new Date();
  sinceDate.setDate(sinceDate.getDate() - days);
  const sinceIso = sinceDate.toISOString();

  const appsPromise = query<{
    normalized: string;
    vendor: string;
    product: string;
    cveCount: string;
    latestPublished: string;
  }>(
    `SELECT
       a.normalized,
       a.vendor,
       a.product,
       COUNT(DISTINCT ap.cve_id) AS "cveCount",
       MAX(cd.published_at)       AS "latestPublished"
     FROM cve_details cd
     JOIN affected_products ap ON ap.cve_id = cd.cve_id
     JOIN applications a ON a.id = ap.application_id
     WHERE cd.published_at >= $1::timestamptz
     GROUP BY a.normalized, a.vendor, a.product
     ORDER BY MAX(cd.published_at) DESC NULLS LAST
     LIMIT $2`,
    [sinceIso, limit],
  ).catch(() => ({ rows: [] as Array<{
    normalized: string; vendor: string; product: string; cveCount: string; latestPublished: string;
  }>}));

  const pkgsPromise = query<{
    ecosystem: string;
    packageName: string;
    advisoryCount: string;
    latestPublished: string;
  }>(
    `SELECT
       p.ecosystem,
       p.package_name             AS "packageName",
       COUNT(DISTINCT gp.ghsa_id) AS "advisoryCount",
       MAX(g.published_at)        AS "latestPublished"
     FROM ghsa_advisories g
     JOIN ghsa_packages gp ON gp.ghsa_id = g.ghsa_id
     JOIN packages p       ON p.id = gp.package_id
     WHERE g.published_at >= $1::timestamptz
       AND g.withdrawn_at IS NULL
     GROUP BY p.ecosystem, p.package_name
     ORDER BY MAX(g.published_at) DESC NULLS LAST
     LIMIT $2`,
    [sinceIso, limit],
  ).catch(() => ({ rows: [] as Array<{
    ecosystem: string; packageName: string; advisoryCount: string; latestPublished: string;
  }>}));

  const [appsResult, pkgsResult] = await Promise.all([appsPromise, pkgsPromise]);

  return withCors(jsonResponse({
    days,
    applications: appsResult.rows.map((r) => ({
      normalized: r.normalized,
      vendor: r.vendor,
      product: r.product,
      cveCount: parseInt(r.cveCount, 10),
      latestPublished: r.latestPublished,
    })),
    packages: pkgsResult.rows.map((r) => ({
      ecosystem: r.ecosystem,
      packageName: r.packageName,
      advisoryCount: parseInt(r.advisoryCount, 10),
      latestPublished: r.latestPublished,
    })),
  }, 1800));
}
