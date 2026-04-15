import { NextRequest } from 'next/server';
import { query } from '../../../lib/db';
import { jsonResponse, errorResponse } from '../../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../../lib/cors';

export { OPTIONS };

const ECOSYSTEM_RE = /^[a-z][a-z0-9-]{1,49}$/;

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ ecosystem: string; nameEncoded: string }> },
) {
  const { ecosystem: rawEco, nameEncoded: rawName } = await params;

  const ecosystem = rawEco.toLowerCase();
  if (!ECOSYSTEM_RE.test(ecosystem)) {
    return withCors(errorResponse(400, 'Invalid ecosystem', 'VALIDATION_ERROR'));
  }

  let packageName: string;
  try {
    packageName = decodeURIComponent(rawName);
  } catch {
    return withCors(errorResponse(400, 'Invalid package name encoding', 'VALIDATION_ERROR'));
  }

  if (!packageName || packageName.length > 500) {
    return withCors(errorResponse(400, 'Invalid package name', 'VALIDATION_ERROR'));
  }

  const includeWithdrawn = req.nextUrl.searchParams.get('include_withdrawn') === '1';

  const pkgResult = await query<{
    id: string;
    ecosystem: string;
    packageName: string;
    purl: string | null;
  }>(
    `SELECT id, ecosystem, package_name AS "packageName", purl
     FROM packages
     WHERE ecosystem = $1 AND package_name = $2
     LIMIT 1`,
    [ecosystem, packageName],
  );

  if (pkgResult.rows.length === 0) {
    return withCors(errorResponse(404, 'Package not found', 'NOT_FOUND'));
  }

  const pkg = pkgResult.rows[0];

  // Parameterized withdrawn filter: $2 = null when includeWithdrawn, otherwise 'excluded'.
  // The SQL below short-circuits to no-op when $2 is null.
  const excludeWithdrawn = includeWithdrawn ? null : 'excluded';

  const [advResult, techResult] = await Promise.all([
    query<{
      ghsaId: string;
      cveId: string | null;
      summary: string | null;
      severity: string | null;
      cvssScore: string | null;
      publishedAt: string;
      withdrawnAt: string | null;
      vulnerableRange: string | null;
      fixedVersion: string | null;
    }>(
      `SELECT
         g.ghsa_id                 AS "ghsaId",
         g.cve_id                  AS "cveId",
         g.summary,
         g.severity,
         g.cvss_score              AS "cvssScore",
         g.published_at            AS "publishedAt",
         g.withdrawn_at            AS "withdrawnAt",
         gp.vulnerable_range       AS "vulnerableRange",
         gp.fixed_version          AS "fixedVersion"
       FROM ghsa_packages gp
       JOIN ghsa_advisories g ON g.ghsa_id = gp.ghsa_id
       WHERE gp.package_id = $1
         AND ($2::text IS NULL OR g.withdrawn_at IS NULL)
       ORDER BY g.published_at DESC NULLS LAST, g.ghsa_id DESC`,
      [pkg.id, excludeWithdrawn],
    ),
    query<{ attackId: string; name: string }>(
      `SELECT DISTINCT t.attack_id AS "attackId", t.name
       FROM ghsa_packages gp
       JOIN ghsa_advisories g ON g.ghsa_id = gp.ghsa_id
         AND ($2::text IS NULL OR g.withdrawn_at IS NULL)
       JOIN ghsa_weaknesses w ON w.ghsa_id = g.ghsa_id
       JOIN capec_mappings cm ON cm.cwe_id = w.cwe_id AND cm.technique_id IS NOT NULL
       JOIN techniques t ON t.id = cm.technique_id
       WHERE gp.package_id = $1
       ORDER BY t.attack_id`,
      [pkg.id, excludeWithdrawn],
    ),
  ]);

  // Severity counts
  const severityCounts: Record<string, number> = {};
  for (const adv of advResult.rows) {
    if (adv.severity) {
      severityCounts[adv.severity] = (severityCounts[adv.severity] ?? 0) + 1;
    }
  }

  const advisories = advResult.rows.map((r) => ({
    ghsaId: r.ghsaId,
    cveId: r.cveId,
    summary: r.summary,
    severity: r.severity,
    cvssScore: r.cvssScore ? parseFloat(r.cvssScore) : null,
    publishedAt: r.publishedAt,
    withdrawnAt: r.withdrawnAt,
    packageCount: 1,
    ecosystems: [pkg.ecosystem],
    techniqueCount: 0,
    vulnerableRange: r.vulnerableRange,
    fixedVersion: r.fixedVersion,
  }));

  return withCors(
    jsonResponse(
      {
        packageId: pkg.id,
        ecosystem: pkg.ecosystem,
        packageName: pkg.packageName,
        purl: pkg.purl,
        advisoryCount: advisories.length,
        severityCounts,
        advisories,
        linkedTechniques: techResult.rows,
      },
      3600,
    ),
  );
}
