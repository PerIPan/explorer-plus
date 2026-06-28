import { NextRequest } from 'next/server';
import { query } from '../../../lib/db';
import { jsonResponse, errorResponse } from '../../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../../lib/cors';
import { notCatchallCwe } from '../../../lib/inference';

export { OPTIONS };

const ECOSYSTEM_RE = /^[a-z][a-z0-9-]{1,49}$/;

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ ecosystem: string; nameEncoded: string }> },
) {
  const { ecosystem: rawEco, nameEncoded: rawName } = await params;

  // Ecosystems can be either lowercase (GHSA-tracked: npm, pypi, …) or
  // case-preserved (OSV-tracked: Ubuntu, Debian, Alpine, …). Validate the
  // lowercased form for the regex check but preserve original case for OSV lookup.
  const ecosystemLc = rawEco.toLowerCase();
  if (!ECOSYSTEM_RE.test(ecosystemLc)) {
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
    [ecosystemLc, packageName],
  );

  // Not in GHSA packages — fall back to OSV-tracked packages (Ubuntu/Debian/
  // Alpine/Android/Rocky/Alma/SUSE/etc.). osv_affected stores ecosystem with
  // case preserved as the user provided in the URL.
  if (pkgResult.rows.length === 0) {
    return handleOsvPackage(rawEco, packageName);
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
       JOIN capec_mappings cm ON cm.cwe_id = w.cwe_id AND cm.technique_id IS NOT NULL AND ${notCatchallCwe('cm.cwe_id')}
       JOIN techniques t ON t.id = cm.technique_id AND t.is_revoked = false AND t.is_deprecated = false
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
        source: 'GHSA',
        advisoryCount: advisories.length,
        severityCounts,
        advisories,
        linkedTechniques: techResult.rows,
      },
      3600,
    ),
  );
}

/** OSV-sourced package detail (Ubuntu, Debian, Alpine, Android, etc.).
 *  Shape kept compatible with the GHSA path so PackageDetail.tsx renders
 *  the same component — distinguished by source='OSV'. ghsaId carries the
 *  OSV native id (DSA-/USN-/ALAS-/etc.). */
async function handleOsvPackage(rawEco: string, packageName: string) {
  // Single case-insensitive lookup — no N+1 loop. Returns the stored
  // ecosystem value (case preserved) so subsequent queries use the same form.
  const resolve = await query<{ ecosystem: string }>(
    `SELECT ecosystem FROM osv_affected
     WHERE LOWER(ecosystem) = LOWER($1) AND package_name = $2
     LIMIT 1`,
    [rawEco, packageName],
  );
  if (resolve.rows.length === 0) {
    return withCors(errorResponse(404, 'Package not found', 'NOT_FOUND'));
  }
  const resolvedEco = resolve.rows[0].ecosystem;

  const advRes = await query<{
    osvId: string;
    cveId: string | null;
    summary: string | null;
    severity: string | null;
    cvssScore: string | null;
    publishedAt: string;
    vulnerableRange: string | null;
    fixedVersion: string | null;
  }>(
    `SELECT
       a.osv_id    AS "osvId",
       (SELECT alias FROM unnest(a.aliases) AS alias WHERE alias LIKE 'CVE-%' LIMIT 1) AS "cveId",
       a.summary   AS summary,
       a.severity  AS severity,
       a.cvss_score::text AS "cvssScore",
       a.published AS "publishedAt",
       NULL::text  AS "vulnerableRange",
       NULL::text  AS "fixedVersion"
     FROM osv_affected oa
     JOIN osv_advisories a ON a.osv_id = oa.osv_id AND a.ecosystem = oa.ecosystem
     WHERE oa.ecosystem = $1
       AND oa.package_ecosystem = oa.ecosystem
       AND oa.package_name = $2
     ORDER BY a.published DESC NULLS LAST, a.osv_id DESC
     LIMIT 500`,
    [resolvedEco, packageName],
  );

  const severityCounts: Record<string, number> = {};
  for (const adv of advRes.rows) {
    if (adv.severity) severityCounts[adv.severity] = (severityCounts[adv.severity] ?? 0) + 1;
  }

  const advisories = advRes.rows.map((r) => ({
    // ghsaId field reused so PackageDetail.tsx can render OSV ids the same way.
    ghsaId: r.osvId,
    cveId: r.cveId,
    summary: r.summary,
    severity: r.severity,
    cvssScore: r.cvssScore ? parseFloat(r.cvssScore) : null,
    publishedAt: r.publishedAt,
    withdrawnAt: null,
    packageCount: 1,
    ecosystems: [resolvedEco],
    techniqueCount: 0,
    vulnerableRange: r.vulnerableRange,
    fixedVersion: r.fixedVersion,
  }));

  return withCors(
    jsonResponse(
      {
        packageId: `osv:${resolvedEco}:${packageName}`,
        ecosystem: resolvedEco,
        packageName,
        purl: null,
        source: 'OSV',
        advisoryCount: advisories.length,
        severityCounts,
        advisories,
        linkedTechniques: [],
      },
      3600,
    ),
  );
}
