import { NextRequest } from 'next/server';
import { query } from '../../lib/db';
import { jsonResponse, errorResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';
import { notCatchallCwe } from '../../lib/inference';
import { escapeLikePattern } from '../../lib/queries';

export { OPTIONS };

const GHSA_ID_RE = /^GHSA(?:-[0-9a-z]{4}){3}$/i;

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ ghsaId: string }> },
) {
  const { ghsaId: raw } = await params;
  // GHSA canonical form is uppercase `GHSA-` prefix with lowercase segments
  // (e.g. `GHSA-g4vj-cjjj-v7hg`). Only normalize the prefix — the random
  // segments are stored verbatim and case-matters for lookup.
  const ghsaId = raw.replace(/^ghsa-/i, 'GHSA-');

  if (!GHSA_ID_RE.test(ghsaId)) {
    return withCors(errorResponse(400, 'Invalid GHSA ID', 'VALIDATION_ERROR'));
  }

  const advResult = await query<{
    ghsaId: string;
    cveId: string | null;
    summary: string | null;
    description: string | null;
    severity: string | null;
    cvssScore: string | null;
    cvssVector: string | null;
    cvssV4Score: string | null;
    cvssV4Vector: string | null;
    publishedAt: string;
    withdrawnAt: string | null;
  }>(
    `SELECT
       ghsa_id         AS "ghsaId",
       cve_id          AS "cveId",
       summary,
       description,
       severity,
       cvss_score      AS "cvssScore",
       cvss_vector     AS "cvssVector",
       cvss_v4_score   AS "cvssV4Score",
       cvss_v4_vector  AS "cvssV4Vector",
       published_at    AS "publishedAt",
       withdrawn_at    AS "withdrawnAt"
     FROM ghsa_advisories
     WHERE ghsa_id = $1
     LIMIT 1`,
    [ghsaId],
  );

  if (advResult.rows.length === 0) {
    return withCors(errorResponse(404, 'GHSA advisory not found', 'NOT_FOUND'));
  }

  const adv = advResult.rows[0];

  // Optional version filter — substring/text match on the affected packages'
  // vulnerable_range / fixed_version. The advisory is the context (standalone).
  const versionRaw = req.nextUrl.searchParams.get('version')?.trim();
  const version = versionRaw ? versionRaw.slice(0, 100) : null;
  const pkgVersionClause = version ? 'AND (gp.vulnerable_range ILIKE $2 OR gp.fixed_version ILIKE $2)' : '';
  const pkgParams = version ? [ghsaId, `%${escapeLikePattern(version)}%`] : [ghsaId];

  const [cweResult, pkgResult, techResult, capecResult] = await Promise.all([
    query<{ cweId: string }>(
      `SELECT cwe_id AS "cweId" FROM ghsa_weaknesses WHERE ghsa_id = $1 ORDER BY cwe_id`,
      [ghsaId],
    ),
    query<{
      ecosystem: string;
      packageName: string;
      purl: string | null;
      vulnerableRange: string | null;
      fixedVersion: string | null;
    }>(
      `SELECT
         p.ecosystem,
         p.package_name    AS "packageName",
         p.purl,
         gp.vulnerable_range AS "vulnerableRange",
         gp.fixed_version  AS "fixedVersion"
       FROM ghsa_packages gp
       JOIN packages p ON p.id = gp.package_id
       WHERE gp.ghsa_id = $1 ${pkgVersionClause}
       ORDER BY p.ecosystem, p.package_name, gp.vulnerable_range NULLS FIRST`,
      pkgParams,
    ),
    query<{ attackId: string; name: string }>(
      `SELECT DISTINCT t.attack_id AS "attackId", t.name
       FROM ghsa_weaknesses w
       JOIN capec_mappings cm ON cm.cwe_id = w.cwe_id AND cm.technique_id IS NOT NULL AND ${notCatchallCwe('cm.cwe_id')}
       JOIN techniques t ON t.id = cm.technique_id AND t.is_revoked = false AND t.is_deprecated = false
       WHERE w.ghsa_id = $1
       ORDER BY t.attack_id`,
      [ghsaId],
    ),
    // Attack patterns whose referenced CWEs overlap this GHSA's CWEs
    query<{ capecId: string; name: string; severity: string | null; likelihood: string | null; abstraction: string | null }>(
      `SELECT p.id AS "capecId", p.name, p.severity, p.likelihood, p.abstraction
       FROM capec_patterns p
       WHERE p.cwe_ids && (
         SELECT COALESCE(ARRAY_AGG(DISTINCT cwe_id::text), ARRAY[]::text[])
         FROM ghsa_weaknesses WHERE ghsa_id = $1
       )
       ORDER BY
         CASE p.severity WHEN 'Very High' THEN 5 WHEN 'High' THEN 4 WHEN 'Medium' THEN 3
              WHEN 'Low' THEN 2 WHEN 'Very Low' THEN 1 ELSE 0 END DESC,
         p.id`,
      [ghsaId],
    ).catch(() => ({ rows: [] as Array<{ capecId: string; name: string; severity: string | null; likelihood: string | null; abstraction: string | null }> })),
  ]);

  const packageCount = pkgResult.rows.length;
  const ecosystems = Array.from(new Set(pkgResult.rows.map((r) => r.ecosystem)));

  return withCors(
    jsonResponse(
      {
        ghsaId: adv.ghsaId,
        versionFilter: version,
        cveId: adv.cveId,
        summary: adv.summary,
        description: adv.description,
        severity: adv.severity,
        cvssScore: adv.cvssScore ? parseFloat(adv.cvssScore) : null,
        cvssVector: adv.cvssVector,
        cvssV4Score: adv.cvssV4Score ? parseFloat(adv.cvssV4Score) : null,
        cvssV4Vector: adv.cvssV4Vector,
        publishedAt: adv.publishedAt,
        withdrawnAt: adv.withdrawnAt,
        packageCount,
        ecosystems,
        techniqueCount: techResult.rows.length,
        cwes: cweResult.rows.map((r) => r.cweId),
        packages: pkgResult.rows,
        techniques: techResult.rows,
        capecPatterns: capecResult.rows,
      },
      3600,
    ),
  );
}
