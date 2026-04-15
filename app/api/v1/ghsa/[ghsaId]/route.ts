import { NextRequest } from 'next/server';
import { query } from '../../lib/db';
import { jsonResponse, errorResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';

export { OPTIONS };

const GHSA_ID_RE = /^GHSA(?:-[0-9a-z]{4}){3}$/i;

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ ghsaId: string }> },
) {
  const { ghsaId: raw } = await params;
  const ghsaId = raw.toUpperCase().replace(/^GHSA-/i, 'GHSA-');

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

  const [cweResult, pkgResult, techResult] = await Promise.all([
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
       WHERE gp.ghsa_id = $1
       ORDER BY p.ecosystem, p.package_name, gp.vulnerable_range NULLS FIRST`,
      [ghsaId],
    ),
    query<{ attackId: string; name: string }>(
      `SELECT DISTINCT t.attack_id AS "attackId", t.name
       FROM ghsa_weaknesses w
       JOIN capec_mappings cm ON cm.cwe_id = w.cwe_id AND cm.technique_id IS NOT NULL
       JOIN techniques t ON t.id = cm.technique_id
       WHERE w.ghsa_id = $1
       ORDER BY t.attack_id`,
      [ghsaId],
    ),
  ]);

  const packageCount = pkgResult.rows.length;
  const ecosystems = Array.from(new Set(pkgResult.rows.map((r) => r.ecosystem)));

  return withCors(
    jsonResponse(
      {
        ghsaId: adv.ghsaId,
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
      },
      3600,
    ),
  );
}
