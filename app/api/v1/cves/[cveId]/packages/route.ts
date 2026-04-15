import { NextRequest } from 'next/server';
import { query } from '../../../lib/db';
import { jsonResponse, errorResponse } from '../../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../../lib/cors';

export { OPTIONS };

const CVE_ID_RE = /^CVE-\d{4}-\d{4,7}$/i;

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ cveId: string }> },
) {
  const { cveId: raw } = await params;
  const cveId = raw.toUpperCase();

  if (!CVE_ID_RE.test(cveId)) {
    return withCors(errorResponse(400, 'Invalid CVE ID', 'VALIDATION_ERROR'));
  }

  try {
    // Look up GHSA alias
    const ghsaResult = await query<{ ghsaId: string }>(
      `SELECT ghsa_id AS "ghsaId" FROM ghsa_advisories WHERE cve_id = $1 LIMIT 1`,
      [cveId],
    );

    if (ghsaResult.rows.length === 0) {
      return withCors(jsonResponse({ cveId, ghsaId: null, packages: [] }, 3600));
    }

    const ghsaId = ghsaResult.rows[0].ghsaId;

    const pkgResult = await query<{
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
    );

    return withCors(jsonResponse({
      cveId,
      ghsaId,
      packages: pkgResult.rows,
    }, 3600));
  } catch (err) {
    // Pre-migration graceful degradation
    console.error('/cves/:cveId/packages failed:', err);
    return withCors(jsonResponse({ cveId, ghsaId: null, packages: [] }, 60));
  }
}
