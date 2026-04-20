import { NextRequest } from 'next/server';
import { query } from '../../lib/db';
import { jsonResponse, errorResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';

export { OPTIONS };

// OSV IDs are heterogeneous: CAN-*, CVE-*, DSA-*, DLA-*, LBSEC-*, LSN-*,
// MAL-*, OSV-*, RLSA-*, SUSE-SU-*, USN-*, etc. Allow anything that looks
// like an upstream identifier (alnum + -, _, ., /, ~ at most).
const OSV_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._\-/~:]{1,127}$/;

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ osvId: string }> },
) {
  const { osvId: raw } = await params;
  const osvId = decodeURIComponent(raw);

  if (!OSV_ID_RE.test(osvId)) {
    return withCors(errorResponse(400, 'Invalid OSV ID', 'VALIDATION_ERROR'));
  }

  // Multiple rows can share the same osv_id across ecosystems (rare for our
  // non-GHSA slice, but possible for OSS-Fuzz ↔ distro cross-references).
  // The detail endpoint aggregates: returns the primary row (any one) plus
  // the full set of affected packages across all rows with this osv_id.
  const advisoryRes = await query<{
    osvId: string;
    ecosystem: string;
    aliases: string[] | null;
    summary: string | null;
    details: string | null;
    severityRaw: Array<{ type?: string; score?: string }> | null;
    cvssVector: string | null;
    cvssScore: string | null;
    cvssSeverity: string | null;
    published: string | null;
    modified: string | null;
  }>(
    `SELECT
       osv_id          AS "osvId",
       ecosystem,
       aliases,
       summary,
       details,
       severity_raw    AS "severityRaw",
       cvss_vector     AS "cvssVector",
       cvss_score      AS "cvssScore",
       cvss_severity   AS "cvssSeverity",
       published,
       modified
     FROM osv_advisories
     WHERE osv_id = $1
     ORDER BY ecosystem
     LIMIT 1`,
    [osvId],
  );

  if (advisoryRes.rows.length === 0) {
    return withCors(errorResponse(404, 'OSV advisory not found', 'NOT_FOUND'));
  }

  const adv = advisoryRes.rows[0];

  const affectedRes = await query<{
    packageName: string;
    packageEcosystem: string;
    versions: string[] | null;
    ranges: Array<Record<string, unknown>> | null;
  }>(
    `SELECT
       package_name       AS "packageName",
       package_ecosystem  AS "packageEcosystem",
       versions,
       ranges
     FROM osv_affected
     WHERE osv_id = $1
     ORDER BY package_ecosystem, package_name`,
    [osvId],
  );

  const aliases = adv.aliases ?? [];
  const cveIds = aliases.filter((a) => /^CVE-\d{4}-\d+$/.test(a));

  return withCors(
    jsonResponse(
      {
        osvId: adv.osvId,
        ecosystem: adv.ecosystem,
        aliases,
        cveIds,
        summary: adv.summary,
        details: adv.details,
        severityRaw: adv.severityRaw ?? [],
        cvssVector: adv.cvssVector,
        cvssScore: adv.cvssScore ? parseFloat(adv.cvssScore) : null,
        cvssSeverity: adv.cvssSeverity,
        published: adv.published,
        modified: adv.modified,
        packageCount: affectedRes.rows.length,
        affected: affectedRes.rows.map((r) => ({
          packageName: r.packageName,
          packageEcosystem: r.packageEcosystem,
          versions: r.versions,
          ranges: r.ranges ?? [],
        })),
      },
      3600,
    ),
  );
}
