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
  // LATERAL-join cve_details via the first CVE alias to backfill severity
  // for OSV rows where the distro didn't publish CVSS data (very common
  // for Chainguard/Wolfi/Linux/SUSE rebuild advisories). The stored
  // cvss_severity stays NULL if OSV didn't give us one — we expose the
  // resolved value at read time via COALESCE.
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
    severityInherited: boolean;
    published: string | null;
    modified: string | null;
  }>(
    `SELECT
       o.osv_id          AS "osvId",
       o.ecosystem,
       o.aliases,
       o.summary,
       o.details,
       o.severity_raw    AS "severityRaw",
       o.cvss_vector     AS "cvssVector",
       COALESCE(o.cvss_score, cve.cvss_score)       AS "cvssScore",
       COALESCE(o.cvss_severity, cve.cvss_severity) AS "cvssSeverity",
       (o.cvss_severity IS NULL AND cve.cvss_severity IS NOT NULL) AS "severityInherited",
       o.published,
       o.modified
     FROM osv_advisories o
     LEFT JOIN LATERAL (
       SELECT cd.cvss_severity, cd.cvss_score
       FROM cve_details cd
       WHERE cd.cve_id = ANY(o.aliases)
       LIMIT 1
     ) cve ON true
     WHERE o.osv_id = $1
     ORDER BY o.ecosystem
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
        /** True when the severity was inherited from a CVE alias rather
         *  than published by the distro itself — UI can render a subtle
         *  "via CVE" hint to be transparent about the source. */
        severityInherited: adv.severityInherited ?? false,
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
