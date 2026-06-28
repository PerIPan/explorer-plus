import { NextRequest } from 'next/server';
import { query } from '../../../lib/db';
import { jsonResponse, errorResponse } from '../../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../../lib/cors';
import { notCatchallCwe } from '../../../lib/inference';

export { OPTIONS };

const ATTACK_ID_RE = /^(AML\.)?(T|TA)\d{4}(\.\d{3})?$/;

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ attackId: string }> },
) {
  const { attackId: raw } = await params;
  const attackId = raw.toUpperCase();

  if (!ATTACK_ID_RE.test(attackId)) {
    return withCors(errorResponse(400, 'Invalid ATT&CK ID', 'VALIDATION_ERROR'));
  }

  try {
    const result = await query<{
      packageId: string;
      ecosystem: string;
      packageName: string;
      advisoryCount: string;
      severityTop: string | null;
    }>(
      `SELECT
         p.id                          AS "packageId",
         p.ecosystem,
         p.package_name                AS "packageName",
         COUNT(DISTINCT g.ghsa_id)     AS "advisoryCount",
         -- Pick highest severity (CRITICAL > HIGH > MEDIUM > LOW) across active advisories
         (ARRAY_AGG(g.severity ORDER BY
           CASE g.severity
             WHEN 'CRITICAL' THEN 1
             WHEN 'HIGH' THEN 2
             WHEN 'MEDIUM' THEN 3
             WHEN 'LOW' THEN 4
             ELSE 5
           END))[1] AS "severityTop"
       FROM ghsa_packages gp
       JOIN packages p ON p.id = gp.package_id
       JOIN ghsa_advisories g ON g.ghsa_id = gp.ghsa_id AND g.withdrawn_at IS NULL
       JOIN ghsa_weaknesses w ON w.ghsa_id = g.ghsa_id
       JOIN capec_mappings cm ON cm.cwe_id = w.cwe_id AND cm.technique_id IS NOT NULL AND ${notCatchallCwe('cm.cwe_id')}
       JOIN techniques t ON t.id = cm.technique_id AND t.attack_id = $1 AND t.is_revoked = false AND t.is_deprecated = false
       GROUP BY p.id, p.ecosystem, p.package_name
       ORDER BY COUNT(DISTINCT g.ghsa_id) DESC, p.ecosystem, p.package_name
       LIMIT 100`,
      [attackId],
    );

    return withCors(jsonResponse({
      attackId,
      packages: result.rows.map((r) => ({
        packageId: r.packageId,
        ecosystem: r.ecosystem,
        packageName: r.packageName,
        advisoryCount: parseInt(r.advisoryCount, 10),
        severityTop: r.severityTop,
      })),
    }, 3600));
  } catch (err) {
    console.error(`/techniques/${attackId}/packages failed:`, err);
    return withCors(jsonResponse({ attackId, packages: [] }, 60));
  }
}
