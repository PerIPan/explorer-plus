import { NextRequest } from 'next/server';
import { query } from '../../../../lib/db';
import { jsonResponse, errorResponse } from '../../../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../../../lib/cors';

export { OPTIONS };

const CATEGORY_ID_RE = /^(A|ML|LLM)\d{2}$/i;

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ categoryId: string }> },
) {
  const { categoryId: raw } = await params;
  const categoryId = raw.toUpperCase();

  if (!CATEGORY_ID_RE.test(categoryId)) {
    return withCors(errorResponse(400, 'Invalid OWASP category ID', 'VALIDATION_ERROR'));
  }

  try {
    // First resolve this category's CWE set
    const catResult = await query<{ cwe_ids: string[] }>(
      `SELECT cwe_ids FROM owasp_top10 WHERE UPPER(category_id) = $1 LIMIT 1`,
      [categoryId],
    );

    if (catResult.rows.length === 0 || !catResult.rows[0].cwe_ids?.length) {
      return withCors(jsonResponse({ categoryId, packages: [] }, 3600));
    }

    const cweIds = catResult.rows[0].cwe_ids;

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
       JOIN ghsa_weaknesses w ON w.ghsa_id = g.ghsa_id AND w.cwe_id = ANY($1::text[])
       GROUP BY p.id, p.ecosystem, p.package_name
       ORDER BY COUNT(DISTINCT g.ghsa_id) DESC, p.ecosystem, p.package_name
       LIMIT 100`,
      [cweIds],
    );

    return withCors(jsonResponse({
      categoryId,
      packages: result.rows.map((r) => ({
        packageId: r.packageId,
        ecosystem: r.ecosystem,
        packageName: r.packageName,
        advisoryCount: parseInt(r.advisoryCount, 10),
        severityTop: r.severityTop,
      })),
    }, 3600));
  } catch (err) {
    console.error(`/frameworks/owasp/${categoryId}/packages failed:`, err);
    return withCors(jsonResponse({ categoryId, packages: [] }, 60));
  }
}
