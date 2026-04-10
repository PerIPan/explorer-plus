import { NextRequest } from 'next/server';
import { query } from '../../lib/db';
import { jsonResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';

export { OPTIONS };

/**
 * Aggregate VERIS + Cloud Control mappings for a set of technique IDs.
 * Used by actor/software/campaign profile views to show framework coverage.
 *
 * GET /frameworks/by-techniques?ids=T1566,T1059,T1078
 */
export async function GET(req: NextRequest) {
  const raw = req.nextUrl.searchParams.get('ids') ?? '';
  const ids = raw.split(',').map((s) => s.trim()).filter((s) => /^T\d{4}(\.\d{3})?$/.test(s)).slice(0, 200);

  if (ids.length === 0) {
    return withCors(jsonResponse({ veris: [], cloud: [], owasp: [], csf: [] }));
  }

  const [verisResult, cloudResult, owaspResult, csfResult] = await Promise.all([
    query<{ verisId: string; count: string }>(
      `SELECT veris_id AS "verisId", COUNT(*)::text AS count
       FROM veris_mappings
       WHERE attack_technique_id = ANY($1::text[])
       GROUP BY veris_id
       ORDER BY COUNT(*) DESC`,
      [ids],
    ),
    query<{ provider: string; controlId: string; controlName: string; mappingType: string | null; count: string }>(
      `SELECT
         provider,
         control_id AS "controlId",
         MAX(control_name) AS "controlName",
         mapping_type AS "mappingType",
         COUNT(DISTINCT attack_technique_id)::text AS count
       FROM cloud_control_mappings
       WHERE attack_technique_id = ANY($1::text[])
       GROUP BY provider, control_id, mapping_type
       ORDER BY provider, COUNT(*) DESC`,
      [ids],
    ),
    // OWASP categories via CWE overlap with techniques' CAPEC mappings
    query<{ categoryId: string; name: string; framework: string }>(
      `SELECT DISTINCT o.category_id AS "categoryId", o.name, o.framework
       FROM owasp_top10 o
       JOIN capec_mappings cm ON cm.cwe_id = ANY(o.cwe_ids)
       WHERE cm.attack_technique_id = ANY($1::text[]) AND cm.technique_id IS NOT NULL
       ORDER BY o.framework, o.category_id`,
      [ids],
    ),
    // CSF v2 subcategories linked to these techniques
    query<{ subcategoryId: string; name: string; function: string; functionName: string; count: string }>(
      `SELECT
         m.subcategory_id AS "subcategoryId",
         s.name,
         s.function,
         s.function_name  AS "functionName",
         COUNT(DISTINCT m.attack_technique_id)::text AS count
       FROM csf_technique_mappings m
       JOIN csf_subcategories s ON s.subcategory_id = m.subcategory_id AND s.version = '2.0'
       WHERE m.attack_technique_id = ANY($1::text[]) AND m.is_draft = FALSE
       GROUP BY m.subcategory_id, s.name, s.function, s.function_name
       ORDER BY COUNT(*) DESC, m.subcategory_id`,
      [ids],
    ),
  ]);

  return withCors(jsonResponse({
    veris: verisResult.rows.map((r) => ({ ...r, count: parseInt(r.count, 10) })),
    cloud: cloudResult.rows.map((r) => ({ ...r, count: parseInt(r.count, 10) })),
    owasp: owaspResult.rows,
    csf: csfResult.rows.map((r) => ({ ...r, count: parseInt(r.count, 10) })),
  }, 3600));
}
