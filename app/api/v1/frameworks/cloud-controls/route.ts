import { NextRequest } from 'next/server';
import { query } from '../../lib/db.js';
import { jsonResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';
import { escapeLikePattern } from '../../lib/queries.js';

export { OPTIONS };

export async function GET(req: NextRequest) {
  const provider = req.nextUrl.searchParams.get('provider')?.slice(0, 20) ?? null;
  const search = req.nextUrl.searchParams.get('q')?.trim().slice(0, 200) ?? null;

  let whereClause = '';
  const params: string[] = [];

  if (provider) {
    params.push(provider);
    whereClause += ` WHERE provider = $${params.length}`;
  }
  if (search) {
    params.push(`%${escapeLikePattern(search)}%`);
    const cond = `(control_id ILIKE $${params.length} OR control_name ILIKE $${params.length} OR attack_technique_id ILIKE $${params.length})`;
    whereClause += whereClause ? ` AND ${cond}` : ` WHERE ${cond}`;
  }

  const result = await query<{
    provider: string;
    controlId: string;
    controlName: string;
    techniqueCount: string;
    techniques: string[];
  }>(
    `SELECT
       provider,
       control_id AS "controlId",
       MAX(control_name) AS "controlName",
       COUNT(DISTINCT attack_technique_id)::text AS "techniqueCount",
       array_agg(DISTINCT attack_technique_id ORDER BY attack_technique_id) FILTER (WHERE attack_technique_id IS NOT NULL) AS techniques
     FROM cloud_control_mappings
     ${whereClause}
     GROUP BY provider, control_id
     ORDER BY provider, MAX(control_name)`,
    params,
  );

  const stats = await query<{ provider: string; count: string }>(
    `SELECT provider, COUNT(DISTINCT control_id)::text AS count FROM cloud_control_mappings GROUP BY provider ORDER BY provider`,
  );

  return withCors(jsonResponse({
    data: result.rows.map((r) => ({
      ...r,
      techniqueCount: parseInt(r.techniqueCount, 10),
      techniques: r.techniques ?? [],
    })),
    stats: stats.rows,
    total: result.rows.length,
  }, 3600));
}
