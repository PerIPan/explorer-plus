import { NextRequest } from 'next/server';
import { query } from '../../lib/db';
import { jsonResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';
import { escapeLikePattern } from '../../lib/queries';

export { OPTIONS };

export async function GET(req: NextRequest) {
  const search = req.nextUrl.searchParams.get('q')?.trim().slice(0, 200) ?? null;
  const category = req.nextUrl.searchParams.get('category')?.slice(0, 50) ?? null;

  let whereClause = '';
  const params: string[] = [];

  if (category) {
    params.push(`${escapeLikePattern(category)}%`);
    whereClause += ` WHERE veris_id LIKE $${params.length}`;
  }
  if (search) {
    params.push(`%${escapeLikePattern(search)}%`);
    const cond = `(veris_id ILIKE $${params.length} OR attack_technique_id ILIKE $${params.length})`;
    whereClause += whereClause ? ` AND ${cond}` : ` WHERE ${cond}`;
  }

  const result = await query<{
    verisId: string;
    techniqueCount: string;
    techniques: string[];
  }>(
    `SELECT
       veris_id AS "verisId",
       COUNT(DISTINCT attack_technique_id)::text AS "techniqueCount",
       array_agg(DISTINCT attack_technique_id ORDER BY attack_technique_id) FILTER (WHERE attack_technique_id IS NOT NULL) AS techniques
     FROM veris_mappings
     ${whereClause}
     GROUP BY veris_id
     ORDER BY veris_id`,
    params,
  );

  const categories = await query<{ category: string; count: string }>(
    `SELECT
       split_part(veris_id, '.', 1) AS category,
       COUNT(DISTINCT veris_id)::text AS count
     FROM veris_mappings
     GROUP BY split_part(veris_id, '.', 1)
     ORDER BY COUNT(*) DESC`,
  );

  return withCors(jsonResponse({
    data: result.rows.map((r) => ({
      ...r,
      techniqueCount: parseInt(r.techniqueCount, 10),
      techniques: r.techniques ?? [],
    })),
    categories: categories.rows,
    total: result.rows.length,
  }, 3600));
}
