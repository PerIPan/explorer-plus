import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../lib/db.js';
import { withHandler } from '../lib/middleware.js';
import { escapeLikePattern } from '../lib/queries.js';

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const search = typeof req.query.q === 'string' ? req.query.q.trim().slice(0, 200) : null;
  const category = typeof req.query.category === 'string' ? req.query.category.slice(0, 50) : null;

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

  res.status(200).json({
    data: result.rows.map((r) => ({
      ...r,
      techniqueCount: parseInt(r.techniqueCount, 10),
      techniques: r.techniques ?? [],
    })),
    categories: categories.rows,
    total: result.rows.length,
  });
}

export default withHandler(handler, { cacheTtl: 3600 });
