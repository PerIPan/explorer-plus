import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../lib/db.js';
import { withHandler } from '../lib/middleware.js';
import { escapeLikePattern } from '../lib/queries.js';

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const provider = typeof req.query.provider === 'string' ? req.query.provider.slice(0, 20) : null;
  const search = typeof req.query.q === 'string' ? req.query.q.trim().slice(0, 200) : null;

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

  res.status(200).json({
    data: result.rows.map((r) => ({
      ...r,
      techniqueCount: parseInt(r.techniqueCount, 10),
      techniques: r.techniques ?? [],
    })),
    stats: stats.rows,
    total: result.rows.length,
  });
}

export default withHandler(handler, { cacheTtl: 3600 });
