import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../lib/db.js';
import { withHandler } from '../lib/middleware.js';
import { z } from 'zod';

const querySchema = z.object({
  search: z.string().max(200).optional(),
  technique: z.string().max(20).optional(),
  page: z.coerce.number().int().positive().max(1000).default(1),
  limit: z.coerce.number().int().positive().max(5000).default(50),
});

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const parsed = querySchema.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid query params', code: 'VALIDATION_ERROR' });
    return;
  }

  const { search, technique, page, limit } = parsed.data;
  const offset = (page - 1) * limit;
  const params: unknown[] = [];
  const conditions: string[] = [];

  if (search) {
    params.push(`%${search}%`);
    conditions.push(`(ds.det_id ILIKE $${params.length} OR ds.name ILIKE $${params.length})`);
  }
  if (technique) {
    params.push(technique);
    conditions.push(`ds.attack_technique_id = $${params.length}`);
  }

  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  const countResult = await query<{ total: string }>(
    `SELECT COUNT(DISTINCT ds.det_id) AS total FROM detection_strategies ds ${where}`,
    params,
  );
  const total = parseInt(countResult.rows[0].total, 10);

  params.push(limit, offset);
  const dataResult = await query<{
    detId: string;
    name: string;
    attackTechniqueId: string | null;
    techniqueCount: string;
    analyticCount: string;
  }>(
    `SELECT
       ds.det_id                          AS "detId",
       MAX(ds.name)                       AS "name",
       MAX(ds.attack_technique_id)        AS "attackTechniqueId",
       COUNT(DISTINCT ds.attack_technique_id) AS "techniqueCount",
       (SELECT COUNT(*) FROM detection_analytics da WHERE da.det_id = ds.det_id)::text AS "analyticCount"
     FROM detection_strategies ds
     ${where}
     GROUP BY ds.det_id
     ORDER BY ds.det_id ASC
     LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params,
  );

  res.status(200).json({
    data: dataResult.rows.map((r) => ({
      ...r,
      techniqueCount: parseInt(r.techniqueCount, 10),
      analyticCount: parseInt(r.analyticCount, 10),
    })),
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
    },
  });
}

export default withHandler(handler, { cacheTtl: 3600 });
