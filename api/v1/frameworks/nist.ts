import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../lib/db.js';
import { withHandler } from '../lib/middleware.js';
import { paginationSchema } from '../lib/validate.js';
import { z } from 'zod';

const querySchema = z.object({
  search: z.string().max(200).optional(),
  family: z.string().max(100).optional(),
  page:   z.coerce.number().int().positive().max(1000).default(1),
  limit:  z.coerce.number().int().positive().max(200).default(50),
});

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const parsed = querySchema.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid query params', code: 'VALIDATION_ERROR' });
    return;
  }

  const { search, family, page, limit } = parsed.data;
  const offset = (page - 1) * limit;
  const params: unknown[] = [];
  const conditions: string[] = [];

  if (search) {
    params.push(`%${search}%`);
    conditions.push(
      `(nc.control_id ILIKE $${params.length} OR nc.control_name ILIKE $${params.length})`,
    );
  }
  if (family) {
    params.push(family);
    conditions.push(`nc.control_family = $${params.length}`);
  }

  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  const countResult = await query<{ total: string }>(
    `SELECT COUNT(DISTINCT nc.control_id) AS total
     FROM nist_controls nc ${where}`,
    params,
  );
  const total = parseInt(countResult.rows[0].total, 10);

  params.push(limit, offset);
  const dataResult = await query<{
    controlId: string;
    controlName: string | null;
    controlFamily: string | null;
    techniqueCount: string;
  }>(
    `SELECT
       nc.control_id           AS "controlId",
       MAX(nc.control_name)    AS "controlName",
       MAX(nc.control_family)  AS "controlFamily",
       COUNT(nc.attack_technique_id) AS "techniqueCount"
     FROM nist_controls nc
     ${where}
     GROUP BY nc.control_id
     ORDER BY nc.control_id ASC
     LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params,
  );

  res.status(200).json({
    data: dataResult.rows.map((r) => ({
      ...r,
      techniqueCount: parseInt(r.techniqueCount, 10),
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
