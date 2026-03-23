import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../lib/db.js';
import { withHandler } from '../lib/middleware.js';
import { z } from 'zod';

const STAGES = [
  'preparation',
  'identification',
  'containment',
  'eradication',
  'recovery',
  'lessons_learned',
] as const;

const querySchema = z.object({
  search: z.string().max(200).optional(),
  stage:  z.enum(STAGES).optional(),
  page:   z.coerce.number().int().positive().max(1000).default(1),
  limit:  z.coerce.number().int().positive().max(5000).default(100),
});

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const parsed = querySchema.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid query params', code: 'VALIDATION_ERROR' });
    return;
  }

  const { search, stage, page, limit } = parsed.data;
  const offset = (page - 1) * limit;
  const params: unknown[] = [];
  const conditions: string[] = [];

  if (search) {
    params.push(`%${search}%`);
    conditions.push(
      `(ra.title ILIKE $${params.length} OR ra.description ILIKE $${params.length})`,
    );
  }
  if (stage) {
    params.push(stage);
    conditions.push(`ra.stage = $${params.length}`);
  }

  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  const countResult = await query<{ total: string }>(
    `SELECT COUNT(*) AS total FROM react_actions ra ${where}`,
    params,
  );
  const total = parseInt(countResult.rows[0].total, 10);

  params.push(limit, offset);
  const dataResult = await query<{
    actionId: string;
    title: string;
    description: string | null;
    stage: string | null;
    workflow: string | null;
  }>(
    `SELECT
       action_id   AS "actionId",
       title,
       description,
       stage,
       workflow
     FROM react_actions ra
     ${where}
     ORDER BY action_id ASC
     LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params,
  );

  res.status(200).json({
    data: dataResult.rows,
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
    },
  });
}

export default withHandler(handler, { cacheTtl: 3600 });
