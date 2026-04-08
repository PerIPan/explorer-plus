import { NextRequest } from 'next/server';
import { query } from '../../lib/db.js';
import { jsonResponse, errorResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';
import { z } from 'zod';

export { OPTIONS };

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

export async function GET(req: NextRequest) {
  const rawParams: Record<string, string> = {};
  req.nextUrl.searchParams.forEach((v, k) => { rawParams[k] = v; });

  const parsed = querySchema.safeParse(rawParams);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Invalid query params', 'VALIDATION_ERROR'));
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

  return withCors(jsonResponse({
    data: dataResult.rows,
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
    },
  }, 3600));
}
