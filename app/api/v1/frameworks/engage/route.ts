import { NextRequest } from 'next/server';
import { query } from '../../lib/db.js';
import { jsonResponse, errorResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';
import { z } from 'zod';

export { OPTIONS };

const querySchema = z.object({
  search:  z.string().max(200).optional(),
  goal:    z.string().max(100).optional(),
  page:    z.coerce.number().int().positive().max(1000).default(1),
  limit:   z.coerce.number().int().positive().max(5000).default(50),
});

export async function GET(req: NextRequest) {
  const rawParams: Record<string, string> = {};
  req.nextUrl.searchParams.forEach((v, k) => { rawParams[k] = v; });

  const parsed = querySchema.safeParse(rawParams);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Invalid query params', 'VALIDATION_ERROR'));
  }

  const { search, goal, page, limit } = parsed.data;
  const offset = (page - 1) * limit;
  const params: unknown[] = [];
  const conditions: string[] = [];

  if (search) {
    params.push(`%${search}%`);
    conditions.push(
      `(em.engage_name ILIKE $${params.length} OR em.engage_description ILIKE $${params.length})`,
    );
  }
  if (goal) {
    params.push(goal);
    conditions.push(`em.goal = $${params.length}`);
  }

  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  const countResult = await query<{ total: string }>(
    `SELECT COUNT(DISTINCT em.engage_id) AS total FROM engage_mappings em ${where}`,
    params,
  );
  const total = parseInt(countResult.rows[0].total, 10);

  params.push(limit, offset);
  const dataResult = await query<{
    engageId: string;
    engageName: string;
    engageDescription: string | null;
    goal: string | null;
    approach: string | null;
    techniqueCount: string;
  }>(
    `SELECT
       em.engage_id                      AS "engageId",
       MAX(em.engage_name)               AS "engageName",
       MAX(em.engage_description)        AS "engageDescription",
       MAX(em.goal)                      AS "goal",
       MAX(em.approach)                  AS "approach",
       COUNT(em.attack_technique_id)     AS "techniqueCount"
     FROM engage_mappings em
     ${where}
     GROUP BY em.engage_id
     ORDER BY em.engage_id ASC
     LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params,
  );

  return withCors(jsonResponse({
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
  }, 3600));
}
