import { NextRequest } from 'next/server';
import { query } from '../../lib/db.js';
import { jsonResponse, errorResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';
import { z } from 'zod';

export { OPTIONS };

const querySchema = z.object({
  search: z.string().max(200).optional(),
  family: z.string().max(100).optional(),
  page:   z.coerce.number().int().positive().max(1000).default(1),
  limit:  z.coerce.number().int().positive().max(5000).default(50),
});

export async function GET(req: NextRequest) {
  const rawParams: Record<string, string> = {};
  req.nextUrl.searchParams.forEach((v, k) => { rawParams[k] = v; });

  const parsed = querySchema.safeParse(rawParams);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Invalid query params', 'VALIDATION_ERROR'));
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
