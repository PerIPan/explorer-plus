import { NextRequest } from 'next/server';
import { query } from '../../lib/db';
import { jsonResponse, errorResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';
import { z } from 'zod';

export { OPTIONS };

const querySchema = z.object({
  search: z.string().max(200).optional(),
  technique: z.string().max(20).optional(),
  page: z.coerce.number().int().positive().max(1000).default(1),
  limit: z.coerce.number().int().positive().max(5000).default(50),
});

export async function GET(req: NextRequest) {
  const rawParams: Record<string, string> = {};
  req.nextUrl.searchParams.forEach((v, k) => { rawParams[k] = v; });

  const parsed = querySchema.safeParse(rawParams);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Invalid query params', 'VALIDATION_ERROR'));
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
    analytics: string;
  }>(
    `SELECT
       ds.det_id                          AS "detId",
       MAX(ds.name)                       AS "name",
       MAX(ds.attack_technique_id)        AS "attackTechniqueId",
       COALESCE(
         (SELECT json_agg(json_build_object(
           'analyticId', da.analytic_id,
           'name', da.name,
           'description', da.description,
           'platforms', da.platforms
         ) ORDER BY da.analytic_id)
         FROM detection_analytics da WHERE da.det_id = ds.det_id),
         '[]'::json
       )::text AS "analytics"
     FROM detection_strategies ds
     ${where}
     GROUP BY ds.det_id
     ORDER BY ds.det_id ASC
     LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params,
  );

  return withCors(jsonResponse({
    data: dataResult.rows.map((r) => ({
      detId: r.detId,
      name: r.name,
      attackTechniqueId: r.attackTechniqueId,
      analytics: JSON.parse(r.analytics) as Array<{
        analyticId: string; name: string; description: string | null; platforms: string[];
      }>,
    })),
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
    },
  }, 3600));
}
