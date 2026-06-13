import { NextRequest } from 'next/server';
import { query } from '../../lib/db';
import { jsonResponse, errorResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';
import { paginationSchema } from '../../lib/validate';
import { escapeLikePattern } from '../../lib/queries';
import { z } from 'zod';

export { OPTIONS };

const querySchema = paginationSchema.extend({
  technique: z.string().optional(),
  level: z.string().optional(),
  q: z.string().min(1).max(200).optional(),
});

export async function GET(req: NextRequest) {
  const rawParams: Record<string, string> = {};
  req.nextUrl.searchParams.forEach((v, k) => { rawParams[k] = v; });

  const parsed = querySchema.safeParse(rawParams);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Invalid query parameters', 'VALIDATION_ERROR'));
  }

  const { page, limit, technique, level, q } = parsed.data;
  const offset = (page - 1) * limit;

  const params: unknown[] = [];
  const conditions: string[] = [];

  if (technique) {
    params.push(technique);
    // sigma_rules has both attack_technique_id (text) and technique_id (FK)
    conditions.push(`s.attack_technique_id = $${params.length}`);
  }

  if (level) {
    params.push(level);
    conditions.push(`s.level = $${params.length}`);
  }

  if (q) {
    params.push(`%${escapeLikePattern(q)}%`);
    conditions.push(`(s.title ILIKE $${params.length} OR s.sigma_id ILIKE $${params.length})`);
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  const countResult = await query<{ count: string }>(
    `SELECT COUNT(*) FROM sigma_rules s ${whereClause}`,
    params,
  );
  const total = parseInt(countResult.rows[0].count, 10);

  params.push(limit, offset);
  const dataResult = await query<{
    id: string;
    sigma_id: string | null;
    title: string;
    level: string | null;
    status: string | null;
    logsource_category: string | null;
    logsource_product: string | null;
    technique_attack_id: string | null;
    technique_name: string | null;
    created_at: string;
  }>(
    `SELECT
       s.id,
       s.sigma_id,
       s.title,
       s.level,
       s.status,
       s.logsource_category,
       s.logsource_product,
       COALESCE(t.attack_id, s.attack_technique_id) AS technique_attack_id,
       t.name AS technique_name,
       s.created_at
     FROM sigma_rules s
     LEFT JOIN techniques t ON t.id = s.technique_id
     ${whereClause}
     ORDER BY
       CASE s.level
         WHEN 'critical' THEN 1
         WHEN 'high' THEN 2
         WHEN 'medium' THEN 3
         WHEN 'low' THEN 4
         WHEN 'informational' THEN 5
         ELSE 6
       END,
       s.title ASC
     LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params,
  );

  return withCors(jsonResponse({
    data: dataResult.rows,
    pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
  }, 1800));
}
