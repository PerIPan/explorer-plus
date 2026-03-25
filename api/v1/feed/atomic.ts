import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../lib/db.js';
import { withHandler } from '../lib/middleware.js';
import { paginationSchema } from '../lib/validate.js';
import { z } from 'zod';

const querySchema = paginationSchema.extend({
  technique: z.string().optional(),
  platform: z.string().optional(),
  q: z.string().max(200).optional(),
});

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const parsed = querySchema.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid query parameters', code: 'VALIDATION_ERROR' });
    return;
  }

  const { page, limit, technique, platform, q } = parsed.data;
  const offset = (page - 1) * limit;

  const params: unknown[] = [];
  const conditions: string[] = [];

  if (q) {
    const { escapeLikePattern } = await import('../lib/queries.js');
    params.push(`%${escapeLikePattern(q)}%`);
    conditions.push(`(a.name ILIKE $${params.length} OR a.attack_technique_id ILIKE $${params.length})`);
  }

  if (technique) {
    params.push(technique);
    conditions.push(`a.attack_technique_id = $${params.length}`);
  }

  if (platform) {
    params.push(`{${platform}}`);
    conditions.push(`a.platforms && $${params.length}::text[]`);
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  const countResult = await query<{ count: string }>(
    `SELECT COUNT(*) FROM atomic_tests a ${whereClause}`,
    params,
  );
  const total = parseInt(countResult.rows[0].count, 10);

  params.push(limit, offset);
  const dataResult = await query<{
    id: string;
    test_number: number;
    name: string;
    description: string | null;
    platforms: string[] | null;
    executor_type: string | null;
    executor_command: string | null;
    cleanup_command: string | null;
    technique_attack_id: string | null;
    technique_name: string | null;
  }>(
    `SELECT
       a.id,
       a.test_number,
       a.name,
       a.description,
       a.platforms,
       a.executor_type,
       a.executor_command,
       a.cleanup_command,
       COALESCE(t.attack_id, a.attack_technique_id) AS technique_attack_id,
       t.name AS technique_name
     FROM atomic_tests a
     LEFT JOIN techniques t ON t.id = a.technique_id
     ${whereClause}
     ORDER BY a.attack_technique_id ASC NULLS LAST, a.test_number ASC
     LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params,
  );

  res.status(200).json({
    data: dataResult.rows,
    pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
  });
}

export default withHandler(handler);
