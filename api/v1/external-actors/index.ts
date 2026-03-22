import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../lib/db.js';
import { withHandler } from '../lib/middleware.js';
import { paginationSchema } from '../lib/validate.js';
import { buildPaginationClause, buildSortClause } from '../lib/queries.js';
import { z } from 'zod';

const ALLOWED_SORT = ['name', 'country', 'category', 'source'];

const querySchema = paginationSchema.extend({
  search: z.string().min(2).max(200).optional(),
  country: z.string().max(20).optional(),
  category: z.string().max(50).optional(),
  source: z.string().max(50).optional(),
});

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const parsed = querySchema.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({
      error: 'Invalid query parameters',
      code: 'VALIDATION_ERROR',
      details: parsed.error.flatten(),
    });
    return;
  }

  const { page, limit, sort, order, search, country, category, source } = parsed.data;
  const sortCol = sort ?? 'name';
  const sortClause = buildSortClause(sortCol, order, ALLOWED_SORT);
  const { offset } = buildPaginationClause(page, limit);

  const params: unknown[] = [];
  const conditions: string[] = [];

  if (search) {
    params.push(search);
    conditions.push(
      `to_tsvector('english', COALESCE(name, '') || ' ' || COALESCE(description, '')) @@ plainto_tsquery('english', $${params.length})`,
    );
  }

  if (country) {
    params.push(country);
    conditions.push(`country = $${params.length}`);
  }

  if (category) {
    params.push(category);
    conditions.push(`category = $${params.length}`);
  }

  if (source) {
    params.push(source);
    conditions.push(`source = $${params.length}`);
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  const countResult = await query<{ count: string }>(
    `SELECT count(*) FROM external_actors ${whereClause}`,
    params,
  );
  const total = parseInt(countResult.rows[0].count, 10);

  params.push(limit, offset);
  const dataResult = await query<{
    id: string;
    name: string;
    description: string | null;
    source: string;
    country: string | null;
    category: string | null;
    synonyms: string[] | null;
    refs: string[] | null;
    mitreGroupId: string | null;
  }>(
    `SELECT
       id,
       name,
       description,
       source,
       country,
       category,
       synonyms,
       refs,
       mitre_group_id AS "mitreGroupId"
     FROM external_actors
     ${whereClause}
     ${sortClause}
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
