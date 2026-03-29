import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../lib/db.js';
import { withHandler } from '../lib/middleware.js';
import { buildSearchCondition, buildPaginationClause, buildSortClause } from '../lib/queries.js';
import { paginationSchema, domainSchema } from '../lib/validate.js';
import { z } from 'zod';

const ALLOWED_SORT = ['name', 'attack_id', 'stix_modified'];

const querySchema = paginationSchema.extend({
  search: z.string().min(3).max(200).optional(),
  domain: domainSchema,
  include_deprecated: z.coerce.boolean().default(false),
});

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const parsed = querySchema.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid query parameters', code: 'VALIDATION_ERROR', details: parsed.error.flatten() });
    return;
  }

  const { page, limit, sort, order, search, domain, include_deprecated } = parsed.data;
  const sortCol = sort ?? 'name';
  const sortClause = buildSortClause(sortCol, order, ALLOWED_SORT);
  const { offset } = buildPaginationClause(page, limit);

  const params: unknown[] = [];
  const conditions: string[] = [];

  if (!include_deprecated) {
    conditions.push('m.is_revoked = false', 'm.is_deprecated = false');
  }

  if (search) {
    params.push(search);
    const { clause } = buildSearchCondition(search);
    conditions.push(clause.replace('$PARAM', `$${params.length}`));
  }

  if (domain) {
    params.push(domain);
    conditions.push(`m.domain = $${params.length}`);
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  const countResult = await query<{ count: string }>(
    `SELECT count(*) FROM mitigations m ${whereClause}`,
    params,
  );
  const total = parseInt(countResult.rows[0].count, 10);

  params.push(limit, offset);
  const dataResult = await query<{
    attackId: string; name: string; description: string | null;
    url: string | null; isRevoked: boolean; isDeprecated: boolean;
    domain: string | null; stixModified: string | null;
  }>(
    `SELECT
       m.attack_id     AS "attackId",
       m.name,
       m.description,
       m.url,
       m.is_revoked    AS "isRevoked",
       m.is_deprecated AS "isDeprecated",
       m.domain,
       m.stix_modified AS "stixModified"
     FROM mitigations m
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
