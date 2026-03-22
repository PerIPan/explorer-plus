import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../_lib/db.js';
import { withHandler } from '../_lib/middleware.js';
import { buildSearchCondition, buildPaginationClause, buildSortClause } from '../_lib/queries.js';
import { paginationSchema, softwareTypeSchema } from '../_lib/validate.js';
import { z } from 'zod';

const ALLOWED_SORT = ['name', 'attack_id', 'type', 'stix_modified'];

const querySchema = paginationSchema.extend({
  search: z.string().min(3).max(200).optional(),
  type: softwareTypeSchema.optional(),
  platform: z.string().optional(),
  include_deprecated: z.coerce.boolean().default(false),
});

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const parsed = querySchema.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid query parameters', code: 'VALIDATION_ERROR', details: parsed.error.flatten() });
    return;
  }

  const { page, limit, sort, order, search, type, platform, include_deprecated } = parsed.data;
  const sortCol = sort ?? 'name';
  const sortClause = buildSortClause(sortCol, order, ALLOWED_SORT);
  const { offset } = buildPaginationClause(page, limit);

  const params: unknown[] = [];
  const conditions: string[] = [];

  if (!include_deprecated) {
    conditions.push('sw.is_revoked = false', 'sw.is_deprecated = false');
  }

  if (search) {
    params.push(search);
    const { clause } = buildSearchCondition(search);
    conditions.push(clause.replace('$PARAM', `$${params.length}`));
  }

  if (type) {
    params.push(type);
    conditions.push(`sw.type = $${params.length}`);
  }

  if (platform) {
    params.push(`{${platform}}`);
    conditions.push(`sw.platforms && $${params.length}::text[]`);
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  const countResult = await query<{ count: string }>(
    `SELECT count(*) FROM attack_software sw ${whereClause}`,
    params,
  );
  const total = parseInt(countResult.rows[0].count, 10);

  params.push(limit, offset);
  const dataResult = await query<{
    attackId: string; name: string; description: string | null;
    url: string | null; type: string; platforms: string[] | null;
    aliases: string[] | null; isRevoked: boolean; isDeprecated: boolean;
    domain: string | null; stixModified: string | null;
  }>(
    `SELECT
       sw.attack_id     AS "attackId",
       sw.name,
       sw.description,
       sw.url,
       sw.type,
       sw.platforms,
       sw.aliases,
       sw.is_revoked    AS "isRevoked",
       sw.is_deprecated AS "isDeprecated",
       sw.domain,
       sw.stix_modified AS "stixModified"
     FROM attack_software sw
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
