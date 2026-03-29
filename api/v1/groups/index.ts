import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../lib/db.js';
import { withHandler } from '../lib/middleware.js';
import { buildSearchCondition, buildPaginationClause, buildSortClause } from '../lib/queries.js';
import { paginationSchema, domainSchema } from '../lib/validate.js';
import { z } from 'zod';

const ALLOWED_SORT = ['name', 'attack_id', 'stix_modified'];

const querySchema = paginationSchema.extend({
  search: z.string().min(3).max(200).optional(),
  sector: z.string().max(50).optional(),
  domain: domainSchema,
  include_deprecated: z.coerce.boolean().default(false),
});

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const parsed = querySchema.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid query parameters', code: 'VALIDATION_ERROR', details: parsed.error.flatten() });
    return;
  }

  const { page, limit, sort, order, search, sector, domain, include_deprecated } = parsed.data;
  const sortCol = sort ?? 'name';
  const sortClause = buildSortClause(sortCol, order, ALLOWED_SORT);
  const { offset } = buildPaginationClause(page, limit);

  const params: unknown[] = [];
  const conditions: string[] = [];

  if (!include_deprecated) {
    conditions.push('g.is_revoked = false', 'g.is_deprecated = false');
  }

  if (search) {
    params.push(search);
    const { clause } = buildSearchCondition(search);
    conditions.push(clause.replace('name', 'g.name').replace('description', 'g.description').replace('$PARAM', `$${params.length}`));
  }

  if (sector) {
    params.push(sector);
    conditions.push(`EXISTS (
      SELECT 1 FROM group_sectors gs
      JOIN sectors s ON s.id = gs.sector_id
      WHERE gs.group_id = g.id AND s.slug = $${params.length}
    )`);
  }

  if (domain) {
    params.push(domain);
    conditions.push(`EXISTS (
      SELECT 1 FROM group_techniques gt
      JOIN techniques t ON t.id = gt.technique_id
      WHERE gt.group_id = g.id AND t.domain = $${params.length}
    )`);
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  const countResult = await query<{ count: string }>(
    `SELECT count(*) FROM threat_groups g ${whereClause}`,
    params,
  );
  const total = parseInt(countResult.rows[0].count, 10);

  params.push(limit, offset);
  const dataResult = await query<{
    attackId: string; name: string; description: string | null;
    url: string | null; aliases: string[] | null; isRevoked: boolean;
    isDeprecated: boolean; stixModified: string | null; domain: string | null;
  }>(
    `SELECT
       g.attack_id     AS "attackId",
       g.name,
       g.description,
       g.url,
       g.aliases,
       g.is_revoked    AS "isRevoked",
       g.is_deprecated AS "isDeprecated",
       g.stix_modified AS "stixModified",
       g.domain
     FROM threat_groups g
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
