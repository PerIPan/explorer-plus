import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../lib/db.js';
import { withHandler } from '../lib/middleware.js';
import { buildSearchCondition, buildPaginationClause, buildSortClause } from '../lib/queries.js';
import { paginationSchema } from '../lib/validate.js';
import { z } from 'zod';

const ALLOWED_SORT = ['name', 'attack_id', 'first_seen', 'last_seen', 'stix_modified'];

const querySchema = paginationSchema.extend({
  search: z.string().min(3).max(200).optional(),
  sector: z.string().max(50).optional(),
  domain: z.enum(['enterprise-attack', 'mobile-attack', 'ics-attack']).optional(),
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
    conditions.push('c.is_revoked = false', 'c.is_deprecated = false');
  }

  if (search) {
    params.push(search);
    const { clause } = buildSearchCondition(search);
    conditions.push(clause.replace('$PARAM', `$${params.length}`));
  }

  if (sector) {
    params.push(sector);
    conditions.push(`c.id IN (
      SELECT gc.campaign_id FROM group_campaigns gc
      JOIN group_sectors gs ON gs.group_id = gc.group_id
      JOIN sectors s ON s.id = gs.sector_id WHERE s.slug = $${params.length}
    )`);
  }

  if (domain) {
    params.push(domain);
    conditions.push(`c.domain = $${params.length}`);
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  const countResult = await query<{ count: string }>(
    `SELECT count(*) FROM campaigns c ${whereClause}`,
    params,
  );
  const total = parseInt(countResult.rows[0].count, 10);

  params.push(limit, offset);
  const dataResult = await query<{
    attackId: string; name: string; description: string | null;
    url: string | null; aliases: string[] | null; firstSeen: string | null;
    lastSeen: string | null; isRevoked: boolean; isDeprecated: boolean;
    domain: string | null; stixModified: string | null;
  }>(
    `SELECT
       c.attack_id     AS "attackId",
       c.name,
       c.description,
       c.url,
       c.aliases,
       c.first_seen    AS "firstSeen",
       c.last_seen     AS "lastSeen",
       c.is_revoked    AS "isRevoked",
       c.is_deprecated AS "isDeprecated",
       c.domain,
       c.stix_modified AS "stixModified"
     FROM campaigns c
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
