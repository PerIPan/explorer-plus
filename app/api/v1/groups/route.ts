import { NextRequest } from 'next/server';
import { query } from '../lib/db';
import { jsonResponse, errorResponse } from '../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../lib/cors';
import { buildSearchCondition, buildPaginationClause, buildSortClause } from '../lib/queries';
import { paginationSchema, domainSchema } from '../lib/validate';
import { z } from 'zod';

export { OPTIONS };

const ALLOWED_SORT = ['name', 'attack_id', 'stix_modified'];

const querySchema = paginationSchema.extend({
  search: z.string().min(3).max(200).optional(),
  sector: z.string().max(50).optional(),
  domain: domainSchema,
  include_deprecated: z.coerce.boolean().default(false),
});

export async function GET(req: NextRequest) {
  const rawParams: Record<string, string> = {};
  req.nextUrl.searchParams.forEach((v, k) => { rawParams[k] = v; });

  const parsed = querySchema.safeParse(rawParams);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Invalid query parameters', 'VALIDATION_ERROR'));
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
    conditions.push(clause.replaceAll('name', 'g.name').replaceAll('description', 'g.description').replace('$PARAM', `$${params.length}`));
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

  return withCors(jsonResponse({
    data: dataResult.rows,
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
    },
  }, 3600));
}
