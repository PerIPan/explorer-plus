import { NextRequest } from 'next/server';
import { query } from '../lib/db';
import { jsonResponse, errorResponse } from '../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../lib/cors';
import { buildSearchCondition, buildPaginationClause, buildSortClause } from '../lib/queries';
import { paginationSchema, softwareTypeSchema, platformSchema, domainSchema } from '../lib/validate';
import { z } from 'zod';

export { OPTIONS };

const ALLOWED_SORT = ['name', 'attack_id', 'type', 'stix_modified'];

const querySchema = paginationSchema.extend({
  search: z.string().min(3).max(200).optional(),
  type: softwareTypeSchema.optional(),
  platform: platformSchema.optional(),
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

  const { page, limit, sort, order, search, type, platform, sector, domain, include_deprecated } = parsed.data;
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

  if (sector) {
    params.push(sector);
    conditions.push(`sw.id IN (
      SELECT gsw.software_id FROM group_software gsw
      JOIN group_sectors gs ON gs.group_id = gsw.group_id
      JOIN sectors s ON s.id = gs.sector_id WHERE s.slug = $${params.length}
    )`);
  }

  if (domain) {
    params.push(domain);
    conditions.push(`sw.domain = $${params.length}`);
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

  return withCors(jsonResponse({
    data: dataResult.rows,
    pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
  }, 3600));
}
