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

  return withCors(jsonResponse({
    data: dataResult.rows,
    pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
  }, 3600));
}
