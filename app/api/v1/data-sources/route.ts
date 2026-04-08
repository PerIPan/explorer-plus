import { NextRequest } from 'next/server';
import { query } from '../lib/db.js';
import { jsonResponse, errorResponse } from '../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../lib/cors';
import { buildSearchCondition } from '../lib/queries.js';
import { domainSchema } from '../lib/validate.js';
import { z } from 'zod';

export { OPTIONS };

const querySchema = z.object({
  search: z.string().min(3).max(200).optional(),
  domain: domainSchema,
});

export async function GET(req: NextRequest) {
  const rawParams: Record<string, string> = {};
  req.nextUrl.searchParams.forEach((v, k) => { rawParams[k] = v; });

  const parsed = querySchema.safeParse(rawParams);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Invalid query parameters', 'VALIDATION_ERROR'));
  }

  const { search, domain } = parsed.data;
  const params: unknown[] = [];
  const conditions: string[] = ['ds.is_revoked = false'];

  if (search) {
    params.push(search);
    const { clause } = buildSearchCondition(search);
    conditions.push(clause.replaceAll('name', 'ds.name').replaceAll('description', 'ds.description').replace('$PARAM', `$${params.length}`));
  }

  if (domain) {
    params.push(domain);
    conditions.push(`ds.domain = $${params.length}`);
  }

  const whereClause = `WHERE ${conditions.join(' AND ')}`;

  const dataResult = await query<{
    attackId: string; name: string; description: string | null;
    url: string | null; componentCount: string; domain: string | null;
  }>(
    `SELECT
       ds.attack_id     AS "attackId",
       ds.name,
       ds.description,
       ds.url,
       ds.domain,
       COUNT(dc.id)     AS "componentCount"
     FROM data_sources ds
     LEFT JOIN data_components dc ON dc.data_source_id = ds.id
       AND dc.is_revoked = false AND dc.is_deprecated = false
     ${whereClause}
     GROUP BY ds.id, ds.attack_id, ds.name, ds.description, ds.url, ds.domain
     ORDER BY ds.name ASC`,
    params,
  );

  return withCors(jsonResponse({
    data: dataResult.rows.map((r) => ({
      ...r,
      componentCount: parseInt(r.componentCount, 10),
    })),
  }, 3600));
}
