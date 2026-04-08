import { NextRequest } from 'next/server';
import { query } from '../lib/db.js';
import { jsonResponse, errorResponse } from '../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../lib/cors';
import { domainSchema } from '../lib/validate.js';
import { z } from 'zod';

export { OPTIONS };

const querySchema = z.object({
  sector: z.string().max(50).optional(),
  domain: domainSchema,
});

export async function GET(req: NextRequest) {
  const rawParams: Record<string, string> = {};
  req.nextUrl.searchParams.forEach((v, k) => { rawParams[k] = v; });

  const parsed = querySchema.safeParse(rawParams);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Invalid query parameters', 'VALIDATION_ERROR'));
  }

  const { sector, domain } = parsed.data;
  const params: unknown[] = [];
  const conditions: string[] = [];

  let techniqueFilter = '';
  if (sector) {
    params.push(sector);
    conditions.push(`ta.id IN (
      SELECT tt.tactic_id FROM technique_tactics tt
      JOIN group_techniques gt ON gt.technique_id = tt.technique_id
      JOIN group_sectors gs ON gs.group_id = gt.group_id
      JOIN sectors s ON s.id = gs.sector_id
      WHERE s.slug = $${params.length}
    )`);
    techniqueFilter = `AND tt.technique_id IN (
      SELECT gt.technique_id FROM group_techniques gt
      JOIN group_sectors gs ON gs.group_id = gt.group_id
      JOIN sectors s ON s.id = gs.sector_id
      WHERE s.slug = $${params.length}
    )`;
  }

  if (domain) {
    params.push(domain);
    conditions.push(`ta.domain = $${params.length}`);
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  const dataResult = await query<{
    attackId: string; name: string; description: string | null;
    url: string | null; sortOrder: number | null; domain: string | null;
    techniqueCount: string;
  }>(
    `SELECT
       ta.attack_id    AS "attackId",
       ta.name,
       ta.description,
       ta.url,
       ta.sort_order   AS "sortOrder",
       ta.domain,
       (SELECT COUNT(DISTINCT tt.technique_id)
        FROM technique_tactics tt
        JOIN techniques t ON t.id = tt.technique_id
          AND t.is_revoked = false AND t.is_deprecated = false
        WHERE tt.tactic_id = ta.id ${techniqueFilter}
       ) AS "techniqueCount"
     FROM tactics ta
     ${whereClause}
     ORDER BY ta.sort_order ASC NULLS LAST`,
    params,
  );

  return withCors(jsonResponse({
    data: dataResult.rows.map((r) => ({
      ...r,
      techniqueCount: parseInt(r.techniqueCount, 10),
    })),
  }, 3600));
}
