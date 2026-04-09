import { NextRequest } from 'next/server';
import { query } from '../lib/db';
import { jsonResponse, errorResponse } from '../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../lib/cors';
import { searchSchema, paginationSchema } from '../lib/validate';
import { buildPaginationClause } from '../lib/queries';
import { z } from 'zod';

export { OPTIONS };

const querySchema = paginationSchema.extend({
  q: searchSchema,
});

const FTS = `to_tsvector('english', COALESCE(description, '')) @@ plainto_tsquery('english', $1)`;

export async function GET(req: NextRequest) {
  const rawParams: Record<string, string> = {};
  req.nextUrl.searchParams.forEach((v, k) => { rawParams[k] = v; });

  const parsed = querySchema.safeParse(rawParams);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Query param "q" is required and must be at least 3 characters', 'VALIDATION_ERROR'));
  }

  const { q, page, limit } = parsed.data;
  const { offset } = buildPaginationClause(page, limit);

  // Count across all three procedure tables
  const countResult = await query<{ count: string }>(
    `SELECT (
       (SELECT count(*) FROM group_techniques    WHERE ${FTS}) +
       (SELECT count(*) FROM software_techniques WHERE ${FTS}) +
       (SELECT count(*) FROM campaign_techniques WHERE ${FTS})
     )::text AS count`,
    [q],
  );
  const total = parseInt(countResult.rows[0].count, 10);

  // Union across all three tables with source info
  const dataResult = await query<{
    sourceType: string; sourceAttackId: string; sourceName: string;
    techniqueAttackId: string; techniqueName: string;
    description: string | null;
  }>(
    `(
       SELECT
         'group'      AS "sourceType",
         tg.attack_id AS "sourceAttackId",
         tg.name      AS "sourceName",
         t.attack_id  AS "techniqueAttackId",
         t.name       AS "techniqueName",
         gt.description
       FROM group_techniques gt
       JOIN threat_groups tg ON tg.id = gt.group_id
       JOIN techniques    t  ON t.id  = gt.technique_id
       WHERE ${FTS.replace('description', 'gt.description')}
     )
     UNION ALL
     (
       SELECT
         'software'   AS "sourceType",
         sw.attack_id AS "sourceAttackId",
         sw.name      AS "sourceName",
         t.attack_id  AS "techniqueAttackId",
         t.name       AS "techniqueName",
         st.description
       FROM software_techniques st
       JOIN attack_software sw ON sw.id = st.software_id
       JOIN techniques      t  ON t.id  = st.technique_id
       WHERE ${FTS.replace('description', 'st.description')}
     )
     UNION ALL
     (
       SELECT
         'campaign'   AS "sourceType",
         c.attack_id  AS "sourceAttackId",
         c.name       AS "sourceName",
         t.attack_id  AS "techniqueAttackId",
         t.name       AS "techniqueName",
         ct.description
       FROM campaign_techniques ct
       JOIN campaigns  c ON c.id  = ct.campaign_id
       JOIN techniques t ON t.id  = ct.technique_id
       WHERE ${FTS.replace('description', 'ct.description')}
     )
     ORDER BY "sourceName" ASC, "techniqueName" ASC
     LIMIT $2 OFFSET $3`,
    [q, limit, offset],
  );

  return withCors(jsonResponse({
    data: dataResult.rows,
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
    },
  }, 300));
}
