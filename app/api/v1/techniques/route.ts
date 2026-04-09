import { NextRequest } from 'next/server';
import { query } from '../lib/db';
import { jsonResponse, errorResponse } from '../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../lib/cors';
import { buildSearchCondition, buildPaginationClause } from '../lib/queries';
import { paginationSchema, platformSchema, domainSchema } from '../lib/validate';
import { z } from 'zod';

export { OPTIONS };

// Map frontend sort keys to qualified SQL columns (avoids ambiguity with JOINs)
const SORT_MAP: Record<string, string> = {
  name: 't.name',
  attack_id: 't.attack_id',
  stix_modified: 't.stix_modified',
};

const querySchema = paginationSchema.extend({
  search: z.string().min(3).max(200).optional(),
  tactic: z.string().optional(),
  platform: platformSchema.optional(),
  sector: z.string().max(50).optional(),
  domain: domainSchema,
  include_deprecated: z.coerce.boolean().default(false),
  include_subtechniques: z.coerce.boolean().default(false),
});

export async function GET(req: NextRequest) {
  const rawParams: Record<string, string> = {};
  req.nextUrl.searchParams.forEach((v, k) => { rawParams[k] = v; });

  const parsed = querySchema.safeParse(rawParams);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Invalid query parameters', 'VALIDATION_ERROR'));
  }

  const { page, limit, sort, order, search, tactic, platform, sector, domain, include_deprecated, include_subtechniques } = parsed.data;
  const sortCol = SORT_MAP[sort ?? 'name'] ?? 't.name';
  const sortDir = order === 'desc' ? 'DESC' : 'ASC';
  const sortClause = `ORDER BY ${sortCol} ${sortDir}`;
  const { offset } = buildPaginationClause(page, limit);

  const params: unknown[] = [];
  const conditions: string[] = include_subtechniques ? [] : ['t.is_subtechnique = false'];

  if (!include_deprecated) {
    conditions.push('t.is_revoked = false', 't.is_deprecated = false');
  }

  if (search) {
    params.push(search);
    const { clause } = buildSearchCondition(search);
    conditions.push(clause.replace('$PARAM', `$${params.length}`));
  }

  if (tactic) {
    params.push(tactic);
    conditions.push(`EXISTS (
      SELECT 1 FROM technique_tactics tt
      JOIN tactics ta ON ta.id = tt.tactic_id
      WHERE tt.technique_id = t.id AND ta.attack_id = $${params.length}
    )`);
  }

  if (platform) {
    params.push(`{${platform}}`);
    conditions.push(`t.platforms && $${params.length}::text[]`);
  }

  if (sector) {
    params.push(sector);
    conditions.push(`t.id IN (
      SELECT gt.technique_id FROM group_techniques gt
      JOIN group_sectors gs ON gs.group_id = gt.group_id
      JOIN sectors s ON s.id = gs.sector_id WHERE s.slug = $${params.length}
    )`);
  }

  if (domain) {
    params.push(domain);
    conditions.push(`t.domain = $${params.length}`);
  }

  const whereClause = `WHERE ${conditions.join(' AND ')}`;

  const countResult = await query<{ count: string }>(
    `SELECT count(*) FROM techniques t ${whereClause}`,
    params,
  );
  const total = parseInt(countResult.rows[0].count, 10);

  params.push(limit, offset);
  const dataResult = await query<{
    attackId: string; name: string; description: string | null;
    url: string | null; platforms: string[] | null; isRevoked: boolean;
    isDeprecated: boolean; stixModified: string | null; domain: string | null;
    tactics: string[] | null;
  }>(
    `SELECT
       t.attack_id        AS "attackId",
       t.name,
       t.description,
       t.url,
       COALESCE(t.platforms, pt.platforms) AS "platforms",
       t.is_revoked       AS "isRevoked",
       t.is_deprecated    AS "isDeprecated",
       t.stix_modified    AS "stixModified",
       COALESCE(t.domain, pt.domain)      AS "domain",
       COALESCE(
         array_agg(DISTINCT ta.name) FILTER (WHERE ta.name IS NOT NULL),
         array_agg(DISTINCT pta.name) FILTER (WHERE pta.name IS NOT NULL)
       ) AS "tactics"
     FROM techniques t
     LEFT JOIN techniques pt ON pt.id = t.parent_technique_id
     LEFT JOIN technique_tactics tt ON tt.technique_id = t.id
     LEFT JOIN tactics ta ON ta.id = tt.tactic_id
     LEFT JOIN technique_tactics ptt ON ptt.technique_id = pt.id
     LEFT JOIN tactics pta ON pta.id = ptt.tactic_id
     ${whereClause}
     GROUP BY t.id, t.attack_id, t.name, t.description, t.url, t.platforms,
              t.is_revoked, t.is_deprecated, t.stix_modified, t.domain,
              pt.platforms, pt.domain
     ${sortClause}
     LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params,
  );

  // Fetch sub-techniques for all returned parent techniques in one query
  const attackIds = dataResult.rows.map((r) => r.attackId);
  let subTechniqueMap: Record<string, Array<{ attackId: string; name: string; platforms: string[]; tactics: string[] }>> = {};

  if (attackIds.length > 0) {
    const subResult = await query<{
      parentAttackId: string; attackId: string; name: string;
      platforms: string[] | null; tactics: string[] | null;
    }>(
      `SELECT
         p.attack_id  AS "parentAttackId",
         s.attack_id  AS "attackId",
         s.name,
         COALESCE(s.platforms, p.platforms) AS "platforms",
         COALESCE(
           array_agg(DISTINCT ta.name) FILTER (WHERE ta.name IS NOT NULL),
           array_agg(DISTINCT pta.name) FILTER (WHERE pta.name IS NOT NULL)
         ) AS "tactics"
       FROM techniques s
       JOIN techniques p ON p.id = s.parent_technique_id
       LEFT JOIN technique_tactics stt ON stt.technique_id = s.id
       LEFT JOIN tactics ta ON ta.id = stt.tactic_id
       LEFT JOIN technique_tactics ptt ON ptt.technique_id = p.id
       LEFT JOIN tactics pta ON pta.id = ptt.tactic_id
       WHERE p.attack_id = ANY($1::text[])
         AND s.is_revoked = false
         AND s.is_deprecated = false
       GROUP BY p.attack_id, s.attack_id, s.name, s.platforms, p.platforms
       ORDER BY s.attack_id ASC`,
      [attackIds],
    );
    for (const row of subResult.rows) {
      if (!subTechniqueMap[row.parentAttackId]) subTechniqueMap[row.parentAttackId] = [];
      subTechniqueMap[row.parentAttackId].push({
        attackId: row.attackId,
        name: row.name,
        platforms: row.platforms ?? [],
        tactics: row.tactics ?? [],
      });
    }
  }

  const data = dataResult.rows.map((r) => ({
    ...r,
    tactics: r.tactics ?? [],
    sub_techniques: subTechniqueMap[r.attackId] ?? [],
  }));

  return withCors(jsonResponse({
    data,
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
    },
  }, 3600));
}
