import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../_lib/db';
import { withHandler } from '../_lib/middleware';
import { buildSearchCondition, buildPaginationClause, buildSortClause } from '../_lib/queries';
import { paginationSchema } from '../_lib/validate';
import { z } from 'zod';

const ALLOWED_SORT = ['name', 'attack_id', 'stix_modified'];

const querySchema = paginationSchema.extend({
  search: z.string().min(3).max(200).optional(),
  tactic: z.string().optional(),
  platform: z.string().optional(),
  include_deprecated: z.coerce.boolean().default(false),
});

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const parsed = querySchema.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid query parameters', code: 'VALIDATION_ERROR', details: parsed.error.flatten() });
    return;
  }

  const { page, limit, sort, order, search, tactic, platform, include_deprecated } = parsed.data;
  const sortCol = sort ?? 'name';
  const sortClause = buildSortClause(sortCol, order, ALLOWED_SORT);
  const { offset } = buildPaginationClause(page, limit);

  const params: unknown[] = [];
  const conditions: string[] = ['t.is_subtechnique = false'];

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
       t.platforms,
       t.is_revoked       AS "isRevoked",
       t.is_deprecated    AS "isDeprecated",
       t.stix_modified    AS "stixModified",
       t.domain,
       array_agg(DISTINCT ta.name) FILTER (WHERE ta.name IS NOT NULL) AS "tactics"
     FROM techniques t
     LEFT JOIN technique_tactics tt ON tt.technique_id = t.id
     LEFT JOIN tactics ta ON ta.id = tt.tactic_id
     ${whereClause}
     GROUP BY t.id, t.attack_id, t.name, t.description, t.url, t.platforms,
              t.is_revoked, t.is_deprecated, t.stix_modified, t.domain
     ${sortClause}
     LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params,
  );

  // Fetch sub-techniques for all returned parent techniques in one query
  const attackIds = dataResult.rows.map((r) => r.attackId);
  let subTechniqueMap: Record<string, Array<{ attackId: string; name: string }>> = {};

  if (attackIds.length > 0) {
    const subResult = await query<{ parentAttackId: string; attackId: string; name: string }>(
      `SELECT
         p.attack_id  AS "parentAttackId",
         s.attack_id  AS "attackId",
         s.name
       FROM techniques s
       JOIN techniques p ON p.id = s.parent_technique_id
       WHERE p.attack_id = ANY($1::text[])
         AND s.is_revoked = false
         AND s.is_deprecated = false
       ORDER BY s.attack_id ASC`,
      [attackIds],
    );
    for (const row of subResult.rows) {
      if (!subTechniqueMap[row.parentAttackId]) subTechniqueMap[row.parentAttackId] = [];
      subTechniqueMap[row.parentAttackId].push({ attackId: row.attackId, name: row.name });
    }
  }

  const data = dataResult.rows.map((r) => ({
    ...r,
    tactics: r.tactics ?? [],
    sub_techniques: subTechniqueMap[r.attackId] ?? [],
  }));

  res.status(200).json({
    data,
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
    },
  });
}

export default withHandler(handler, { cacheTtl: 3600 });
