import { NextRequest } from 'next/server';
import { query } from '../lib/db';
import { jsonResponse, errorResponse } from '../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../lib/cors';
import { escapeLikePattern } from '../lib/queries';
import { z } from 'zod';

export { OPTIONS };

const LEVEL_KEYS = ['l0', 'l1', 'l2', 'l3', 'l3_5', 'l4', 'l5'] as const;
const ZONES = ['ot', 'dmz', 'it'] as const;

const querySchema = z.object({
  search:   z.string().min(2).max(200).optional(),
  level:    z.enum(LEVEL_KEYS).optional(),
  zone:     z.enum(ZONES).optional(),
  sector:   z.string().max(60).optional(),
  boundary: z.enum(['true', 'false']).optional(),
  page:     z.coerce.number().int().positive().max(1000).default(1),
  limit:    z.coerce.number().int().positive().max(200).default(50),
});

export async function GET(req: NextRequest) {
  const rawParams: Record<string, string> = {};
  req.nextUrl.searchParams.forEach((v, k) => { rawParams[k] = v; });

  const parsed = querySchema.safeParse(rawParams);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Invalid query params', 'VALIDATION_ERROR'));
  }

  const { search, level, zone, sector, boundary, page, limit } = parsed.data;
  const offset = (page - 1) * limit;
  const params: unknown[] = [];
  const conditions: string[] = ['NOT a.is_revoked', 'NOT a.is_deprecated'];

  if (search) {
    // Escape % and _ so a caller-supplied wildcard cannot turn this filter
    // into a match-everything scan (as 17 other v1 routes already do).
    params.push(`%${escapeLikePattern(search)}%`);
    conditions.push(`(a.name ILIKE $${params.length} OR a.attack_id ILIKE $${params.length})`);
  }
  if (level) {
    // Matches an asset present at the level, not merely primary there — the
    // Historian is at L3 and L3.5, and both answers must include it.
    params.push(level);
    conditions.push(`$${params.length} = ANY(p.spans_levels)`);
  }
  if (zone) {
    params.push(zone);
    conditions.push(
      `EXISTS (SELECT 1 FROM purdue_levels zl
                WHERE zl.level_key = ANY(p.spans_levels) AND zl.zone = $${params.length})`,
    );
  }
  if (sector) {
    // Labels are stored as MITRE writes them ("Electric", "Water and
    // Wastewater"); match case-insensitively so "electric" finds them too.
    params.push(sector);
    conditions.push(
      `EXISTS (SELECT 1 FROM unnest(COALESCE(a.sectors, '{}')) s WHERE lower(s) = lower($${params.length}))`,
    );
  }
  if (boundary === 'true')  conditions.push('p.is_boundary');
  if (boundary === 'false') conditions.push('NOT p.is_boundary');

  const where = `WHERE ${conditions.join(' AND ')}`;

  const countResult = await query<{ total: string }>(
    `SELECT COUNT(*) AS total
       FROM attack_assets a
       LEFT JOIN asset_purdue_placement p ON p.asset_id = a.id
     ${where}`,
    params,
  );
  const total = parseInt(countResult.rows[0].total, 10);

  params.push(limit, offset);
  const dataResult = await query(
    `SELECT
       a.attack_id                       AS "attackId",
       a.name,
       a.url,
       COALESCE(a.sectors,   '{}')       AS sectors,
       COALESCE(a.platforms, '{}')       AS platforms,
       p.primary_level                   AS "primaryLevel",
       l.label                           AS "primaryLevelLabel",
       l.zone,
       COALESCE(p.spans_levels, '{}')    AS "spansLevels",
       COALESCE(p.is_boundary, false)    AS "isBoundary",
       p.rationale,
       COALESCE(t.n, 0)::int             AS "techniqueCount"
     FROM attack_assets a
     LEFT JOIN asset_purdue_placement p ON p.asset_id = a.id
     LEFT JOIN purdue_levels l          ON l.level_key = p.primary_level
     LEFT JOIN (
       SELECT asset_id, COUNT(*) AS n FROM asset_techniques GROUP BY asset_id
     ) t ON t.asset_id = a.id
     ${where}
     ORDER BY l.sort_order NULLS LAST, a.attack_id ASC
     LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params,
  );

  return withCors(jsonResponse({
    data: dataResult.rows,
    pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
  }, 3600));
}
