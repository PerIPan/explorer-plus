import { NextRequest } from 'next/server';
import { query } from '../lib/db';
import { jsonResponse, errorResponse } from '../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../lib/cors';
import { paginationSchema } from '../lib/validate';
import { buildPaginationClause } from '../lib/queries';
import { z } from 'zod';

export { OPTIONS };

const querySchema = paginationSchema.extend({
  search: z.string().min(2).max(200).optional(),
  country: z.string().max(20).optional(),
  category: z.string().max(50).optional(),
  source: z.string().max(50).optional(),
  mitre_group: z.string().max(20).optional(),
});

export async function GET(req: NextRequest) {
  const rawParams: Record<string, string> = {};
  req.nextUrl.searchParams.forEach((v, k) => { rawParams[k] = v; });

  const parsed = querySchema.safeParse(rawParams);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Invalid query parameters', 'VALIDATION_ERROR'));
  }

  const { page, limit, sort, order, search, country, category, source, mitre_group } = parsed.data;
  const sortCol = sort ?? 'name';
  const SORT_MAP: Record<string, string> = { name: "ea.name", country: "ea.country", category: "ea.category", source: "ea.source" };
  const sortClause = `ORDER BY ${SORT_MAP[sortCol] ?? "ea.name"} ${order === "desc" ? "DESC" : "ASC"}`;
  const { offset } = buildPaginationClause(page, limit);

  const params: unknown[] = [];
  const conditions: string[] = [];

  if (search) {
    params.push(search);
    conditions.push(
      `to_tsvector('english', COALESCE(ea.name, '') || ' ' || COALESCE(ea.description, '')) @@ plainto_tsquery('english', $${params.length})`,
    );
  }

  if (country) {
    params.push(country);
    conditions.push(`ea.country = $${params.length}`);
  }

  if (category) {
    params.push(category);
    conditions.push(`ea.category = $${params.length}`);
  }

  if (source) {
    params.push(source);
    conditions.push(`ea.source = $${params.length}`);
  }

  if (mitre_group) {
    params.push(mitre_group);
    conditions.push(`ea.mitre_group_id = $${params.length}`);
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  const countResult = await query<{ count: string }>(
    `SELECT count(*) FROM external_actors ea ${whereClause}`,
    params,
  );
  const total = parseInt(countResult.rows[0].count, 10);

  params.push(limit, offset);
  const dataResult = await query<{
    id: string;
    name: string;
    description: string | null;
    source: string;
    country: string | null;
    category: string | null;
    synonyms: string[] | null;
    refs: string[] | null;
    mitreGroupId: string | null;
    mitreGroupName: string | null;
    motivation: string | null;
    suspectedVictims: string[] | null;
    targetCategories: string[] | null;
    suspectedStateSponsor: string | null;
    attributionConfidence: string | null;
  }>(
    `SELECT
       ea.id,
       ea.name,
       ea.description,
       ea.source,
       ea.country,
       ea.category,
       ea.synonyms,
       ea.refs,
       ea.mitre_group_id AS "mitreGroupId",
       tg.name AS "mitreGroupName",
       ea.motivation,
       ea.suspected_victims AS "suspectedVictims",
       ea.target_categories AS "targetCategories",
       ea.suspected_state_sponsor AS "suspectedStateSponsor",
       ea.attribution_confidence AS "attributionConfidence"
     FROM external_actors ea
     LEFT JOIN threat_groups tg ON tg.attack_id = ea.mitre_group_id
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
