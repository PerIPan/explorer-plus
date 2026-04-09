import { NextRequest } from 'next/server';
import { query } from '../lib/db';
import { jsonResponse, errorResponse } from '../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../lib/cors';
import { searchSchema, domainSchema } from '../lib/validate';
import { z } from 'zod';

export { OPTIONS };

const querySchema = z.object({
  q: searchSchema,
  domain: domainSchema,
});

const FTS = `to_tsvector('english', COALESCE(name, '') || ' ' || COALESCE(description, '')) @@ plainto_tsquery('english', $1)`;

export async function GET(req: NextRequest) {
  const rawParams: Record<string, string> = {};
  req.nextUrl.searchParams.forEach((v, k) => { rawParams[k] = v; });

  const parsed = querySchema.safeParse(rawParams);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Query param "q" is required and must be at least 3 characters', 'VALIDATION_ERROR'));
  }

  const { q, domain } = parsed.data;
  // $1 = search term; $2 = domain (when provided)
  const domainCond = domain ? ` AND domain = $2` : '';
  const domainParams = domain ? [q, domain] : [q];

  const [techResult, groupResult, softResult, mitResult, campResult, dsResult, owaspResult] = await Promise.all([
    query<{ attackId: string; name: string; description: string | null; platforms: string[] | null }>(
      `SELECT attack_id AS "attackId", name, description, platforms
       FROM techniques
       WHERE ${FTS} AND is_revoked = false AND is_deprecated = false${domainCond}
       ORDER BY name ASC LIMIT 20`,
      domainParams,
    ),
    // Groups are NOT filtered by domain
    query<{ attackId: string; name: string; description: string | null; aliases: string[] | null }>(
      `SELECT attack_id AS "attackId", name, description, aliases
       FROM threat_groups
       WHERE ${FTS} AND is_revoked = false AND is_deprecated = false
       ORDER BY name ASC LIMIT 20`,
      [q],
    ),
    query<{ attackId: string; name: string; type: string; description: string | null }>(
      `SELECT attack_id AS "attackId", name, type, description
       FROM attack_software
       WHERE ${FTS} AND is_revoked = false AND is_deprecated = false${domainCond}
       ORDER BY name ASC LIMIT 20`,
      domainParams,
    ),
    query<{ attackId: string; name: string; description: string | null }>(
      `SELECT attack_id AS "attackId", name, description
       FROM mitigations
       WHERE ${FTS} AND is_revoked = false AND is_deprecated = false${domainCond}
       ORDER BY name ASC LIMIT 20`,
      domainParams,
    ),
    query<{ attackId: string; name: string; description: string | null }>(
      `SELECT attack_id AS "attackId", name, description
       FROM campaigns
       WHERE ${FTS} AND is_revoked = false AND is_deprecated = false${domainCond}
       ORDER BY name ASC LIMIT 20`,
      domainParams,
    ),
    query<{ attackId: string; name: string; description: string | null }>(
      `SELECT attack_id AS "attackId", name, description
       FROM data_sources
       WHERE ${FTS}${domainCond}
       ORDER BY name ASC LIMIT 20`,
      domainParams,
    ),
    // OWASP categories — not domain-filtered
    query<{ categoryId: string; name: string; framework: string; isDraft: boolean }>(
      `SELECT category_id AS "categoryId", name, framework, is_draft AS "isDraft"
       FROM owasp_top10
       WHERE to_tsvector('english', name || ' ' || COALESCE(description, '')) @@ plainto_tsquery('english', $1)
          OR UPPER(category_id) = UPPER($1)
       ORDER BY framework, category_id LIMIT 20`,
      [q],
    ),
  ]);

  return withCors(jsonResponse({
    query: q,
    techniques: techResult.rows,
    groups: groupResult.rows,
    software: softResult.rows,
    mitigations: mitResult.rows,
    campaigns: campResult.rows,
    data_sources: dsResult.rows,
    owasp: owaspResult.rows,
  }, 300));
}
