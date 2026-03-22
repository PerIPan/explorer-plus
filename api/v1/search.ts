import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from './_lib/db.js';
import { withHandler } from './_lib/middleware.js';
import { searchSchema } from './_lib/validate.js';
import { z } from 'zod';

const querySchema = z.object({
  q: searchSchema,
});

const FTS = `to_tsvector('english', COALESCE(name, '') || ' ' || COALESCE(description, '')) @@ plainto_tsquery('english', $1)`;

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const parsed = querySchema.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({
      error: 'Query param "q" is required and must be at least 3 characters',
      code: 'VALIDATION_ERROR',
      details: parsed.error.flatten(),
    });
    return;
  }

  const q = parsed.data.q;

  const [techResult, groupResult, softResult, mitResult, campResult, dsResult] = await Promise.all([
    query<{ attackId: string; name: string; description: string | null; platforms: string[] | null }>(
      `SELECT attack_id AS "attackId", name, description, platforms
       FROM techniques
       WHERE ${FTS} AND is_revoked = false AND is_deprecated = false
       ORDER BY name ASC LIMIT 20`,
      [q],
    ),
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
       WHERE ${FTS} AND is_revoked = false AND is_deprecated = false
       ORDER BY name ASC LIMIT 20`,
      [q],
    ),
    query<{ attackId: string; name: string; description: string | null }>(
      `SELECT attack_id AS "attackId", name, description
       FROM mitigations
       WHERE ${FTS} AND is_revoked = false AND is_deprecated = false
       ORDER BY name ASC LIMIT 20`,
      [q],
    ),
    query<{ attackId: string; name: string; description: string | null }>(
      `SELECT attack_id AS "attackId", name, description
       FROM campaigns
       WHERE ${FTS} AND is_revoked = false AND is_deprecated = false
       ORDER BY name ASC LIMIT 20`,
      [q],
    ),
    query<{ attackId: string; name: string; description: string | null }>(
      `SELECT attack_id AS "attackId", name, description
       FROM data_sources
       WHERE ${FTS}
       ORDER BY name ASC LIMIT 20`,
      [q],
    ),
  ]);

  res.status(200).json({
    query: q,
    techniques: techResult.rows,
    groups: groupResult.rows,
    software: softResult.rows,
    mitigations: mitResult.rows,
    campaigns: campResult.rows,
    data_sources: dsResult.rows,
  });
}

export default withHandler(handler, { cacheTtl: 300 });
