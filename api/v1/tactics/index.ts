import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../lib/db.js';
import { withHandler } from '../lib/middleware.js';
import { z } from 'zod';

const querySchema = z.object({
  sector: z.string().max(50).optional(),
  domain: z.enum(['enterprise-attack', 'mobile-attack', 'ics-attack']).optional(),
});

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const parsed = querySchema.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid query parameters', code: 'VALIDATION_ERROR', details: parsed.error.flatten() });
    return;
  }

  const { sector, domain } = parsed.data;
  const params: unknown[] = [];
  const conditions: string[] = [];

  // Base: count non-revoked, non-deprecated techniques per tactic
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
    // Also filter the technique count to sector-linked techniques only
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

  res.status(200).json({
    data: dataResult.rows.map((r) => ({
      ...r,
      techniqueCount: parseInt(r.techniqueCount, 10),
    })),
  });
}

export default withHandler(handler, { cacheTtl: 3600 });
