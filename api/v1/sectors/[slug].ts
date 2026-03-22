import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../lib/db';
import { withHandler } from '../lib/middleware';
import { slugSchema } from '../lib/validate';

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const parsed = slugSchema.safeParse(req.query.slug);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid slug format', code: 'VALIDATION_ERROR' });
    return;
  }
  const slug = parsed.data;

  const sectorResult = await query<{
    id: string; name: string; slug: string | null;
  }>(
    `SELECT id, name, slug FROM sectors WHERE slug = $1`,
    [slug],
  );

  if (sectorResult.rows.length === 0) {
    res.status(404).json({ error: 'Sector not found', code: 'NOT_FOUND' });
    return;
  }

  const sector = sectorResult.rows[0];
  const sectorId = sector.id;

  const groupsResult = await query<{
    attackId: string; name: string; description: string | null;
    aliases: string[] | null; source: string; matchedKeywords: string[] | null;
  }>(
    `SELECT
       tg.attack_id       AS "attackId",
       tg.name,
       tg.description,
       tg.aliases,
       gs.source,
       gs.matched_keywords AS "matchedKeywords"
     FROM group_sectors gs
     JOIN threat_groups tg ON tg.id = gs.group_id
     WHERE gs.sector_id = $1
       AND tg.is_revoked = false AND tg.is_deprecated = false
     ORDER BY tg.name ASC`,
    [sectorId],
  );

  res.status(200).json({
    ...sector,
    groups: groupsResult.rows,
  });
}

export default withHandler(handler, { cacheTtl: 3600 });
