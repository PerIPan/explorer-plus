import { NextRequest } from 'next/server';
import { query } from '../../lib/db';
import { jsonResponse, errorResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';
import { slugSchema } from '../../lib/validate';

export { OPTIONS };

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ slug: string }> }
) {
  const { slug: rawSlug } = await params;
  const parsed = slugSchema.safeParse(rawSlug);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Invalid slug format', 'VALIDATION_ERROR'));
  }
  const slug = parsed.data;

  const sectorResult = await query<{
    id: string; name: string; slug: string | null;
  }>(
    `SELECT id, name, slug FROM sectors WHERE slug = $1`,
    [slug],
  );

  if (sectorResult.rows.length === 0) {
    return withCors(errorResponse(404, 'Sector not found', 'NOT_FOUND'));
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

  return withCors(jsonResponse({
    ...sector,
    groups: groupsResult.rows,
  }, 3600));
}
