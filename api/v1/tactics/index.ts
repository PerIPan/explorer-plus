import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../_lib/db';
import { withHandler } from '../_lib/middleware';

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
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
       COUNT(DISTINCT tt.technique_id) AS "techniqueCount"
     FROM tactics ta
     LEFT JOIN technique_tactics tt ON tt.tactic_id = ta.id
     LEFT JOIN techniques t ON t.id = tt.technique_id
       AND t.is_revoked = false AND t.is_deprecated = false
     GROUP BY ta.id, ta.attack_id, ta.name, ta.description, ta.url, ta.sort_order, ta.domain
     ORDER BY ta.sort_order ASC NULLS LAST`,
  );

  res.status(200).json({
    data: dataResult.rows.map((r) => ({
      ...r,
      techniqueCount: parseInt(r.techniqueCount, 10),
    })),
  });
}

export default withHandler(handler, { cacheTtl: 3600 });
