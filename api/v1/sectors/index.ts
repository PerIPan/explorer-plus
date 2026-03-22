import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../_lib/db.js';
import { withHandler } from '../_lib/middleware.js';

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const dataResult = await query<{
    name: string; slug: string | null; groupCount: string;
  }>(
    `SELECT
       s.name,
       s.slug,
       COUNT(DISTINCT gs.group_id) AS "groupCount"
     FROM sectors s
     LEFT JOIN group_sectors gs ON gs.sector_id = s.id
     GROUP BY s.id, s.name, s.slug
     ORDER BY s.name ASC`,
  );

  res.status(200).json({
    data: dataResult.rows.map((r) => ({
      ...r,
      groupCount: parseInt(r.groupCount, 10),
    })),
  });
}

export default withHandler(handler, { cacheTtl: 3600 });
