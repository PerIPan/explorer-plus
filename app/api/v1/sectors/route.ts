import { NextRequest } from 'next/server';
import { query } from '../lib/db.js';
import { jsonResponse } from '../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../lib/cors';

export { OPTIONS };

export async function GET(_req: NextRequest) {
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

  return withCors(jsonResponse({
    data: dataResult.rows.map((r) => ({
      ...r,
      groupCount: parseInt(r.groupCount, 10),
    })),
  }, 3600));
}
