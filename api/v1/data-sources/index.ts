import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../lib/db';
import { withHandler } from '../lib/middleware';
import { buildSearchCondition } from '../lib/queries';
import { z } from 'zod';

const querySchema = z.object({
  search: z.string().min(3).max(200).optional(),
});

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const parsed = querySchema.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid query parameters', code: 'VALIDATION_ERROR', details: parsed.error.flatten() });
    return;
  }

  const { search } = parsed.data;
  const params: unknown[] = [];
  const conditions: string[] = ['ds.is_revoked = false', 'ds.is_deprecated = false'];

  if (search) {
    params.push(search);
    const { clause } = buildSearchCondition(search);
    conditions.push(clause.replace('$PARAM', `$${params.length}`));
  }

  const whereClause = `WHERE ${conditions.join(' AND ')}`;

  const dataResult = await query<{
    attackId: string; name: string; description: string | null;
    url: string | null; componentCount: string; domain: string | null;
  }>(
    `SELECT
       ds.attack_id     AS "attackId",
       ds.name,
       ds.description,
       ds.url,
       ds.domain,
       COUNT(dc.id)     AS "componentCount"
     FROM data_sources ds
     LEFT JOIN data_components dc ON dc.data_source_id = ds.id
       AND dc.is_revoked = false AND dc.is_deprecated = false
     ${whereClause}
     GROUP BY ds.id, ds.attack_id, ds.name, ds.description, ds.url, ds.domain
     ORDER BY ds.name ASC`,
    params,
  );

  res.status(200).json({
    data: dataResult.rows.map((r) => ({
      ...r,
      componentCount: parseInt(r.componentCount, 10),
    })),
  });
}

export default withHandler(handler, { cacheTtl: 3600 });
