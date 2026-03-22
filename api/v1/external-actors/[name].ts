import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../lib/db.js';
import { withHandler } from '../lib/middleware.js';

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const rawName = req.query['name'];
  if (!rawName || typeof rawName !== 'string') {
    res.status(400).json({ error: 'Name parameter required', code: 'VALIDATION_ERROR' });
    return;
  }

  const name = decodeURIComponent(rawName);

  const result = await query<{
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
       tg.name           AS "mitreGroupName"
     FROM external_actors ea
     LEFT JOIN threat_groups tg ON tg.attack_id = ea.mitre_group_id
     WHERE ea.name = $1
     LIMIT 1`,
    [name],
  );

  if (result.rows.length === 0) {
    res.status(404).json({ error: 'Actor not found', code: 'NOT_FOUND' });
    return;
  }

  res.status(200).json(result.rows[0]);
}

export default withHandler(handler, { cacheTtl: 3600 });
