import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../../../lib/db.js';
import { withHandler } from '../../../lib/middleware.js';

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const iocId = typeof req.query.iocId === 'string' ? req.query.iocId : '';
  if (!iocId) {
    res.status(400).json({ error: 'Missing iocId', code: 'VALIDATION_ERROR' });
    return;
  }

  const result = await query<{ attackId: string; name: string }>(
    `SELECT t.attack_id AS "attackId", t.name
     FROM technique_iocs ti
     JOIN techniques t ON t.id = ti.technique_id
     WHERE ti.ioc_id = $1
     ORDER BY t.attack_id ASC`,
    [iocId],
  );

  res.status(200).json({ data: result.rows });
}

export default withHandler(handler, { cacheTtl: 3600 });
