import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../../../lib/db.js';
import { withHandler } from '../../../lib/middleware.js';

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const reportId = typeof req.query.reportId === 'string' ? req.query.reportId : '';
  if (!reportId) {
    res.status(400).json({ error: 'Missing reportId', code: 'VALIDATION_ERROR' });
    return;
  }

  const result = await query<{ attackId: string; name: string }>(
    `SELECT t.attack_id AS "attackId", t.name
     FROM report_techniques rt
     JOIN techniques t ON t.id = rt.technique_id
     WHERE rt.report_id = $1
     ORDER BY t.attack_id ASC`,
    [reportId],
  );

  res.status(200).json({ data: result.rows });
}

export default withHandler(handler, { cacheTtl: 3600 });
