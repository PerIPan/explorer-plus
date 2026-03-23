import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../../../lib/db.js';
import { withHandler } from '../../../lib/middleware.js';
import { z } from 'zod';

const uuidSchema = z.string().uuid();

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const raw = typeof req.query.reportId === 'string' ? req.query.reportId : '';
  const parsed = uuidSchema.safeParse(raw);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid reportId', code: 'VALIDATION_ERROR' });
    return;
  }
  const reportId = parsed.data;

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
