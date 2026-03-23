import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../../../lib/db.js';
import { withHandler } from '../../../lib/middleware.js';
import { z } from 'zod';

const uuidSchema = z.string().uuid();

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const raw = typeof req.query.iocId === 'string' ? req.query.iocId : '';
  const parsed = uuidSchema.safeParse(raw);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid iocId', code: 'VALIDATION_ERROR' });
    return;
  }
  const iocId = parsed.data;

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
