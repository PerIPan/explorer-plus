import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../../../lib/db.js';
import { withHandler } from '../../../lib/middleware.js';
import { z } from 'zod';

const controlIdSchema = z.string().regex(/^[A-Z]{2}-\d{1,3}$/);

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const raw = typeof req.query.controlId === 'string' ? req.query.controlId : '';
  const parsed = controlIdSchema.safeParse(raw);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid controlId', code: 'VALIDATION_ERROR' });
    return;
  }
  const controlId = parsed.data;

  const result = await query<{ attackId: string; name: string }>(
    `SELECT t.attack_id AS "attackId", t.name
     FROM nist_controls nc
     JOIN techniques t ON t.id = nc.technique_id
     WHERE nc.control_id = $1
     ORDER BY t.attack_id ASC`,
    [controlId],
  );

  res.status(200).json({ data: result.rows });
}

export default withHandler(handler, { cacheTtl: 3600 });
