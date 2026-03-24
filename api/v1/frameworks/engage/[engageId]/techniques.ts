import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../../../lib/db.js';
import { withHandler } from '../../../lib/middleware.js';
import { z } from 'zod';

const engageIdSchema = z.string().regex(/^EA[CV]\d{4}$/);

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const raw = typeof req.query.engageId === 'string' ? req.query.engageId : '';
  const parsed = engageIdSchema.safeParse(raw);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid engageId', code: 'VALIDATION_ERROR' });
    return;
  }
  const engageId = parsed.data;

  const result = await query<{ attackId: string; name: string }>(
    `SELECT t.attack_id AS "attackId", t.name
     FROM engage_mappings em
     JOIN techniques t ON t.id = em.technique_id
     WHERE em.engage_id = $1
     ORDER BY t.attack_id ASC`,
    [engageId],
  );

  res.status(200).json({ data: result.rows });
}

export default withHandler(handler, { cacheTtl: 3600 });
