import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../_lib/db.js';
import { withHandler } from '../_lib/middleware.js';
import { paginationSchema } from '../_lib/validate.js';
import { z } from 'zod';

const querySchema = paginationSchema.extend({
  type: z.string().optional(),
  source: z.string().optional(),
  malware: z.string().optional(),
  q: z.string().min(1).max(200).optional(),
  since: z.string().optional(),
});

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const parsed = querySchema.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid query parameters', code: 'VALIDATION_ERROR' });
    return;
  }

  const { page, limit, type, source, malware, q, since, order } = parsed.data;
  const offset = (page - 1) * limit;

  const params: unknown[] = [];
  const conditions: string[] = [];

  if (type) {
    params.push(type);
    conditions.push(`i.type = $${params.length}`);
  }

  if (source) {
    params.push(source);
    conditions.push(`i.source = $${params.length}`);
  }

  if (malware) {
    params.push(`%${malware}%`);
    conditions.push(`i.malware_family ILIKE $${params.length}`);
  }

  if (q) {
    params.push(`%${q}%`);
    conditions.push(
      `(i.value ILIKE $${params.length} OR i.malware_family ILIKE $${params.length})`,
    );
  }

  if (since) {
    const d = new Date(since);
    if (!isNaN(d.getTime())) {
      params.push(d.toISOString());
      conditions.push(`i.first_seen >= $${params.length}`);
    }
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const sortDir = order === 'asc' ? 'ASC' : 'DESC';

  const countResult = await query<{ count: string }>(
    `SELECT COUNT(*) FROM ioc_entries i ${whereClause}`,
    params,
  );
  const total = parseInt(countResult.rows[0].count, 10);

  params.push(limit, offset);
  const dataResult = await query<{
    id: string;
    type: string;
    value: string;
    source: string | null;
    malware_family: string | null;
    first_seen: string | null;
    created_at: string;
  }>(
    `SELECT i.id, i.type, i.value, i.source, i.malware_family, i.first_seen, i.created_at
     FROM ioc_entries i
     ${whereClause}
     ORDER BY i.first_seen ${sortDir} NULLS LAST
     LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params,
  );

  // Normalize field name for frontend compatibility
  const data = dataResult.rows.map((r) => ({
    ...r,
    first_seen_at: r.first_seen,
  }));

  res.status(200).json({
    data,
    pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
  });
}

export default withHandler(handler);
