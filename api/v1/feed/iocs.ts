import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../lib/db.js';
import { withHandler } from '../lib/middleware.js';
import { paginationSchema } from '../lib/validate.js';
import { z } from 'zod';

const querySchema = paginationSchema.extend({
  type: z.string().optional(),
  source: z.string().optional(),
  malware: z.string().optional(),
  q: z.string().min(1).max(200).optional(),
  since: z.string().optional(),
  sector: z.string().max(50).optional(),
});

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const parsed = querySchema.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid query parameters', code: 'VALIDATION_ERROR' });
    return;
  }

  const { page, limit, type, source, malware, q, since, order, sector } = parsed.data;
  const offset = (page - 1) * limit;

  const params: unknown[] = [];
  const conditions: string[] = [];

  // Sector filter: show IOCs linked to sector groups OR IOCs with no technique links
  if (sector) {
    params.push(sector);
    conditions.push(`(
      i.id IN (
        SELECT ti2.ioc_id FROM technique_iocs ti2
        JOIN group_techniques gt ON gt.technique_id = ti2.technique_id
        JOIN group_sectors gs ON gs.group_id = gt.group_id
        JOIN sectors s ON s.id = gs.sector_id
        WHERE s.slug = $${params.length}
      )
      OR i.id NOT IN (SELECT ti3.ioc_id FROM technique_iocs ti3)
    )`);
  }

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
  // Default to DESC (latest first) when no explicit order given
  const effectiveOrder = req.query.order ? order : 'desc';
  const sortDir = effectiveOrder === 'asc' ? 'ASC' : 'DESC';

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
    source_ref: string | null;
    created_at: string;
    technique_count: string;
  }>(
    `SELECT i.id, i.type, i.value, i.source, i.malware_family, i.first_seen, i.source_ref, i.created_at,
            COUNT(ti.technique_id) AS technique_count
     FROM ioc_entries i
     LEFT JOIN technique_iocs ti ON ti.ioc_id = i.id
     ${whereClause}
     GROUP BY i.id
     ORDER BY i.first_seen ${sortDir} NULLS LAST
     LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params,
  );

  // Normalize field name for frontend compatibility
  const data = dataResult.rows.map((r) => ({
    ...r,
    first_seen_at: r.first_seen,
    technique_count: parseInt(r.technique_count, 10),
  }));

  res.status(200).json({
    data,
    pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
  });
}

export default withHandler(handler);
