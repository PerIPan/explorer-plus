import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../lib/db.js';
import { withHandler } from '../lib/middleware.js';
import { paginationSchema } from '../lib/validate.js';
import { z } from 'zod';

const querySchema = paginationSchema.extend({
  source: z.string().optional(),
  since: z.string().optional(),
  q: z.string().min(1).max(200).optional(),
  sortBy: z.string().optional(),
  sector: z.string().max(50).optional(),
});

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const parsed = querySchema.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid query parameters', code: 'VALIDATION_ERROR' });
    return;
  }

  const { page, limit, source, since, q, sortBy, order, sector } = parsed.data;
  const offset = (page - 1) * limit;

  const params: unknown[] = [];
  const conditions: string[] = [];

  // Sector filter: show reports linked to sector groups OR reports with no technique links
  if (sector) {
    params.push(sector);
    conditions.push(`(
      r.id IN (
        SELECT rt2.report_id FROM report_techniques rt2
        JOIN group_techniques gt ON gt.technique_id = rt2.technique_id
        JOIN group_sectors gs ON gs.group_id = gt.group_id
        JOIN sectors s ON s.id = gs.sector_id
        WHERE s.slug = $${params.length}
      )
      OR NOT EXISTS (SELECT 1 FROM report_techniques rt3 WHERE rt3.report_id = r.id)
    )`);
  }

  if (source) {
    params.push(source);
    conditions.push(`r.source = $${params.length}`);
  }

  if (since) {
    const d = new Date(since);
    if (!isNaN(d.getTime())) {
      params.push(d.toISOString());
      conditions.push(`r.published_at >= $${params.length}`);
    }
  }

  if (q) {
    params.push(`%${q}%`);
    conditions.push(
      `(r.title ILIKE $${params.length} OR r.summary ILIKE $${params.length})`,
    );
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  const allowedSort: Record<string, string> = {
    title: 'r.title',
    source: 'r.source',
    published_at: 'r.published_at',
    created_at: 'r.created_at',
  };
  const sortCol = allowedSort[sortBy ?? 'published_at'] ?? 'r.published_at';
  // Default to DESC (latest first) when no explicit order given
  const effectiveOrder = req.query.order ? order : 'desc';
  const sortDir = effectiveOrder === 'asc' ? 'ASC' : 'DESC';

  const countResult = await query<{ count: string }>(
    `SELECT COUNT(*) FROM threat_reports r ${whereClause}`,
    params,
  );
  const total = parseInt(countResult.rows[0].count, 10);

  params.push(limit, offset);
  const dataResult = await query<{
    id: string;
    title: string;
    url: string | null;
    source: string | null;
    published_at: string | null;
    created_at: string;
    technique_count: string;
  }>(
    `SELECT
       r.id,
       r.title,
       r.url,
       r.source,
       r.published_at,
       r.created_at,
       COUNT(rt.technique_id) AS technique_count
     FROM threat_reports r
     LEFT JOIN report_techniques rt ON rt.report_id = r.id
     ${whereClause}
     GROUP BY r.id
     ORDER BY ${sortCol} ${sortDir} NULLS LAST
     LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params,
  );

  const data = dataResult.rows.map((r) => ({
    ...r,
    technique_count: parseInt(r.technique_count, 10),
  }));

  res.status(200).json({
    data,
    pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
  });
}

export default withHandler(handler);
