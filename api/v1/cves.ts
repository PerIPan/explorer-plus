import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from './lib/db.js';
import { withHandler } from './lib/middleware.js';
import { paginationSchema } from './lib/validate.js';
import { z } from 'zod';

const querySchema = paginationSchema.extend({
  severity: z.string().optional(),
  source: z.string().optional(),
  q: z.string().min(1).max(200).optional(),
  sector: z.string().max(50).optional(),
});

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const parsed = querySchema.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid query parameters', code: 'VALIDATION_ERROR' });
    return;
  }

  const { page, limit, severity, source, q, order, sector } = parsed.data;
  const offset = (page - 1) * limit;

  // Build base query: distinct CVE IDs from ioc_entries joined with cve_details
  const params: unknown[] = [];
  const conditions: string[] = ["i.type = 'cve'"];

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
      OR NOT EXISTS (SELECT 1 FROM technique_iocs ti3 WHERE ti3.ioc_id = i.id)
    )`);
  }

  if (severity) {
    params.push(severity.toUpperCase());
    conditions.push(`cd.cvss_severity = $${params.length}`);
  }

  if (source) {
    params.push(source);
    conditions.push(`i.source = $${params.length}`);
  }

  if (q) {
    params.push(`%${q}%`);
    conditions.push(
      `(i.value ILIKE $${params.length} OR cd.description ILIKE $${params.length} OR cd.cwe_id ILIKE $${params.length})`,
    );
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const effectiveOrder = req.query.order ? order : 'desc';
  const sortDir = effectiveOrder === 'asc' ? 'ASC' : 'DESC';

  // Count distinct CVEs
  const countResult = await query<{ count: string }>(
    `SELECT COUNT(DISTINCT i.value) FROM ioc_entries i
     LEFT JOIN cve_details cd ON cd.cve_id = i.value
     ${whereClause}`,
    params,
  );
  const total = parseInt(countResult.rows[0].count, 10);

  // Fetch CVE list with aggregated sources and technique count
  params.push(limit, offset);
  const dataResult = await query<{
    cve_id: string;
    description: string | null;
    cvss_score: string | null;
    cvss_severity: string | null;
    cwe_id: string | null;
    published_at: string | null;
    sources: string;
    technique_count: string;
  }>(
    `SELECT
       i_agg.cve_id,
       cd.description,
       cd.cvss_score,
       cd.cvss_severity,
       cd.cwe_id,
       cd.published_at,
       i_agg.sources,
       i_agg.technique_count
     FROM (
       SELECT
         i.value AS cve_id,
         STRING_AGG(DISTINCT i.source, ',') AS sources,
         COUNT(DISTINCT ti.technique_id) AS technique_count
       FROM ioc_entries i
       LEFT JOIN technique_iocs ti ON ti.ioc_id = i.id
       LEFT JOIN cve_details cd ON cd.cve_id = i.value
       ${whereClause}
       GROUP BY i.value
     ) i_agg
     LEFT JOIN cve_details cd ON cd.cve_id = i_agg.cve_id
     ORDER BY cd.cvss_score ${sortDir} NULLS LAST, i_agg.cve_id ASC
     LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params,
  );

  const data = dataResult.rows.map((r) => ({
    cveId: r.cve_id,
    description: r.description,
    cvssScore: r.cvss_score ? parseFloat(r.cvss_score) : null,
    cvssSeverity: r.cvss_severity,
    cweId: r.cwe_id,
    publishedAt: r.published_at,
    sources: r.sources ? r.sources.split(',') : [],
    techniqueCount: parseInt(r.technique_count, 10),
  }));

  res.status(200).json({
    data,
    pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
  });
}

export default withHandler(handler, { cacheTtl: 300 });
