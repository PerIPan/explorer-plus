import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from './lib/db.js';
import { withHandler } from './lib/middleware.js';
import { paginationSchema } from './lib/validate.js';
import { escapeLikePattern } from './lib/queries.js';
import { z } from 'zod';

const querySchema = paginationSchema.extend({
  severity: z.string().optional(),
  source: z.string().optional(),
  q: z.string().min(1).max(200).optional(),
  sector: z.string().max(50).optional(),
  since: z.string().optional(),
});

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const parsed = querySchema.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid query parameters', code: 'VALIDATION_ERROR' });
    return;
  }

  const { page, limit, severity, source, q, order, sector, since } = parsed.data;
  const offset = (page - 1) * limit;

  // Primary source: cve_details (CVElistV5 + NVD + CISA KEV)
  // Secondary: ioc_entries for source badges and technique links
  const params: unknown[] = [];
  const conditions: string[] = [];

  if (severity) {
    params.push(severity.toUpperCase());
    conditions.push(`cd.cvss_severity = $${params.length}`);
  }

  if (source) {
    params.push(source);
    conditions.push(`EXISTS (SELECT 1 FROM ioc_entries i WHERE i.type = 'cve' AND i.value = cd.cve_id AND i.source = $${params.length})`);
  }

  if (q) {
    params.push(`%${escapeLikePattern(q)}%`);
    conditions.push(
      `(cd.cve_id ILIKE $${params.length} OR cd.description ILIKE $${params.length} OR cd.cwe_id ILIKE $${params.length})`,
    );
  }

  if (since) {
    const d = new Date(since);
    if (!isNaN(d.getTime())) {
      params.push(d.toISOString());
      conditions.push(`cd.published_at >= $${params.length}`);
    }
  }

  if (sector) {
    params.push(sector);
    conditions.push(`EXISTS (
      SELECT 1 FROM affected_products ap
      JOIN app_technique_groups atg ON atg.application_id = ap.application_id
      JOIN group_sectors gs ON gs.group_id = (
        SELECT tg.id FROM threat_groups tg WHERE tg.attack_id = atg.group_attack_id LIMIT 1
      )
      JOIN sectors s ON s.id = gs.sector_id
      WHERE ap.cve_id = cd.cve_id AND s.slug = $${params.length}
    )`);
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const effectiveOrder = req.query.order ? order : 'desc';
  const sortDir = effectiveOrder === 'asc' ? 'ASC' : 'DESC';

  // Count
  const countResult = await query<{ count: string }>(
    `SELECT COUNT(*) FROM cve_details cd ${whereClause}`,
    params,
  );
  const total = parseInt(countResult.rows[0].count, 10);

  // Fetch with sources + technique count from ioc_entries path
  params.push(limit, offset);
  const dataResult = await query<{
    cve_id: string;
    description: string | null;
    cvss_score: string | null;
    cvss_severity: string | null;
    cwe_id: string | null;
    published_at: string | null;
    sources: string | null;
    technique_count: string;
  }>(
    `SELECT
       cd.cve_id,
       cd.description,
       cd.cvss_score,
       cd.cvss_severity,
       cd.cwe_id,
       cd.published_at,
       (SELECT STRING_AGG(DISTINCT i.source, ',')
        FROM ioc_entries i WHERE i.type = 'cve' AND i.value = cd.cve_id) AS sources,
       (SELECT COUNT(DISTINCT t_id) FROM (
          SELECT ti.technique_id AS t_id
          FROM ioc_entries i JOIN technique_iocs ti ON ti.ioc_id = i.id
          WHERE i.type = 'cve' AND i.value = cd.cve_id
          UNION
          SELECT cm.technique_id
          FROM cve_weaknesses cw JOIN capec_mappings cm ON cm.cwe_id = cw.cwe_id AND cm.technique_id IS NOT NULL
          WHERE cw.cve_id = cd.cve_id
        ) sub)::text AS technique_count
     FROM cve_details cd
     ${whereClause}
     ORDER BY cd.published_at ${sortDir} NULLS LAST, cd.cve_id DESC
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
