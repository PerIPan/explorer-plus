import { NextRequest } from 'next/server';
import { query } from '../lib/db';
import { jsonResponse, errorResponse } from '../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../lib/cors';
import { paginationSchema } from '../lib/validate';
import { escapeLikePattern } from '../lib/queries';
import { z } from 'zod';

export { OPTIONS };

const querySchema = paginationSchema.extend({
  severity: z.string().optional(),
  source: z.string().optional(),
  q: z.string().min(1).max(200).optional(),
  sector: z.string().max(50).optional(),
  since: z.string().optional(),
  technique: z.string().regex(/^(AML\.)?(T|TA)\d{4}(\.\d{3})?$/).optional(),
  app: z.string().min(1).max(200).optional(),
});

export async function GET(req: NextRequest) {
  const rawParams: Record<string, string> = {};
  req.nextUrl.searchParams.forEach((v, k) => { rawParams[k] = v; });

  const parsed = querySchema.safeParse(rawParams);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Invalid query parameters', 'VALIDATION_ERROR'));
  }

  const { page, limit, severity, source, q, order, sector, since, technique, app } = parsed.data;
  const offset = (page - 1) * limit;

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

  if (technique) {
    params.push(technique);
    conditions.push(`cd.cve_id IN (
      SELECT cw.cve_id FROM cve_weaknesses cw
      JOIN capec_mappings cm ON cm.cwe_id = cw.cwe_id
      JOIN techniques t ON t.id = cm.technique_id AND t.attack_id = $${params.length}
      UNION
      SELECT i.value FROM ioc_entries i
      JOIN technique_iocs ti ON ti.ioc_id = i.id
      JOIN techniques t ON t.id = ti.technique_id AND t.attack_id = $${params.length}
      WHERE i.type = 'cve'
    )`);
  }

  if (app) {
    params.push(`%${escapeLikePattern(app)}%`);
    conditions.push(`cd.cve_id IN (
      SELECT ap.cve_id FROM affected_products ap
      JOIN applications a ON a.id = ap.application_id
      WHERE a.vendor ILIKE $${params.length} OR a.product ILIKE $${params.length}
    )`);
  }

  if (sector) {
    params.push(sector);
    conditions.push(`cd.cve_id IN (
      SELECT ap.cve_id FROM affected_products ap
      JOIN app_technique_groups atg ON atg.application_id = ap.application_id
      JOIN threat_groups tg ON tg.attack_id = atg.group_attack_id
      JOIN group_sectors gs ON gs.group_id = tg.id
      JOIN sectors s ON s.id = gs.sector_id
      WHERE s.slug = $${params.length}
    )`);
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const effectiveOrder = rawParams.order ? order : 'desc';
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
    cvss_vector: string | null;
    cwe_id: string | null;
    published_at: string | null;
    epss_score: string | null;
    epss_percentile: string | null;
    sources: string | null;
    technique_count: string;
    technique_ids: string | null;
    app_names: string | null;
  }>(
    `WITH page AS (
       SELECT cd.cve_id, cd.description, cd.cvss_score, cd.cvss_severity, cd.cvss_vector,
              cd.cwe_id, cd.published_at, cd.epss_score, cd.epss_percentile
       FROM cve_details cd
       ${whereClause}
       ORDER BY cd.published_at ${sortDir} NULLS LAST, cd.cve_id DESC
       LIMIT $${params.length - 1} OFFSET $${params.length}
     ),
     src AS (
       SELECT i.value AS cve_id, STRING_AGG(DISTINCT i.source, ',') AS sources
       FROM ioc_entries i
       WHERE i.type = 'cve' AND i.value IN (SELECT cve_id FROM page)
       GROUP BY i.value
     ),
     tech AS (
       SELECT cve_id,
         COUNT(DISTINCT technique_id)::text AS technique_count,
         STRING_AGG(DISTINCT attack_id, ',' ORDER BY attack_id) AS technique_ids
       FROM (
         SELECT i.value AS cve_id, ti.technique_id, t.attack_id
         FROM ioc_entries i JOIN technique_iocs ti ON ti.ioc_id = i.id
         JOIN techniques t ON t.id = ti.technique_id
         WHERE i.type = 'cve' AND i.value IN (SELECT cve_id FROM page)
         UNION
         SELECT cw.cve_id, cm.technique_id, t.attack_id
         FROM cve_weaknesses cw JOIN capec_mappings cm ON cm.cwe_id = cw.cwe_id AND cm.technique_id IS NOT NULL
         JOIN techniques t ON t.id = cm.technique_id
         WHERE cw.cve_id IN (SELECT cve_id FROM page)
       ) sub GROUP BY cve_id
     ),
     apps AS (
       SELECT ap.cve_id, STRING_AGG(DISTINCT a.vendor || ' ' || a.product, ' | ' ORDER BY a.vendor || ' ' || a.product) AS app_names
       FROM affected_products ap
       JOIN applications a ON a.id = ap.application_id
       WHERE ap.cve_id IN (SELECT cve_id FROM page)
       GROUP BY ap.cve_id
     )
     SELECT p.*, s.sources, COALESCE(t.technique_count, '0') AS technique_count,
            t.technique_ids, a.app_names
     FROM page p
     LEFT JOIN src s ON s.cve_id = p.cve_id
     LEFT JOIN tech t ON t.cve_id = p.cve_id
     LEFT JOIN apps a ON a.cve_id = p.cve_id
     ORDER BY p.published_at ${sortDir} NULLS LAST, p.cve_id DESC`,
    params,
  );

  const data = dataResult.rows.map((r) => ({
    cveId: r.cve_id,
    description: r.description,
    cvssScore: r.cvss_score ? parseFloat(r.cvss_score) : null,
    cvssSeverity: r.cvss_severity,
    cvssVector: r.cvss_vector,
    cweId: r.cwe_id,
    publishedAt: r.published_at,
    epssScore: r.epss_score ? parseFloat(r.epss_score) : null,
    epssPercentile: r.epss_percentile ? parseFloat(r.epss_percentile) : null,
    sources: r.sources ? r.sources.split(',') : [],
    techniqueCount: parseInt(r.technique_count, 10),
    techniques: r.technique_ids ? r.technique_ids.split(',') : [],
    applications: r.app_names ?? '',
  }));

  return withCors(jsonResponse({
    data,
    pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
  }, 3600));
}
