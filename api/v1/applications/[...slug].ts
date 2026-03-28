import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../lib/db.js';
import { withHandler } from '../lib/middleware.js';
import { z } from 'zod';

const slugSchema = z.string().min(1).max(200).regex(/^[a-z0-9/]+$/);

const querySchema = z.object({
  page: z.coerce.number().int().positive().max(1000).default(1),
  limit: z.coerce.number().int().positive().max(100).default(20),
});

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const slugParsed = slugSchema.safeParse(
    Array.isArray(req.query.slug) ? req.query.slug.join('/') : req.query.slug,
  );
  if (!slugParsed.success) {
    res.status(400).json({ error: 'Invalid slug', code: 'VALIDATION_ERROR' });
    return;
  }
  const slug = slugParsed.data;
  const parsed = querySchema.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid query params', code: 'VALIDATION_ERROR' });
    return;
  }
  const { page, limit } = parsed.data;
  const offset = (page - 1) * limit;

  // Find application
  const appResult = await query<{
    id: string; vendor: string; product: string; normalized: string;
    cpePrefix: string | null; cveCount: number;
  }>(
    `SELECT id, vendor, product, normalized, cpe_prefix AS "cpePrefix", cve_count AS "cveCount"
     FROM applications WHERE normalized = $1`,
    [slug],
  );

  if (appResult.rows.length === 0) {
    res.status(404).json({ error: 'Application not found', code: 'NOT_FOUND' });
    return;
  }
  const app = appResult.rows[0];

  // Parallel queries for the 360 view
  const [cvesResult, techniquesResult, groupsResult, weaknessesResult, cveCountResult] = await Promise.all([
    // CVEs paginated by CVSS
    query<{
      cveId: string; description: string | null;
      cvssScore: number | null; cvssSeverity: string | null;
      publishedAt: string | null; isKev: boolean;
    }>(
      `SELECT cd.cve_id AS "cveId", cd.description,
              cd.cvss_score AS "cvssScore", cd.cvss_severity AS "cvssSeverity",
              cd.published_at AS "publishedAt", cd.is_kev AS "isKev"
       FROM affected_products ap
       JOIN cve_details cd ON cd.cve_id = ap.cve_id
       WHERE ap.application_id = $1
       ORDER BY cd.cvss_score DESC NULLS LAST, cd.published_at DESC NULLS LAST
       LIMIT $2 OFFSET $3`,
      [app.id, limit, offset],
    ),

    // Techniques from materialized view (distinct)
    query<{ attackId: string; name: string; groupCount: string }>(
      `SELECT attack_technique_id AS "attackId", technique_name AS "name",
              COUNT(DISTINCT group_attack_id)::text AS "groupCount"
       FROM app_technique_groups
       WHERE application_id = $1
       GROUP BY attack_technique_id, technique_name
       ORDER BY COUNT(DISTINCT group_attack_id) DESC, technique_name ASC`,
      [app.id],
    ),

    // Groups from materialized view (distinct)
    query<{ attackId: string; name: string; techniqueCount: string }>(
      `SELECT group_attack_id AS "attackId", group_name AS "name",
              COUNT(DISTINCT attack_technique_id)::text AS "techniqueCount"
       FROM app_technique_groups
       WHERE application_id = $1
       GROUP BY group_attack_id, group_name
       ORDER BY COUNT(DISTINCT attack_technique_id) DESC, group_name ASC`,
      [app.id],
    ),

    // CWE distribution
    query<{ cweId: string; count: string }>(
      `SELECT cw.cwe_id AS "cweId", COUNT(DISTINCT cw.cve_id)::text AS "count"
       FROM affected_products ap
       JOIN cve_weaknesses cw ON cw.cve_id = ap.cve_id
       WHERE ap.application_id = $1
       GROUP BY cw.cwe_id
       ORDER BY COUNT(DISTINCT cw.cve_id) DESC
       LIMIT 20`,
      [app.id],
    ),

    // Total CVE count for pagination
    query<{ total: string }>(
      `SELECT COUNT(DISTINCT ap.cve_id)::text AS total
       FROM affected_products ap WHERE ap.application_id = $1`,
      [app.id],
    ),
  ]);

  res.status(200).json({
    ...app,
    cves: cvesResult.rows,
    cvePagination: {
      page, limit,
      total: parseInt(cveCountResult.rows[0].total, 10),
      totalPages: Math.ceil(parseInt(cveCountResult.rows[0].total, 10) / limit),
    },
    techniques: techniquesResult.rows.map((r) => ({
      ...r, groupCount: parseInt(r.groupCount, 10),
    })),
    groups: groupsResult.rows.map((r) => ({
      ...r, techniqueCount: parseInt(r.techniqueCount, 10),
    })),
    weaknesses: weaknessesResult.rows.map((r) => ({
      ...r, count: parseInt(r.count, 10),
    })),
  });
}

export default withHandler(handler, { cacheTtl: 3600 });
