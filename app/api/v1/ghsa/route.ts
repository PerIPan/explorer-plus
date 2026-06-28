import { NextRequest } from 'next/server';
import { query } from '../lib/db';
import { jsonResponse, errorResponse } from '../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../lib/cors';
import { paginationSchema } from '../lib/validate';
import { escapeLikePattern } from '../lib/queries';
import { notCatchallCwe, liveTechnique } from '../lib/inference';
import { z } from 'zod';

export { OPTIONS };

const ECOSYSTEM_RE = /^[a-z][a-z0-9-]{1,49}$/;

const querySchema = paginationSchema.extend({
  severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']).optional(),
  ecosystem: z.string().regex(ECOSYSTEM_RE).optional(),
  since: z.string().optional(),
  q: z.string().min(3).max(200).optional(),       // min 3 to avoid short-query seq-scan DoS on description
  has_cve: z.enum(['true', 'false']).optional(),
  package: z.string().min(3).max(200).optional(), // min 3 for same reason
  include_withdrawn: z.enum(['true', 'false', '0', '1']).optional(),
});

export async function GET(req: NextRequest) {
  const rawParams: Record<string, string> = {};
  req.nextUrl.searchParams.forEach((v, k) => { rawParams[k] = v; });

  const parsed = querySchema.safeParse(rawParams);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Invalid query parameters', 'VALIDATION_ERROR'));
  }

  const { page, limit, severity, ecosystem, since, q, order } = parsed.data;
  const hasCve = parsed.data.has_cve;
  const pkg = parsed.data.package;
  const includeWithdrawn =
    parsed.data.include_withdrawn === 'true' || parsed.data.include_withdrawn === '1';

  const offset = (page - 1) * limit;
  const params: unknown[] = [];
  const conditions: string[] = [];

  if (!includeWithdrawn) {
    conditions.push(`g.withdrawn_at IS NULL`);
  }

  if (severity) {
    params.push(severity.toUpperCase());
    conditions.push(`g.severity = $${params.length}`);
  }

  if (hasCve === 'true') conditions.push(`g.cve_id IS NOT NULL`);
  if (hasCve === 'false') conditions.push(`g.cve_id IS NULL`);

  if (since) {
    const d = new Date(since);
    if (!isNaN(d.getTime())) {
      params.push(d.toISOString());
      conditions.push(`g.published_at >= $${params.length}`);
    }
  }

  if (q) {
    params.push(`%${escapeLikePattern(q)}%`);
    conditions.push(
      `(g.ghsa_id ILIKE $${params.length} OR g.cve_id ILIKE $${params.length} OR g.summary ILIKE $${params.length} OR g.description ILIKE $${params.length})`,
    );
  }

  if (ecosystem) {
    params.push(ecosystem.toLowerCase());
    conditions.push(`g.ghsa_id IN (
      SELECT gp.ghsa_id FROM ghsa_packages gp
      JOIN packages p ON p.id = gp.package_id
      WHERE p.ecosystem = $${params.length}
    )`);
  }

  if (pkg) {
    params.push(`%${escapeLikePattern(pkg)}%`);
    conditions.push(`g.ghsa_id IN (
      SELECT gp.ghsa_id FROM ghsa_packages gp
      JOIN packages p ON p.id = gp.package_id
      WHERE p.package_name ILIKE $${params.length}
    )`);
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const sortDir = order === 'asc' ? 'ASC' : 'DESC';

  // Count
  const countResult = await query<{ count: string }>(
    `SELECT COUNT(*) FROM ghsa_advisories g ${whereClause}`,
    params,
  );
  const total = parseInt(countResult.rows[0].count, 10);

  params.push(limit, offset);
  const rows = await query<{
    ghsa_id: string;
    cve_id: string | null;
    summary: string | null;
    severity: string | null;
    cvss_score: string | null;
    published_at: string;
    withdrawn_at: string | null;
    package_count: string;
    ecosystems: string[] | null;
    technique_count: string;
  }>(
    `WITH page AS (
       SELECT g.ghsa_id, g.cve_id, g.summary, g.severity, g.cvss_score, g.published_at, g.withdrawn_at
       FROM ghsa_advisories g
       ${whereClause}
       ORDER BY g.published_at ${sortDir} NULLS LAST, g.ghsa_id DESC
       LIMIT $${params.length - 1} OFFSET $${params.length}
     ),
     pkg AS (
       SELECT gp.ghsa_id,
              COUNT(DISTINCT gp.package_id) AS package_count,
              ARRAY_AGG(DISTINCT p.ecosystem) AS ecosystems
       FROM ghsa_packages gp
       JOIN packages p ON p.id = gp.package_id
       WHERE gp.ghsa_id IN (SELECT ghsa_id FROM page)
       GROUP BY gp.ghsa_id
     ),
     tech AS (
       SELECT w.ghsa_id, COUNT(DISTINCT cm.technique_id) AS technique_count
       FROM ghsa_weaknesses w
       JOIN capec_mappings cm ON cm.cwe_id = w.cwe_id AND cm.technique_id IS NOT NULL AND ${notCatchallCwe('cm.cwe_id')}
       JOIN techniques t ON t.id = cm.technique_id AND ${liveTechnique('t')}
       WHERE w.ghsa_id IN (SELECT ghsa_id FROM page)
       GROUP BY w.ghsa_id
     )
     SELECT p.*,
            COALESCE(pk.package_count, 0)::text AS package_count,
            pk.ecosystems,
            COALESCE(t.technique_count, 0)::text AS technique_count
     FROM page p
     LEFT JOIN pkg pk ON pk.ghsa_id = p.ghsa_id
     LEFT JOIN tech t ON t.ghsa_id = p.ghsa_id
     ORDER BY p.published_at ${sortDir} NULLS LAST, p.ghsa_id DESC`,
    params,
  );

  const data = rows.rows.map((r) => ({
    ghsaId: r.ghsa_id,
    cveId: r.cve_id,
    summary: r.summary,
    severity: r.severity,
    cvssScore: r.cvss_score ? parseFloat(r.cvss_score) : null,
    publishedAt: r.published_at,
    withdrawnAt: r.withdrawn_at,
    packageCount: parseInt(r.package_count, 10),
    ecosystems: r.ecosystems ?? [],
    techniqueCount: parseInt(r.technique_count, 10),
  }));

  return withCors(jsonResponse({
    data,
    pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
  }, 1800));
}
