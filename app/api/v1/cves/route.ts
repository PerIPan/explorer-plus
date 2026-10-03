import { NextRequest } from 'next/server';
import { query } from '../lib/db';
import { jsonResponse, errorResponse } from '../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../lib/cors';
import { paginationSchema, versionParam, sinceToIso } from '../lib/validate';
import { escapeLikePattern } from '../lib/queries';
import { notCatchallCwe, liveTechnique } from '../lib/inference';
import { z } from 'zod';

export { OPTIONS };

const querySchema = paginationSchema.extend({
  severity: z.string().optional(),
  source: z.string().optional(),
  q: z.string().min(1).max(200).optional(),
  sector: z.string().max(50).optional(),
  since: z.string().optional(),
  technique: z.string().regex(/^(AML\.)?(T|TA)\d{4}(\.\d{3})?$/).optional(),
  // "Only CVEs an analyst hand-mapped to a technique", not the CWE inference.
  curated: z.enum(['1', 'true']).optional(),
  app: z.string().min(1).max(200).optional(),
  // Substring/text match against affected_products.version_start/version_end.
  // Only meaningful with `app` (product context) — versions aren't globally
  // comparable. NOT a semantic "is this version vulnerable" verdict.
  version: versionParam,
});

export async function GET(req: NextRequest) {
  const rawParams: Record<string, string> = {};
  req.nextUrl.searchParams.forEach((v, k) => { rawParams[k] = v; });

  const parsed = querySchema.safeParse(rawParams);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Invalid query parameters', 'VALIDATION_ERROR'));
  }

  const { page, limit, severity, source, q, order, sector, since, technique, app, version, curated } = parsed.data;
  const curatedOnly = curated === '1' || curated === 'true';
  const offset = (page - 1) * limit;

  // version filtering only makes sense scoped to a product (versions aren't
  // globally comparable). Reject a bare ?version= with a clear message.
  if (version && !app) {
    return withCors(errorResponse(400, 'The `version` filter requires `app` (product context), e.g. ?app=nginx&version=1.20', 'MISSING_CONTEXT'));
  }

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

  const sinceIso = sinceToIso(since);
  if (sinceIso) {
    params.push(sinceIso);
    conditions.push(`cd.published_at >= $${params.length}`);
  }

  if (technique) {
    params.push(technique);
    /*
     * CURATED: the CTID / CISA hand-mapped CVE->technique edges only, which is
     * a DIFFERENT and much smaller relation than the two inference arms below.
     *
     * It exists because the compliance page's heat badges count exactly this
     * (`capec_id = 'CTID-DIRECT'`) and say so — "not CWE inference" — while the
     * default list here counts the inference union. Linking one to the other
     * without this filter lands a badge reading 62 on a page reading 636
     * (T1078, measured). Verified to reproduce the badge exactly: T1190 199,
     * T1059 134, T1078 62, T1195.002 0.
     *
     * Joined on `attack_technique_id`, and with NO liveness predicate, because
     * scripts/refresh-cti-heat.mjs does neither — parity with the number being
     * clicked is the whole point, so this mirrors that query rather than the
     * house style below.
     */
    if (curatedOnly) {
      conditions.push(`cd.cve_id IN (
        SELECT cw.cve_id FROM cve_weaknesses cw
        JOIN capec_mappings cm ON cm.cwe_id = cw.cwe_id
             AND cm.capec_id = 'CTID-DIRECT'
             AND cm.attack_technique_id = $${params.length}
      )`);
    } else {
    // `liveTechnique` on BOTH arms. It was on the weakness arm only, so asking
    // for a revoked technique returned its IOC-linked CVEs and none of its
    // CWE-linked ones — a half-answer that depended on which arm happened to
    // carry the data. Same spelling on both sides now, via the helper rather
    // than a hand-written predicate.
    conditions.push(`cd.cve_id IN (
      SELECT cw.cve_id FROM cve_weaknesses cw
      JOIN capec_mappings cm ON cm.cwe_id = cw.cwe_id AND ${notCatchallCwe('cm.cwe_id')}
      JOIN techniques t ON t.id = cm.technique_id AND t.attack_id = $${params.length} AND ${liveTechnique('t')}
      UNION
      SELECT i.value FROM ioc_entries i
      JOIN technique_iocs ti ON ti.ioc_id = i.id
      JOIN techniques t ON t.id = ti.technique_id AND t.attack_id = $${params.length} AND ${liveTechnique('t')}
      WHERE i.type = 'cve'
    )`);
    }
  }

  /*
   * `curated` WITHOUT `technique`: every CVE carrying any hand-mapped technique
   * edge, rather than any one technique's. Useful on its own as "the analyst-
   * confirmed corpus", and it keeps the checkbox meaningful when the technique
   * box is empty instead of silently doing nothing.
   */
  if (curatedOnly && !technique) {
    conditions.push(`EXISTS (
      SELECT 1 FROM cve_weaknesses cw
      JOIN capec_mappings cm ON cm.cwe_id = cw.cwe_id AND cm.capec_id = 'CTID-DIRECT'
      WHERE cw.cve_id = cd.cve_id
    )`);
  }

  if (app) {
    params.push(`%${escapeLikePattern(app)}%`);
    const appIdx = params.length;
    let versionClause = '';
    if (version) {
      params.push(`%${escapeLikePattern(version)}%`);
      versionClause = ` AND (ap.version_start ILIKE $${params.length} OR ap.version_end ILIKE $${params.length})`;
    }
    conditions.push(`cd.cve_id IN (
      SELECT ap.cve_id FROM affected_products ap
      JOIN applications a ON a.id = ap.application_id
      WHERE (a.vendor ILIKE $${appIdx} OR a.product ILIKE $${appIdx})${versionClause}
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
         JOIN techniques t ON t.id = ti.technique_id AND ${liveTechnique('t')}
         WHERE i.type = 'cve' AND i.value IN (SELECT cve_id FROM page)
         UNION
         SELECT cw.cve_id, cm.technique_id, t.attack_id
         FROM cve_weaknesses cw JOIN capec_mappings cm ON cm.cwe_id = cw.cwe_id AND cm.technique_id IS NOT NULL AND ${notCatchallCwe('cm.cwe_id')}
         JOIN techniques t ON t.id = cm.technique_id AND ${liveTechnique('t')}
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
    versionFilter: version ?? null,
    pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
  }, 3600));
}
