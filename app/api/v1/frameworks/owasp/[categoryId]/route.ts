import { NextRequest } from 'next/server';
import { query } from '../../../lib/db';
import { jsonResponse, errorResponse } from '../../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../../lib/cors';
import { notCatchallCwe, liveTechnique } from '../../../lib/inference';

export { OPTIONS };

/**
 * OWASP Top 10 category detail — CWEs, linked techniques, top CVEs, affected apps.
 */
export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ categoryId: string }> }
) {
  const { categoryId: raw } = await params;
  const categoryId = raw.toUpperCase();

  if (!/^(A|ML|LLM)\d{2}$/i.test(categoryId)) {
    return withCors(errorResponse(400, 'Invalid category ID', 'VALIDATION_ERROR'));
  }

  const catResult = await query<{
    category_id: string; name: string; description: string | null;
    url: string | null; cwe_ids: string[]; framework: string;
    atlas_technique_ids: string[]; is_draft: boolean;
  }>(
    `SELECT category_id, name, description, url, cwe_ids, framework, atlas_technique_ids, is_draft
     FROM owasp_top10
     WHERE UPPER(category_id) = $1
     ORDER BY framework
     LIMIT 1`,
    [categoryId],
  );

  if (catResult.rows.length === 0) {
    return withCors(errorResponse(404, 'Category not found', 'NOT_FOUND'));
  }

  const cat = catResult.rows[0];

  const [techniquesResult, cvesResult, appsResult, atlasResult, relatedResult] = await Promise.all([
    // Techniques via CAPEC bridge
    query<{ attackId: string; name: string; cweId: string }>(
      `SELECT DISTINCT cm.attack_technique_id AS "attackId", t.name, cm.cwe_id AS "cweId"
       FROM capec_mappings cm
       JOIN techniques t ON t.id = cm.technique_id AND ${liveTechnique('t')}
       WHERE cm.technique_id IS NOT NULL AND cm.cwe_id = ANY($1::text[]) AND ${notCatchallCwe('cm.cwe_id')}
       ORDER BY cm.attack_technique_id`,
      [cat.cwe_ids],
    ),

    // Top CVEs by severity
    query<{
      cveId: string; description: string | null;
      cvssScore: number | null; cvssSeverity: string | null;
      publishedAt: string | null; isKev: boolean;
    }>(
      `SELECT cd.cve_id AS "cveId", cd.description,
              cd.cvss_score AS "cvssScore", cd.cvss_severity AS "cvssSeverity",
              cd.published_at AS "publishedAt", COALESCE(cd.is_kev, false) AS "isKev"
       FROM cve_details cd
       JOIN cve_weaknesses cw ON cw.cve_id = cd.cve_id
       WHERE cw.cwe_id = ANY($1::text[])
       ORDER BY cd.cvss_score DESC NULLS LAST, cd.published_at DESC NULLS LAST
       LIMIT 20`,
      [cat.cwe_ids],
    ),

    // Affected applications
    query<{ normalized: string; vendor: string; product: string; cveCount: string }>(
      `SELECT a.normalized, a.vendor, a.product, a.cve_count::text AS "cveCount"
       FROM applications a
       WHERE a.id IN (
         SELECT DISTINCT ap.application_id
         FROM affected_products ap
         JOIN cve_weaknesses cw ON cw.cve_id = ap.cve_id
         WHERE cw.cwe_id = ANY($1::text[])
       )
       ORDER BY a.cve_count DESC
       LIMIT 50`,
      [cat.cwe_ids],
    ),

    // ATLAS techniques
    query<{ attackId: string; name: string }>(
      `SELECT attack_id AS "attackId", name
       FROM techniques
       WHERE attack_id = ANY($1::text[]) AND domain = 'atlas-attack'
       ORDER BY attack_id`,
      [cat.atlas_technique_ids],
    ),

    // Related categories across frameworks sharing CWEs or ATLAS techniques
    query<{ categoryId: string; name: string; framework: string }>(
      `SELECT category_id AS "categoryId", name, framework
       FROM owasp_top10
       WHERE category_id != $1 AND framework != $2
         AND (cwe_ids && $3::text[] OR atlas_technique_ids && $4::text[])
       ORDER BY framework, category_id`,
      [categoryId, cat.framework, cat.cwe_ids, cat.atlas_technique_ids],
    ),
  ]);

  // Group techniques by CWE for the response
  const techniques = techniquesResult.rows.map((r) => ({
    attackId: r.attackId,
    name: r.name,
    cweId: r.cweId,
  }));

  return withCors(jsonResponse({
    categoryId: cat.category_id,
    name: cat.name,
    description: cat.description,
    url: cat.url,
    framework: cat.framework,
    isDraft: cat.is_draft,
    cwes: cat.cwe_ids,
    techniques,
    atlasTechniques: atlasResult.rows,
    cves: cvesResult.rows,
    applications: appsResult.rows.map((r) => ({ ...r, cveCount: parseInt(r.cveCount, 10) })),
    relatedCategories: relatedResult.rows,
  }, 3600));
}
