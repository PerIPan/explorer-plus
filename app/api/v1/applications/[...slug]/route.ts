import { NextRequest } from 'next/server';
import { query } from '../../lib/db';
import { jsonResponse, errorResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';
import { escapeLikePattern } from '../../lib/queries';
import { z } from 'zod';

export { OPTIONS };

const slugSchema = z.string().min(1).max(200).regex(/^[a-z0-9/]+$/);

const querySchema = z.object({
  page: z.coerce.number().int().positive().max(1000).default(1),
  limit: z.coerce.number().int().positive().max(100).default(20),
  // Substring/text match against affected_products version_start/version_end.
  // The product is the context; narrows the returned CVE list + count only.
  version: z.string().min(1).max(100).optional(),
});

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ slug: string[] }> }
) {
  const { slug: slugParts } = await params;
  const rawSlug = slugParts.join('/');

  const slugParsed = slugSchema.safeParse(rawSlug);
  if (!slugParsed.success) {
    return withCors(errorResponse(400, 'Invalid slug', 'VALIDATION_ERROR'));
  }
  const slug = slugParsed.data;

  const rawParams: Record<string, string> = {};
  req.nextUrl.searchParams.forEach((v, k) => { rawParams[k] = v; });

  const parsed = querySchema.safeParse(rawParams);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Invalid query params', 'VALIDATION_ERROR'));
  }
  const { page, limit, version } = parsed.data;
  const offset = (page - 1) * limit;
  const versionLike = version ? `%${escapeLikePattern(version)}%` : null;

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
    return withCors(errorResponse(404, 'Application not found', 'NOT_FOUND'));
  }
  const app = appResult.rows[0];

  // version filter (optional) narrows only the CVE list + its count — the
  // technique/group/weakness aggregates are product-level (no version axis).
  const cvesVersionClause = version ? 'AND (ap.version_start ILIKE $4 OR ap.version_end ILIKE $4)' : '';
  const cvesParams = version ? [app.id, limit, offset, versionLike] : [app.id, limit, offset];
  const countVersionClause = version ? 'AND (ap.version_start ILIKE $2 OR ap.version_end ILIKE $2)' : '';
  const countParams = version ? [app.id, versionLike] : [app.id];

  // Parallel queries for the 360 view
  const [cvesResult, techniquesResult, groupsResult, weaknessesResult, cveCountResult] = await Promise.all([
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
       WHERE ap.application_id = $1 ${cvesVersionClause}
       ORDER BY cd.published_at DESC NULLS LAST, cd.cvss_score DESC NULLS LAST
       LIMIT $2 OFFSET $3`,
      cvesParams,
    ),

    query<{ attackId: string; name: string; groupCount: string }>(
      // Names are JOINed live from techniques rather than denormalised into the
      // matview — keeps app_technique_groups narrow and lets ATT&CK renames
      // flow through without a refresh.
      `SELECT atg.attack_technique_id AS "attackId", t.name AS "name",
              COUNT(DISTINCT atg.group_attack_id)::text AS "groupCount"
       FROM app_technique_groups atg
       JOIN techniques t ON t.attack_id = atg.attack_technique_id
       WHERE atg.application_id = $1
       GROUP BY atg.attack_technique_id, t.name
       ORDER BY COUNT(DISTINCT atg.group_attack_id) DESC, t.name ASC`,
      [app.id],
    ),

    query<{ attackId: string; name: string; techniqueCount: string }>(
      `SELECT atg.group_attack_id AS "attackId", tg.name AS "name",
              COUNT(DISTINCT atg.attack_technique_id)::text AS "techniqueCount"
       FROM app_technique_groups atg
       JOIN threat_groups tg ON tg.attack_id = atg.group_attack_id
       WHERE atg.application_id = $1
       GROUP BY atg.group_attack_id, tg.name
       ORDER BY COUNT(DISTINCT atg.attack_technique_id) DESC, tg.name ASC`,
      [app.id],
    ),

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

    query<{ total: string }>(
      `SELECT COUNT(DISTINCT ap.cve_id)::text AS total
       FROM affected_products ap WHERE ap.application_id = $1 ${countVersionClause}`,
      countParams,
    ),
  ]);

  return withCors(jsonResponse({
    ...app,
    versionFilter: version ?? null,
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
  }, 3600));
}
