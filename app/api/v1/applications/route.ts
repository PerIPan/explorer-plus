import { NextRequest } from 'next/server';
import { query } from '../lib/db.js';
import { jsonResponse, errorResponse } from '../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../lib/cors';
import { z } from 'zod';

export { OPTIONS };

const querySchema = z.object({
  search: z.string().max(200).optional(),
  vendor: z.string().max(200).optional(),
  page: z.coerce.number().int().positive().max(1000).default(1),
  limit: z.coerce.number().int().positive().max(200).default(50),
  sort: z.enum(['cve_count', 'vendor', 'product']).default('cve_count'),
  order: z.enum(['asc', 'desc']).default('desc'),
});

export async function GET(req: NextRequest) {
  const rawParams: Record<string, string> = {};
  req.nextUrl.searchParams.forEach((v, k) => { rawParams[k] = v; });

  const parsed = querySchema.safeParse(rawParams);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Invalid query params', 'VALIDATION_ERROR'));
  }

  const { search, vendor, page, limit, sort, order } = parsed.data;
  const offset = (page - 1) * limit;
  const params: unknown[] = [];
  const conditions: string[] = [];

  if (search) {
    params.push(search);
    conditions.push(`(a.vendor ILIKE '%' || $${params.length} || '%' OR a.product ILIKE '%' || $${params.length} || '%')`);
  }
  if (vendor) {
    params.push(vendor);
    conditions.push(`a.vendor = $${params.length}`);
  }

  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  const sortMap: Record<string, string> = {
    cve_count: 'a.cve_count',
    vendor: 'a.vendor',
    product: 'a.product',
  };
  const sortCol = sortMap[sort] ?? 'a.cve_count';
  const sortDir = order === 'asc' ? 'ASC' : 'DESC';

  const countResult = await query<{ total: string }>(
    `SELECT COUNT(*) AS total FROM applications a ${where}`,
    params,
  );
  const total = parseInt(countResult.rows[0].total, 10);

  params.push(limit, offset);
  const dataResult = await query<{
    id: string;
    vendor: string;
    product: string;
    normalized: string;
    cpePrefix: string | null;
    cveCount: string;
    topSeverity: string | null;
    techniqueCount: string;
    groupCount: string;
  }>(
    `SELECT
       a.id, a.vendor, a.product, a.normalized, a.cpe_prefix AS "cpePrefix",
       a.cve_count::text AS "cveCount",
       (SELECT cd.cvss_severity FROM cve_details cd
        JOIN affected_products ap ON ap.cve_id = cd.cve_id AND ap.application_id = a.id
        WHERE cd.cvss_severity IS NOT NULL
        ORDER BY cd.cvss_score DESC NULLS LAST LIMIT 1
       ) AS "topSeverity",
       (SELECT COUNT(DISTINCT attack_technique_id) FROM app_technique_groups WHERE application_id = a.id)::text AS "techniqueCount",
       (SELECT COUNT(DISTINCT group_attack_id) FROM app_technique_groups WHERE application_id = a.id)::text AS "groupCount"
     FROM applications a
     ${where}
     ORDER BY ${sortCol} ${sortDir}, a.vendor ASC, a.product ASC
     LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params,
  );

  return withCors(jsonResponse({
    data: dataResult.rows.map((r) => ({
      ...r,
      cveCount: parseInt(r.cveCount, 10),
      techniqueCount: parseInt(r.techniqueCount, 10),
      groupCount: parseInt(r.groupCount, 10),
    })),
    pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
  }, 3600));
}
