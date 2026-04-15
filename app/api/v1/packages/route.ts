import { NextRequest } from 'next/server';
import { query } from '../lib/db';
import { jsonResponse, errorResponse } from '../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../lib/cors';
import { paginationSchema } from '../lib/validate';
import { escapeLikePattern } from '../lib/queries';
import { z } from 'zod';

export { OPTIONS };

const ECOSYSTEM_RE = /^[a-z][a-z0-9-]{1,49}$/;

const querySchema = paginationSchema.extend({
  ecosystem: z.string().regex(ECOSYSTEM_RE).optional(),
  q: z.string().min(3).max(200).optional(),  // min 3 so trigram ILIKE is plannable
});

export async function GET(req: NextRequest) {
  const rawParams: Record<string, string> = {};
  req.nextUrl.searchParams.forEach((v, k) => { rawParams[k] = v; });

  const parsed = querySchema.safeParse(rawParams);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Invalid query parameters', 'VALIDATION_ERROR'));
  }

  const { page, limit, ecosystem, q } = parsed.data;
  const offset = (page - 1) * limit;

  const conditions: string[] = [];
  const params: unknown[] = [];

  if (ecosystem) {
    params.push(ecosystem.toLowerCase());
    conditions.push(`ecosystem = $${params.length}`);
  }
  if (q) {
    params.push(`%${escapeLikePattern(q)}%`);
    conditions.push(`package_name ILIKE $${params.length}`);
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  // Count
  try {
    const countResult = await query<{ count: string }>(
      `SELECT COUNT(*) FROM package_summary ${whereClause}`,
      params,
    );
    const total = parseInt(countResult.rows[0].count, 10);

    params.push(limit, offset);
    const result = await query<{
      packageId: string;
      ecosystem: string;
      packageName: string;
      purl: string | null;
      advisoryCount: string;
      latestPublished: string | null;
      severities: string[] | null;
      techniqueCount: string;
    }>(
      `SELECT
         package_id       AS "packageId",
         ecosystem,
         package_name     AS "packageName",
         purl,
         advisory_count   AS "advisoryCount",
         latest_published AS "latestPublished",
         severities,
         technique_count  AS "techniqueCount"
       FROM package_summary
       ${whereClause}
       ORDER BY advisory_count DESC, latest_published DESC NULLS LAST, package_name ASC
       LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params,
    );

    const data = result.rows.map((r) => ({
      packageId: r.packageId,
      ecosystem: r.ecosystem,
      packageName: r.packageName,
      purl: r.purl,
      advisoryCount: parseInt(r.advisoryCount, 10),
      latestPublished: r.latestPublished,
      severities: r.severities ?? [],
      techniqueCount: parseInt(r.techniqueCount, 10),
    }));

    return withCors(jsonResponse({
      data,
      pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
    }, 300));
  } catch (err) {
    // Graceful pre-migration / empty-matview fallback
    console.error('package_summary query failed:', err);
    return withCors(jsonResponse({
      data: [],
      pagination: { page, limit, total: 0, totalPages: 0 },
    }, 60));
  }
}
