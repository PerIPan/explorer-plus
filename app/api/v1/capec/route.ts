import { NextRequest } from 'next/server';
import { query } from '../lib/db';
import { jsonResponse, errorResponse } from '../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../lib/cors';
import { paginationSchema } from '../lib/validate';
import { escapeLikePattern } from '../lib/queries';
import { z } from 'zod';

export { OPTIONS };

const SEVERITY_VALUES = ['Very Low', 'Low', 'Medium', 'High', 'Very High'] as const;
const LIKELIHOOD_VALUES = ['Low', 'Medium', 'High'] as const;
const ABSTRACTION_VALUES = ['Meta', 'Standard', 'Detailed'] as const;

const querySchema = paginationSchema.extend({
  q: z.string().min(2).max(200).optional(),
  abstraction: z.enum(ABSTRACTION_VALUES).optional(),
  severity: z.enum(SEVERITY_VALUES).optional(),
  likelihood: z.enum(LIKELIHOOD_VALUES).optional(),
});

export async function GET(req: NextRequest) {
  const rawParams: Record<string, string> = {};
  req.nextUrl.searchParams.forEach((v, k) => { rawParams[k] = v; });

  const parsed = querySchema.safeParse(rawParams);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Invalid query parameters', 'VALIDATION_ERROR'));
  }

  const { page, limit, q, abstraction, severity, likelihood } = parsed.data;
  const offset = (page - 1) * limit;

  const conditions: string[] = [];
  const params: unknown[] = [];

  if (q) {
    params.push(`%${escapeLikePattern(q)}%`);
    conditions.push(`(p.name ILIKE $${params.length} OR p.id ILIKE $${params.length})`);
  }
  if (abstraction) {
    params.push(abstraction);
    conditions.push(`p.abstraction = $${params.length}`);
  }
  if (severity) {
    params.push(severity);
    conditions.push(`p.severity = $${params.length}`);
  }
  if (likelihood) {
    params.push(likelihood);
    conditions.push(`p.likelihood = $${params.length}`);
  }

  const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  try {
    const countResult = await query<{ total: string }>(
      `SELECT COUNT(*) AS total FROM capec_patterns p ${where}`,
      params,
    );
    const total = parseInt(countResult.rows[0].total, 10);

    params.push(limit, offset);
    const dataResult = await query<{
      id: string;
      name: string;
      abstraction: string | null;
      likelihood: string | null;
      severity: string | null;
      cweIds: string[] | null;
      techniqueCount: string;
      mitigationCount: string;
    }>(
      `SELECT
         p.id, p.name, p.abstraction, p.likelihood, p.severity,
         p.cwe_ids AS "cweIds",
         (SELECT COUNT(DISTINCT cm.technique_id)::text
            FROM capec_mappings cm
            WHERE cm.capec_id = p.id AND cm.technique_id IS NOT NULL) AS "techniqueCount",
         (SELECT COUNT(*)::text FROM capec_pattern_mitigations pm
            WHERE pm.capec_id = p.id) AS "mitigationCount"
       FROM capec_patterns p
       ${where}
       ORDER BY
         CASE p.severity
           WHEN 'Very High' THEN 5 WHEN 'High' THEN 4 WHEN 'Medium' THEN 3
           WHEN 'Low' THEN 2 WHEN 'Very Low' THEN 1 ELSE 0 END DESC,
         p.id ASC
       LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params,
    );

    return withCors(jsonResponse({
      data: dataResult.rows.map((r) => ({
        ...r,
        techniqueCount: parseInt(r.techniqueCount, 10),
        mitigationCount: parseInt(r.mitigationCount, 10),
      })),
      pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
    }, 3600));
  } catch (err) {
    console.error('CAPEC list query failed:', err);
    return withCors(jsonResponse({
      data: [],
      pagination: { page, limit, total: 0, totalPages: 0 },
    }, 60));
  }
}
