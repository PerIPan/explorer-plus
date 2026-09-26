import { NextRequest } from 'next/server';
import { query } from '../../lib/db';
import { jsonResponse, errorResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';
import { z } from 'zod';

export { OPTIONS };

/**
 * The Secure Controls Framework itself — the spine every regulatory framework
 * on /compliance is crosswalked through, rather than one of the frameworks.
 *
 * Its ATT&CK coverage is deliberately reported per control and in `meta`,
 * because it is narrow and the page must not imply otherwise: 108 of the 1,534
 * controls carry a mapping. The other 1,426 are real controls that simply have
 * no ATT&CK counterpart — governance, privacy, procurement — and a page that
 * hid that would suggest the bridge is twenty times wider than it is.
 *
 * `is_unresolved` marks a mapping whose technique id no longer resolves against
 * the ingested ATT&CK version (a revoked or renamed technique). Counted
 * separately so a drop in coverage after a corpus rotation is visible rather
 * than silently absorbed.
 */
const querySchema = z.object({
  search: z.string().max(200).optional(),
  domain: z.string().max(120).optional(),
  /** `mapped` restricts to controls that carry at least one ATT&CK mapping. */
  mapped: z.enum(['1', 'true']).optional(),
  page:   z.coerce.number().int().positive().max(1000).default(1),
  limit:  z.coerce.number().int().positive().max(5000).default(50),
});

export async function GET(req: NextRequest) {
  const rawParams: Record<string, string> = {};
  req.nextUrl.searchParams.forEach((v, k) => { rawParams[k] = v; });

  const parsed = querySchema.safeParse(rawParams);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Invalid query params', 'VALIDATION_ERROR'));
  }

  const { search, domain, mapped, page, limit } = parsed.data;
  const offset = (page - 1) * limit;
  const params: unknown[] = [];
  const conditions: string[] = [];

  if (search) {
    params.push(`%${search}%`);
    conditions.push(
      `(c.scf_id ILIKE $${params.length} OR c.name ILIKE $${params.length} OR c.description ILIKE $${params.length})`,
    );
  }
  if (domain) {
    params.push(domain);
    conditions.push(`c.domain = $${params.length}`);
  }
  if (mapped) {
    conditions.push(`EXISTS (SELECT 1 FROM scf_attack_mappings m WHERE m.scf_id = c.scf_id)`);
  }

  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  const countResult = await query<{ total: string }>(
    `SELECT COUNT(*) AS total FROM scf_controls c ${where}`,
    params,
  );
  const total = parseInt(countResult.rows[0].total, 10);

  params.push(limit, offset);
  const dataResult = await query<{
    scfId: string;
    domain: string;
    name: string;
    description: string;
    techniques: string[] | null;
    unresolvedCount: string;
  }>(
    `SELECT
       c.scf_id      AS "scfId",
       c.domain,
       c.name,
       c.description,
       ARRAY(SELECT m.attack_id FROM scf_attack_mappings m
              WHERE m.scf_id = c.scf_id AND NOT m.is_unresolved
              ORDER BY m.attack_id)                         AS techniques,
       (SELECT COUNT(*) FROM scf_attack_mappings m
         WHERE m.scf_id = c.scf_id AND m.is_unresolved)     AS "unresolvedCount"
     FROM scf_controls c
     ${where}
     ORDER BY c.scf_id ASC
     LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params,
  );

  // Corpus-wide, not page-wide: the honest denominators for the coverage claim.
  const metaResult = await query<{
    controls: string; domains: string; mappedControls: string; mappings: string; frameworks: string;
  }>(
    `SELECT
       (SELECT COUNT(*) FROM scf_controls)                          AS controls,
       (SELECT COUNT(DISTINCT domain) FROM scf_controls)            AS domains,
       (SELECT COUNT(DISTINCT scf_id) FROM scf_attack_mappings)     AS "mappedControls",
       (SELECT COUNT(*) FROM scf_attack_mappings)                   AS mappings,
       (SELECT COUNT(*) FROM scf_frameworks)                        AS frameworks`,
  );
  const m = metaResult.rows[0];

  return withCors(jsonResponse({
    data: dataResult.rows.map((r) => ({
      ...r,
      techniques: r.techniques ?? [],
      unresolvedCount: parseInt(r.unresolvedCount, 10),
    })),
    meta: {
      controls: parseInt(m.controls, 10),
      domains: parseInt(m.domains, 10),
      mappedControls: parseInt(m.mappedControls, 10),
      mappings: parseInt(m.mappings, 10),
      frameworksCrosswalked: parseInt(m.frameworks, 10),
      coverageNote:
        'ATT&CK mappings exist for a minority of SCF controls. The rest are governance, privacy and procurement controls with no ATT&CK counterpart.',
      licence: 'Secure Controls Framework, CC BY 4.0 — https://www.securecontrolsframework.com/',
    },
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
    },
  }, 3600));
}
