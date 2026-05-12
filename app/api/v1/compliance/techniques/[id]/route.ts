import { NextRequest } from 'next/server';
import { query } from '../../../lib/db';
import { jsonResponse, errorResponse } from '../../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../../lib/cors';

export { OPTIONS };

// GET /api/v1/compliance/techniques/<attack_id>
//   ?tier=1,2 (default), ?include_all=1
//
// Returns the compliance-framework chip list for a single ATT&CK technique.
//   - SCF control count per framework
//   - ref_ids (first 5 surfaced, full count in `ref_count`)
//   - flag for whether any of the underlying mappings are unresolved (v19 drift)

interface RouteCtx { params: Promise<{ id: string }> }

export async function GET(req: NextRequest, ctx: RouteCtx) {
  const { id } = await ctx.params;
  const includeAll = req.nextUrl.searchParams.get('include_all') === '1';
  const tierFilter = includeAll ? [1, 2, 3] : [1, 2];

  if (!/^T\d{4}(?:\.\d{3})?$/.test(id)) {
    return errorResponse(400, 'Invalid ATT&CK technique id', 'BAD_REQUEST');
  }

  // Filter unresolved mappings out of the COUNT + ref_ids (Decision 11), then
  // re-run a small EXISTS for the badge. Cap ref_ids at 8 server-side to keep
  // payloads bounded (T1059-class techniques can map to hundreds of refs).
  const sql = `
    WITH ranked AS (
      SELECT fr.framework_key, fr.scf_id, fr.ref_id, f.name, f.region, f.tier, f.license
      FROM scf_attack_mappings m
      JOIN scf_framework_refs fr ON fr.scf_id = m.scf_id
      JOIN scf_frameworks    f  ON f.framework_key = fr.framework_key
      WHERE m.attack_id = $1
        AND f.tier = ANY($2::int[])
        AND NOT m.is_unresolved
    )
    SELECT
      framework_key,
      MAX(name)   AS name,
      MAX(region) AS region,
      MAX(tier)   AS tier,
      MAX(license) AS license,
      COUNT(DISTINCT scf_id)::int AS controls,
      (ARRAY_AGG(DISTINCT ref_id ORDER BY ref_id))[1:8] AS ref_ids,
      EXISTS (
        SELECT 1 FROM scf_attack_mappings m2
        JOIN scf_framework_refs fr2 ON fr2.scf_id = m2.scf_id
        WHERE m2.attack_id = $1 AND fr2.framework_key = ranked.framework_key
          AND m2.is_unresolved
      ) AS has_unresolved
    FROM ranked
    GROUP BY framework_key
    ORDER BY MAX(tier) ASC, controls DESC, MAX(name) ASC
  `;
  const r = await query(sql, [id, tierFilter]);

  return withCors(jsonResponse({ attack_id: id, frameworks: r.rows }, 900));
}
