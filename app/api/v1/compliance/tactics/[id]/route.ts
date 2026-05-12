import { NextRequest } from 'next/server';
import { query } from '../../../lib/db';
import { jsonResponse, errorResponse } from '../../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../../lib/cors';

export { OPTIONS };

// GET /api/v1/compliance/tactics/<attack_id>
// Returns top Tier 1+2 frameworks by reference count over this tactic's
// technique stack. Roll-up against scf_framework_refs/scf_attack_mappings.

interface RouteCtx { params: Promise<{ id: string }> }

export async function GET(req: NextRequest, ctx: RouteCtx) {
  const { id } = await ctx.params;
  if (!/^TA\d{4}$/.test(id)) {
    return errorResponse(400, 'Invalid tactic id', 'BAD_REQUEST');
  }
  const includeAll = req.nextUrl.searchParams.get('include_all') === '1';
  const tierFilter = includeAll ? [1, 2, 3] : [1, 2];

  const r = await query<{
    framework_key: string; name: string; region: string; tier: number;
    techniques_ref: number; controls: number;
  }>(
    `WITH tactic_techs AS (
       SELECT DISTINCT t.attack_id
       FROM tactics tac
       JOIN technique_tactics tt ON tt.tactic_id = tac.id
       JOIN techniques t ON t.id = tt.technique_id
       WHERE tac.attack_id = $1
     )
     SELECT fr.framework_key, f.name, f.region, f.tier,
            COUNT(DISTINCT m.attack_id)::int AS techniques_ref,
            COUNT(DISTINCT fr.scf_id)::int   AS controls
     FROM tactic_techs tt
     JOIN scf_attack_mappings m ON m.attack_id = tt.attack_id AND NOT m.is_unresolved
     JOIN scf_framework_refs fr ON fr.scf_id   = m.scf_id
     JOIN scf_frameworks     f  ON f.framework_key = fr.framework_key
     WHERE f.tier = ANY($2::int[])
     GROUP BY fr.framework_key, f.name, f.region, f.tier
     ORDER BY techniques_ref DESC, controls DESC, f.name ASC
     LIMIT 10`,
    [id, tierFilter],
  );

  return withCors(jsonResponse({ tactic_id: id, frameworks: r.rows }, 900));
}
