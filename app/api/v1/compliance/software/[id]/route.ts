import { NextRequest } from 'next/server';
import { query } from '../../../lib/db';
import { jsonResponse, errorResponse } from '../../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../../lib/cors';

export { OPTIONS };

// GET /api/v1/compliance/software/<attack_id>  (S####)
// UI labels say "Malware"; route + table names stay "software" (repository convention).

interface RouteCtx { params: Promise<{ id: string }> }

export async function GET(req: NextRequest, ctx: RouteCtx) {
  const { id } = await ctx.params;
  if (!/^S\d{4}$/.test(id)) {
    return errorResponse(400, 'Invalid software id', 'BAD_REQUEST');
  }
  const includeAll = req.nextUrl.searchParams.get('include_all') === '1';
  const tierFilter = includeAll ? [1, 2, 3] : [1, 2];

  const r = await query<{
    framework_key: string; name: string; region: string; tier: number;
    controls: number; techniques_ref: number;
  }>(
    `SELECT s.framework_key, f.name, f.region, f.tier,
            s.controls, s.techniques_ref
     FROM scf_software_compliance_summary s
     JOIN attack_software sw ON sw.id = s.software_id
     JOIN scf_frameworks  f  ON f.framework_key = s.framework_key
     WHERE sw.attack_id = $1 AND f.tier = ANY($2::int[])
     ORDER BY s.techniques_ref DESC, s.controls DESC, f.name ASC
     LIMIT 30`,
    [id, tierFilter],
  );

  return withCors(jsonResponse({ software_id: id, frameworks: r.rows }, 900));
}
