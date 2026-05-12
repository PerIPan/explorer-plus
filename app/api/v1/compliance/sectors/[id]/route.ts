import { NextRequest } from 'next/server';
import { query } from '../../../lib/db';
import { jsonResponse, errorResponse } from '../../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../../lib/cors';

export { OPTIONS };

// GET /api/v1/compliance/sectors/<slug-or-name>
// Joins by sectors.slug first, falls back to LOWER(name) equality.

interface RouteCtx { params: Promise<{ id: string }> }

export async function GET(req: NextRequest, ctx: RouteCtx) {
  const { id } = await ctx.params;
  if (!id || id.length > 80) {
    return errorResponse(400, 'Invalid sector id', 'BAD_REQUEST');
  }
  const includeAll = req.nextUrl.searchParams.get('include_all') === '1';
  const tierFilter = includeAll ? [1, 2, 3] : [1, 2];

  const r = await query<{
    framework_key: string; name: string; region: string; tier: number;
    controls: number; techniques_ref: number;
  }>(
    `SELECT s.framework_key, f.name, f.region, f.tier, s.controls, s.techniques_ref
     FROM scf_sector_compliance_summary s
     JOIN sectors        sec ON sec.id = s.sector_id
     JOIN scf_frameworks f   ON f.framework_key = s.framework_key
     WHERE (sec.slug = $1 OR LOWER(sec.name) = LOWER($1))
       AND f.tier = ANY($2::int[])
     ORDER BY s.techniques_ref DESC, s.controls DESC, f.name ASC
     LIMIT 30`,
    [id, tierFilter],
  );

  return withCors(jsonResponse({ sector_id: id, frameworks: r.rows }, 900));
}
