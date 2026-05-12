import { NextRequest } from 'next/server';
import { query } from '../../lib/db';
import { jsonResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';

export { OPTIONS };

// GET /api/v1/compliance/frameworks
//   ?tier=1,2   filter by tier (default: 1,2 — curated)
//   ?include_all=1 include Tier-3 long-tail
//
// Returns the master hub list with coverage stats per framework_key.
// Coverage stats are computed live (cheap — joins are indexed). We can move
// to a materialised view if perf becomes an issue.

interface FrameworkRow {
  framework_key: string;
  name: string;
  version: string | null;
  source_org: string;
  upstream_url: string;
  region: string;
  tier: number;
  license: string | null;
  short_blurb: string | null;
  scf_controls: number;
  techniques_total: number;
  techniques_filtered: number; // techniques referenced by 2+ SCF controls
}

export async function GET(req: NextRequest) {
  const includeAll = req.nextUrl.searchParams.get('include_all') === '1';
  const tierFilter = includeAll ? [1, 2, 3] : [1, 2];

  // PK lookup on scf_framework_coverage (pre-computed at ingest end).
  // p95 < 10ms vs the 532ms cold-compute path.
  const sql = `
    SELECT
      f.framework_key, f.name, f.version, f.source_org, f.upstream_url,
      f.region, f.tier, f.license, f.short_blurb,
      COALESCE(c.scf_controls, 0)        AS scf_controls,
      COALESCE(c.techniques_total, 0)    AS techniques_total,
      COALESCE(c.techniques_filtered, 0) AS techniques_filtered
    FROM scf_frameworks f
    LEFT JOIN scf_framework_coverage c USING (framework_key)
    WHERE f.tier = ANY($1::int[])
    ORDER BY f.tier ASC, f.region ASC, c.techniques_filtered DESC NULLS LAST, f.name ASC
  `;
  const r = await query<FrameworkRow>(sql, [tierFilter]);

  // Also surface global meta — total tracked, ingest version, etc.
  const metaRows = await query<{
    framework_count: string;
    control_count: string;
    mapping_count: string;
    unresolved_count: string;
    last_run_at: string | null;
    scf_version: string | null;
  }>(
    `SELECT
       (SELECT COUNT(*)::text FROM scf_frameworks)              AS framework_count,
       (SELECT COUNT(*)::text FROM scf_controls)                AS control_count,
       (SELECT COUNT(*)::text FROM scf_attack_mappings)         AS mapping_count,
       (SELECT COUNT(*)::text FROM scf_attack_mappings WHERE is_unresolved) AS unresolved_count,
       (SELECT completed_at::text FROM feed_sync_log
         WHERE source='scf' AND status='success'
         ORDER BY completed_at DESC NULLS LAST LIMIT 1)         AS last_run_at,
       (SELECT metadata->>'scfVersion' FROM feed_sync_log
         WHERE source='scf' AND status='success'
         ORDER BY completed_at DESC NULLS LAST LIMIT 1)         AS scf_version`,
  );
  const meta = metaRows.rows[0] ?? {};

  return withCors(
    jsonResponse(
      {
        meta: {
          framework_count: parseInt(meta.framework_count ?? '0', 10),
          control_count: parseInt(meta.control_count ?? '0', 10),
          mapping_count: parseInt(meta.mapping_count ?? '0', 10),
          unresolved_count: parseInt(meta.unresolved_count ?? '0', 10),
          last_run_at: meta.last_run_at,
          scf_version: meta.scf_version,
        },
        frameworks: r.rows,
      },
      900,
    ),
  );
}
