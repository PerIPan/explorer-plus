import { NextRequest } from 'next/server';
import { query } from '../lib/db';
import { jsonResponse } from '../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../lib/cors';

export { OPTIONS };

/**
 * How big each part of the corpus is — the numbers the sidebar puts beside a
 * nav entry, and a fair answer to "how much data is behind this site?".
 *
 * EXACT where exact is cheap, ESTIMATED where it is not. `count(*)` over
 * cve_details and ioc_entries together measured 1,770 ms on Neon, and this is
 * fetched by the shell on page load, so those come from `pg_class.reltuples` —
 * the planner's own estimate, refreshed by autovacuum, 13 ms for the lot and
 * within about 1% (cve_details: 109,130 estimated against 109,829 counted).
 *
 * A nav badge is a sense of scale, not an audit, and the UI abbreviates these
 * to 110K / 2.0M, which is honest about the precision on offer. `meta.estimated`
 * names which fields are approximate so an API caller can tell too.
 */
const ESTIMATE = (table: string) =>
  `(SELECT CASE WHEN reltuples < 0 THEN NULL ELSE reltuples::bigint END
      FROM pg_class WHERE oid = to_regclass('public.${table}'))`;

export async function GET(_req: NextRequest) {
  const result = await query<Record<string, number | null>>(
    `SELECT
       (SELECT count(*) FROM applications)::int                       AS applications,
       (SELECT count(*) FROM attack_assets
          WHERE is_revoked = false AND is_deprecated = false)::int     AS "icsAssets",
       (SELECT count(*) FROM ecosystem_advisory_stats)::int            AS ecosystems,
       (SELECT count(*) FROM packages)::int                            AS packages,
       (SELECT count(*) FROM threat_reports)::int                      AS reports,
       -- Every framework /compliance can show: the curated tiers 1-2 plus the
       -- tier-3 long tail that has at least one control reference. This is the
       -- exact expression behind that page's own framework_count, and behind
       -- ?include_all -- 224, against 21 for the default view. The nav badge is
       -- what is COVERED, not what one filter happens to show.
       (SELECT count(*) FROM scf_frameworks f
          WHERE f.tier <= 2
             OR EXISTS (SELECT 1 FROM scf_framework_refs r
                         WHERE r.framework_key = f.framework_key))::int AS frameworks,
       ${ESTIMATE('cve_details')}::int                                 AS cves,
       ${ESTIMATE('ioc_entries')}::int                                 AS iocs,
       (COALESCE(${ESTIMATE('ghsa_advisories')}, 0)
        + COALESCE(${ESTIMATE('osv_advisories')}, 0))::int             AS advisories`,
  );

  return withCors(
    jsonResponse(
      {
        data: result.rows[0],
        meta: {
          estimated: ['cves', 'iocs', 'advisories'],
          note: 'Estimated fields come from planner statistics and are within ~1%. Everything else is an exact count.',
        },
      },
      // An hour at the CDN. These move on ingest cadences measured in hours.
      3600,
    ),
  );
}
