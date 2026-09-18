import { NextRequest } from 'next/server';
import { query } from '../../lib/db';
import { jsonResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';

export { OPTIONS };

/**
 * The Purdue Model as data: seven levels, the assets present at each, the
 * ATT&CK ICS techniques reaching them, and the full 42-pair flow matrix.
 *
 * Scope note for consumers: technique counts are ICS-domain only. ATT&CK
 * publishes assets for ics-attack and no other domain, so L4/L5 legitimately
 * carry no assets — that is an honest absence, not missing data.
 *
 * One bundled response rather than five endpoints: the whole payload is a few
 * KB (7 levels, 18 assets, 42 rules) and the page renders all of it at once, so
 * splitting it would cost round trips and extra Neon wake-ups for nothing.
 */
export async function GET(_req: NextRequest) {
  const [levels, assets, rules] = await Promise.all([
    // Per-level rollup. Counted over spans_levels, not primary_level, so an
    // asset present at two levels is counted at both — which is the question
    // the matrix actually answers ("what is exposed at this level?").
    query(
      `SELECT
         l.level_key                                      AS "levelKey",
         l.label,
         l.zone,
         l.description,
         l.sort_order                                     AS "sortOrder",
         COUNT(DISTINCT p.asset_id)::int                  AS "assetCount",
         COUNT(DISTINCT at.technique_id)::int             AS "techniqueCount",
         COUNT(DISTINCT p.asset_id) FILTER (WHERE p.is_boundary)::int AS "boundaryAssetCount"
       FROM purdue_levels l
       LEFT JOIN asset_purdue_placement p ON l.level_key = ANY(p.spans_levels)
       LEFT JOIN asset_techniques at      ON at.asset_id = p.asset_id
       GROUP BY l.level_key, l.label, l.zone, l.description, l.sort_order
       ORDER BY l.sort_order ASC`,
    ),
    query(
      `SELECT
         a.attack_id                    AS "attackId",
         a.name,
         p.primary_level                AS "primaryLevel",
         COALESCE(p.spans_levels, '{}') AS "spansLevels",
         p.is_boundary                  AS "isBoundary",
         p.rationale,
         COALESCE(t.n, 0)::int          AS "techniqueCount"
       FROM asset_purdue_placement p
       JOIN attack_assets a ON a.id = p.asset_id
       LEFT JOIN purdue_levels l ON l.level_key = p.primary_level
       LEFT JOIN (SELECT asset_id, COUNT(*) AS n FROM asset_techniques GROUP BY asset_id) t
              ON t.asset_id = p.asset_id
       WHERE NOT a.is_revoked AND NOT a.is_deprecated
       ORDER BY l.sort_order ASC, a.attack_id ASC`,
    ),
    // direct_allowed is single-hop adjacency ONLY. A pair with brokerLevel set
    // is reachable solely by terminating a session at that level, so a consumer
    // must never read it as an adjacency.
    query(
      `SELECT
         r.from_level     AS "fromLevel",
         r.to_level       AS "toLevel",
         r.direct_allowed AS "directAllowed",
         r.broker_level   AS "brokerLevel",
         r.note
       FROM purdue_flow_rules r
       JOIN purdue_levels f ON f.level_key = r.from_level
       JOIN purdue_levels t ON t.level_key = r.to_level
       ORDER BY f.sort_order ASC, t.sort_order ASC`,
    ),
  ]);

  return withCors(jsonResponse({
    data: {
      levels: levels.rows,
      assets: assets.rows,
      flowRules: rules.rows,
      meta: {
        techniqueDomain: 'ics-attack',
        note: 'Technique counts are ATT&CK for ICS only. MITRE publishes assets for the ICS domain alone, so enterprise levels (L4/L5) carry no assets by design. Purdue placement is curated (NIST SP 800-82r3 / ISA-95), not MITRE-published.',
      },
    },
  }, 3600));
}
