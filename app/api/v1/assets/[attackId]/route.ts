import { NextRequest } from 'next/server';
import { query } from '../../lib/db';
import { jsonResponse, errorResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';

export { OPTIONS };

// Validate the segment before it reaches Postgres. An unvalidated value would
// otherwise reach the query and any cast error surfaces as a 500 rather than
// the 404 the caller deserves.
const ASSET_ID_RE = /^A\d{4}$/;

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ attackId: string }> },
) {
  const { attackId } = await params;
  const id = attackId.toUpperCase();
  if (!ASSET_ID_RE.test(id)) {
    return withCors(errorResponse(400, 'Invalid asset ID (expected A0001-style)', 'VALIDATION_ERROR'));
  }

  const assetResult = await query(
    `SELECT
       a.id,
       a.attack_id                    AS "attackId",
       a.name,
       a.description,
       a.url,
       COALESCE(a.sectors,   '{}')    AS sectors,
       COALESCE(a.platforms, '{}')    AS platforms,
       a.is_revoked                   AS "isRevoked",
       a.is_deprecated                AS "isDeprecated",
       p.primary_level                AS "primaryLevel",
       l.label                        AS "primaryLevelLabel",
       l.zone,
       l.description                  AS "primaryLevelDescription",
       COALESCE(p.spans_levels, '{}') AS "spansLevels",
       COALESCE(p.is_boundary, false) AS "isBoundary",
       p.rationale,
       p.source                       AS "placementSource"
     FROM attack_assets a
     LEFT JOIN asset_purdue_placement p ON p.asset_id = a.id
     LEFT JOIN purdue_levels l          ON l.level_key = p.primary_level
     WHERE a.attack_id = $1`,
    [id],
  );

  if (assetResult.rowCount === 0) {
    return withCors(errorResponse(404, `Asset ${id} not found`, 'NOT_FOUND'));
  }
  const asset = assetResult.rows[0] as Record<string, unknown>;
  const assetUuid = asset.id;
  delete asset.id; // internal surrogate; attackId is the public identity

  const [techniques, related, spans, countermeasures] = await Promise.all([
    query(
      `SELECT
         k.attack_id   AS "attackId",
         k.name,
         k.description,
         k.url
       FROM asset_techniques at
       JOIN techniques k ON k.id = at.technique_id
      WHERE at.asset_id = $1
      ORDER BY k.attack_id ASC`,
      [assetUuid],
    ),
    query(
      `SELECT
         related_name                    AS name,
         COALESCE(related_sectors, '{}') AS sectors,
         description
       FROM asset_related_assets
      WHERE asset_id = $1
      ORDER BY related_name ASC`,
      [assetUuid],
    ),
    query(
      `SELECT l.level_key AS "levelKey", l.label, l.zone, l.sort_order AS "sortOrder"
         FROM purdue_levels l
         JOIN asset_purdue_placement p ON l.level_key = ANY(p.spans_levels)
        WHERE p.asset_id = $1
        ORDER BY l.sort_order ASC`,
      [assetUuid],
    ),
    // D3FEND countermeasures reaching this asset through the techniques that
    // target it. Rolled up here rather than fetched per technique: an asset
    // carries 39-61 techniques, so the client would otherwise make dozens of
    // round trips to answer one question. defensive_mappings joins on the
    // technique UUID, not the text attack id.
    query(
      `SELECT
         d.d3fend_id          AS "d3fendId",
         MIN(d.d3fend_name)   AS "d3fendName",
         MIN(d.d3fend_tactic) AS "d3fendTactic",
         COUNT(DISTINCT at.technique_id)::int AS "techniqueCount"
       FROM asset_techniques at
       JOIN defensive_mappings d ON d.technique_id = at.technique_id
      WHERE at.asset_id = $1
      GROUP BY d.d3fend_id
      ORDER BY COUNT(DISTINCT at.technique_id) DESC, d.d3fend_id ASC`,
      [assetUuid],
    ),
  ]);

  // Countermeasures grouped by D3FEND tactic, so the view can show "how this
  // asset is defended" the same way the technique pages do.
  const byTactic: Record<string, number> = {};
  for (const c of countermeasures.rows as Array<{ d3fendTactic: string | null }>) {
    const t = c.d3fendTactic ?? 'Unknown';
    byTactic[t] = (byTactic[t] ?? 0) + 1;
  }

  return withCors(jsonResponse({
    data: {
      ...asset,
      levels: spans.rows,
      techniques: techniques.rows,
      techniqueCount: techniques.rowCount,
      relatedAssets: related.rows,
      countermeasures: countermeasures.rows,
      countermeasureCount: countermeasures.rowCount,
      countermeasuresByTactic: byTactic,
    },
  }, 3600));
}
