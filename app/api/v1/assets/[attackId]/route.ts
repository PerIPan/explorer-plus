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

  const [techniques, related, spans] = await Promise.all([
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
  ]);

  return withCors(jsonResponse({
    data: {
      ...asset,
      levels: spans.rows,
      techniques: techniques.rows,
      techniqueCount: techniques.rowCount,
      relatedAssets: related.rows,
    },
  }, 3600));
}
