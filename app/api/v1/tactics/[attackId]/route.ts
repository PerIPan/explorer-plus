import { NextRequest } from 'next/server';
import { query } from '../../lib/db';
import { jsonResponse, errorResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';
import { attackIdSchema } from '../../lib/validate';

export { OPTIONS };

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ attackId: string }> }
) {
  const { attackId: rawAttackId } = await params;
  const parsed = attackIdSchema.safeParse(rawAttackId);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Invalid attack_id format', 'VALIDATION_ERROR'));
  }
  const attackId = parsed.data;

  const tacticResult = await query<{
    id: string; attackId: string; stixId: string | null; name: string;
    description: string | null; url: string | null; sortOrder: number | null;
    domain: string | null; stixCreated: string | null; stixModified: string | null;
  }>(
    `SELECT
       id, attack_id AS "attackId", stix_id AS "stixId", name, description, url,
       sort_order AS "sortOrder", domain,
       stix_created AS "stixCreated", stix_modified AS "stixModified"
     FROM tactics WHERE attack_id = $1`,
    [attackId],
  );

  if (tacticResult.rows.length === 0) {
    return withCors(errorResponse(404, 'Tactic not found', 'NOT_FOUND'));
  }

  const tactic = tacticResult.rows[0];
  const tacticId = tactic.id;

  /**
   * `dataSources` is the ATT&CK telemetry rollup for this tactic, RANKED by how
   * many of its techniques each source covers.
   *
   * Ranking is the whole point. Flat, the answer is useless — TA0003 reaches 25
   * of the 42 data sources across 113 techniques, TA0002 21, TA0006 19, so "the
   * logs for Persistence" would be 60% of everything. Weighted it has a steep
   * head: Process 87 of 113, File 64, Windows Registry 35, then a long tail.
   * That is an answer someone can act on.
   *
   * Same `is_revoked = false AND is_deprecated = false` filter as the technique
   * list above, so `techniquesCovered` is always out of the number of
   * techniques this response actually returns.
   *
   * Measured 2026-10-02: 20ms (TA0001, TA0010) to 106ms (TA0003) on existing
   * indexes — no matview, no cron.
   */
  const [techniquesResult, dataSourcesResult] = await Promise.all([
    query<{
      attackId: string; name: string; description: string | null;
      platforms: string[] | null; isSubtechnique: boolean;
    }>(
      `SELECT
         t.attack_id      AS "attackId",
         t.name,
         t.description,
         t.platforms,
         t.is_subtechnique AS "isSubtechnique"
       FROM technique_tactics tt
       JOIN techniques t ON t.id = tt.technique_id
       WHERE tt.tactic_id = $1
         AND t.is_revoked = false AND t.is_deprecated = false
       ORDER BY t.attack_id ASC`,
      [tacticId],
    ),
    query<{ attackId: string; name: string; techniquesCovered: number }>(
      `WITH tech AS (
         SELECT t.id
         FROM technique_tactics tt
         JOIN techniques t ON t.id = tt.technique_id
         WHERE tt.tactic_id = $1
           AND t.is_revoked = false AND t.is_deprecated = false
       )
       SELECT ds.attack_id AS "attackId",
              ds.name,
              COUNT(DISTINCT tech.id)::int AS "techniquesCovered"
       FROM tech
       JOIN technique_data_components tdc ON tdc.technique_id = tech.id
       JOIN data_components dc ON dc.id = tdc.data_component_id
       JOIN data_sources ds ON ds.id = dc.data_source_id
       GROUP BY ds.attack_id, ds.name
       ORDER BY COUNT(DISTINCT tech.id) DESC, ds.name ASC`,
      [tacticId],
    ),
  ]);

  return withCors(jsonResponse({
    ...tactic,
    techniques: techniquesResult.rows,
    dataSources: dataSourcesResult.rows,
  }, 3600));
}
