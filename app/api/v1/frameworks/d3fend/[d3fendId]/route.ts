import { NextRequest } from 'next/server';
import { query } from '../../../lib/db';
import { jsonResponse, errorResponse } from '../../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../../lib/cors';

export { OPTIONS };

const CACHE_TTL = 3600;
// All 153 ids in production match this exactly (D3-NTSA, D3-PMAD, D3-RH).
const D3FEND_ID_RE = /^D3-[A-Z]{1,12}$/;

/**
 * GET /api/v1/frameworks/d3fend/:d3fendId
 *
 * One countermeasure: what it is, and every ATT&CK technique it counters,
 * grouped so the ICS techniques are distinguishable from Enterprise ones.
 */
export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ d3fendId: string }> },
) {
  const { d3fendId: raw } = await params;
  const d3fendId = raw.toUpperCase();

  if (!D3FEND_ID_RE.test(d3fendId)) {
    return withCors(errorResponse(400, 'Invalid D3FEND ID', 'VALIDATION_ERROR'));
  }

  const cmResult = await query<{
    d3fendId: string;
    d3fendName: string | null;
    d3fendTactic: string | null;
    d3fendUrl: string | null;
  }>(
    `SELECT
       d3fend_id     AS "d3fendId",
       MIN(d3fend_name)   AS "d3fendName",
       MIN(d3fend_tactic) AS "d3fendTactic",
       MIN(d3fend_url)    AS "d3fendUrl"
     FROM defensive_mappings
     WHERE d3fend_id = $1
     GROUP BY d3fend_id`,
    [d3fendId],
  );

  if (cmResult.rows.length === 0) {
    return withCors(errorResponse(404, 'Countermeasure not found', 'NOT_FOUND'));
  }

  const [techniquesResult, relatedResult] = await Promise.all([
    query<{
      attackId: string;
      name: string | null;
      domain: string | null;
      tacticName: string | null;
      isSubtechnique: boolean | null;
    }>(
      `SELECT
         d.attack_technique_id AS "attackId",
         MAX(t.name)           AS "name",
         MAX(t.domain)         AS "domain",
         MIN(tac.name)         AS "tacticName",
         BOOL_OR(t.is_subtechnique) AS "isSubtechnique"
       FROM defensive_mappings d
       LEFT JOIN techniques t         ON t.id = d.technique_id
       LEFT JOIN technique_tactics tt ON tt.technique_id = t.id
       LEFT JOIN tactics tac          ON tac.id = tt.tactic_id
       WHERE d.d3fend_id = $1
       GROUP BY d.attack_technique_id
       ORDER BY d.attack_technique_id`,
      [d3fendId],
    ),

    // Countermeasures that defend the same techniques -- the practical
    // question being "what else covers this ground".
    query<{ d3fendId: string; d3fendName: string | null; d3fendTactic: string | null; sharedCount: string }>(
      `SELECT
         o.d3fend_id          AS "d3fendId",
         MIN(o.d3fend_name)   AS "d3fendName",
         MIN(o.d3fend_tactic) AS "d3fendTactic",
         COUNT(DISTINCT o.attack_technique_id) AS "sharedCount"
       FROM defensive_mappings o
       WHERE o.d3fend_id <> $1
         AND o.attack_technique_id IN (
           SELECT attack_technique_id FROM defensive_mappings WHERE d3fend_id = $1
         )
       GROUP BY o.d3fend_id
       ORDER BY COUNT(DISTINCT o.attack_technique_id) DESC, o.d3fend_id
       LIMIT 8`,
      [d3fendId],
    ),
  ]);

  const techniques = techniquesResult.rows;
  const byDomain: Record<string, number> = {};
  for (const t of techniques) {
    const d = t.domain ?? 'unknown';
    byDomain[d] = (byDomain[d] ?? 0) + 1;
  }

  return withCors(
    jsonResponse(
      {
        countermeasure: cmResult.rows[0],
        techniqueCount: techniques.length,
        techniquesByDomain: byDomain,
        techniques,
        related: relatedResult.rows.map((r) => ({ ...r, sharedCount: parseInt(r.sharedCount, 10) || 0 })),
      },
      CACHE_TTL,
    ),
  );
}
