import { NextRequest } from 'next/server';
import { query } from '../../lib/db';
import { jsonResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';

export { OPTIONS };

const CACHE_TTL = 3600;

/**
 * D3FEND's seven defensive tactics, in the order MITRE presents its matrix:
 * you model the system, harden it, detect what gets through, isolate it,
 * deceive the adversary, evict them, then restore. Ordering by row count
 * instead would put Detect first and lose that narrative.
 */
export const D3FEND_TACTIC_ORDER = ['Model', 'Harden', 'Detect', 'Isolate', 'Deceive', 'Evict', 'Restore'] as const;

interface CountermeasureRow {
  d3fendId: string;
  d3fendName: string | null;
  d3fendTactic: string;
  d3fendUrl: string | null;
  techniqueCount: string;
  domains: string[];
}

interface CountermeasureItem {
  d3fendId: string;
  d3fendName: string | null;
  d3fendUrl: string | null;
  techniqueCount: number;
  /** ATT&CK domains this countermeasure reaches, e.g. ['enterprise-attack', 'ics-attack']. */
  domains: string[];
}

interface TacticGroup {
  tactic: string;
  countermeasureCount: number;
  techniqueCount: number;
  countermeasures: CountermeasureItem[];
}

/**
 * GET /api/v1/frameworks/d3fend
 *
 * Every D3FEND countermeasure grouped by defensive tactic, with the number of
 * ATT&CK techniques each one counters. The whole taxonomy is ~153 rows, so it
 * ships in one response and the view filters in memory -- same shape as
 * /api/v1/frameworks/csf rather than the paginated /react route.
 */
export async function GET(_req: NextRequest) {
  const result = await query<CountermeasureRow>(
    `SELECT
       d.d3fend_id                          AS "d3fendId",
       MIN(d.d3fend_name)                   AS "d3fendName",
       d.d3fend_tactic                      AS "d3fendTactic",
       MIN(d.d3fend_url)                    AS "d3fendUrl",
       COUNT(DISTINCT d.attack_technique_id) AS "techniqueCount",
       COALESCE(
         ARRAY_AGG(DISTINCT t.domain) FILTER (WHERE t.domain IS NOT NULL),
         '{}'
       )                                    AS domains
     FROM defensive_mappings d
     LEFT JOIN techniques t ON t.id = d.technique_id
     WHERE d.d3fend_tactic IS NOT NULL
     GROUP BY d.d3fend_id, d.d3fend_tactic
     ORDER BY d.d3fend_tactic, d.d3fend_id`,
  );

  const groups = new Map<string, TacticGroup>();
  for (const r of result.rows) {
    let g = groups.get(r.d3fendTactic);
    if (!g) {
      g = { tactic: r.d3fendTactic, countermeasureCount: 0, techniqueCount: 0, countermeasures: [] };
      groups.set(r.d3fendTactic, g);
    }
    const techniqueCount = parseInt(r.techniqueCount, 10) || 0;
    g.countermeasures.push({
      d3fendId: r.d3fendId,
      d3fendName: r.d3fendName,
      d3fendUrl: r.d3fendUrl,
      techniqueCount,
      domains: r.domains ?? [],
    });
    g.countermeasureCount++;
    g.techniqueCount += techniqueCount;
  }

  // Known tactics first in matrix order, then anything D3FEND adds later, so a
  // new tactic surfaces instead of being silently dropped by the ordering.
  const known = D3FEND_TACTIC_ORDER.filter((t) => groups.has(t)).map((t) => groups.get(t)!);
  const extra = [...groups.values()]
    .filter((g) => !(D3FEND_TACTIC_ORDER as readonly string[]).includes(g.tactic))
    .sort((a, b) => a.tactic.localeCompare(b.tactic));

  return withCors(
    jsonResponse(
      {
        data: [...known, ...extra],
        total: result.rows.length,
        meta: {
          countermeasures: result.rows.length,
          tactics: groups.size,
          // D3FEND only maps Enterprise and ICS ATT&CK; Mobile and ATLAS have
          // no countermeasures upstream, so their absence here is not a gap.
          coveredDomains: ['enterprise-attack', 'ics-attack'],
        },
      },
      CACHE_TTL,
    ),
  );
}
