import { NextRequest } from 'next/server';
import { query } from '../../../lib/db';
import { jsonResponse, errorResponse } from '../../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../../lib/cors';
import { FAIR_CAM_SOURCE, FAIR_CAM_ATTRIBUTION } from '../../../../../../src/lib/fair-cam.mjs';
import { classifyCoverageRow } from '../../../../../../src/lib/fair-cam-mappings.mjs';

export { OPTIONS };

const CACHE_TTL = 3600;
const DOMAINS = new Set(['enterprise-attack', 'ics-attack', 'mobile-attack', 'atlas-attack']);

/**
 * GET /api/v1/frameworks/fair-cam/coverage[?domain=enterprise-attack]
 *
 * Every live technique with its candidate controls sorted into FAIR-CAM
 * functions — this site's classification (src/lib/fair-cam-mappings.mjs) of
 * ATT&CK mitigations and D3FEND countermeasures, plus counts of the sources
 * that are not controls (data components, detection strategies, Sigma rules).
 *
 * ONE response for all techniques, on purpose: the technique 360 card, the
 * threat-profile panel and the group panel all read it, so they cannot
 * disagree, there is one CDN cache key instead of one per technique list, and
 * the classification tables never ship to the browser. ~300 KB raw, ~30 KB
 * gzipped; measured at 200–300 ms on production (2026-10-09).
 *
 * ROLL-UP: a parent technique includes its live sub-techniques for every
 * signal; a sub-technique counts only itself. Revoked/deprecated techniques and
 * mitigations, D3FEND rows whose id is not a D3FEND id, and Sigma rules marked
 * deprecated/unsupported are excluded.
 *
 * Availability, never efficacy: FAIR-CAM measures controls per organisation;
 * this lists which candidate controls exist in public knowledge bases.
 */
const COVERAGE_SQL = `
WITH req AS (
  SELECT t.id, t.attack_id, t.name, t.domain
  FROM techniques t
  WHERE NOT t.is_revoked AND NOT t.is_deprecated
    AND ($1::text IS NULL OR t.domain = $1)
),
scope AS (
  SELECT r.id AS req_id, r.id AS src_id, r.attack_id AS src_attack_id FROM req r
  UNION ALL
  SELECT r.id, c.id, c.attack_id
  FROM req r JOIN techniques c ON c.parent_technique_id = r.id
  WHERE NOT c.is_revoked AND NOT c.is_deprecated
),
mit AS (
  SELECT s.req_id, array_agg(DISTINCT m.attack_id ORDER BY m.attack_id) AS ids
  FROM scope s
  JOIN mitigation_techniques mt ON mt.technique_id = s.src_id
  JOIN mitigations m ON m.id = mt.mitigation_id AND NOT m.is_revoked AND NOT m.is_deprecated
  GROUP BY s.req_id
),
d3f AS (
  SELECT s.req_id,
         array_agg(DISTINCT dm.d3fend_id || '|' || COALESCE(dm.d3fend_tactic, '')
                   ORDER BY dm.d3fend_id || '|' || COALESCE(dm.d3fend_tactic, '')) AS ids
  FROM scope s
  JOIN defensive_mappings dm ON dm.technique_id = s.src_id AND dm.d3fend_id ~ '^D3-'
  GROUP BY s.req_id
),
dc AS (
  SELECT s.req_id, count(DISTINCT tdc.data_component_id)::int AS n
  FROM scope s JOIN technique_data_components tdc ON tdc.technique_id = s.src_id
  GROUP BY s.req_id
),
ds AS (
  SELECT s.req_id, count(DISTINCT d.det_id)::int AS n
  FROM scope s JOIN detection_strategies d ON d.attack_technique_id = s.src_attack_id
  GROUP BY s.req_id
),
sg AS (
  SELECT s.req_id, count(DISTINCT sr.id)::int AS n
  FROM scope s
  JOIN sigma_rules sr ON sr.technique_id = s.src_id AND COALESCE(sr.status, '') NOT IN ('deprecated', 'unsupported')
  GROUP BY s.req_id
)
SELECT r.attack_id AS "attackId", r.name, r.domain,
       COALESCE(mit.ids, '{}') AS mitigations,
       COALESCE(d3f.ids, '{}') AS d3fend,
       COALESCE(dc.n, 0) AS "dataComponents",
       COALESCE(ds.n, 0) AS "detectionStrategies",
       COALESCE(sg.n, 0) AS "sigmaRules"
FROM req r
LEFT JOIN mit ON mit.req_id = r.id
LEFT JOIN d3f ON d3f.req_id = r.id
LEFT JOIN dc  ON dc.req_id  = r.id
LEFT JOIN ds  ON ds.req_id  = r.id
LEFT JOIN sg  ON sg.req_id  = r.id
ORDER BY r.attack_id`;

interface Raw {
  attackId: string;
  name: string;
  domain: string | null;
  mitigations: string[];
  d3fend: string[];
  dataComponents: number;
  detectionStrategies: number;
  sigmaRules: number;
}

export async function GET(req: NextRequest) {
  const domain = req.nextUrl.searchParams.get('domain');
  if (domain !== null && !DOMAINS.has(domain)) {
    return withCors(errorResponse(400, 'Invalid domain', 'VALIDATION_ERROR'));
  }

  const [rows, mitNames, d3Names] = await Promise.all([
    query<Raw>(COVERAGE_SQL, [domain]),
    query<{ id: string; name: string }>('SELECT attack_id AS id, name FROM mitigations WHERE NOT is_revoked AND NOT is_deprecated'),
    query<{ id: string; name: string | null }>(
      `SELECT d3fend_id AS id, MIN(d3fend_name) AS name FROM defensive_mappings WHERE d3fend_id ~ '^D3-' GROUP BY d3fend_id`,
    ),
  ]);

  const techniques = rows.rows.map((r) => ({
    attackId: r.attackId,
    name: r.name,
    domain: r.domain,
    ...classifyCoverageRow(r),
  }));

  const used = new Set(techniques.flatMap((t) => Object.values(t.functions).flat()));
  const controls: Record<string, { name: string; kind: 'mitigation' | 'd3fend' }> = {};
  for (const m of mitNames.rows) if (used.has(m.id)) controls[m.id] = { name: m.name, kind: 'mitigation' };
  for (const d of d3Names.rows) if (used.has(d.id)) controls[d.id] = { name: d.name ?? d.id, kind: 'd3fend' };

  return withCors(
    jsonResponse(
      {
        rollup: 'subtechniques',
        attribution: FAIR_CAM_ATTRIBUTION,
        source: { name: FAIR_CAM_SOURCE.name, version: FAIR_CAM_SOURCE.version, licence: FAIR_CAM_SOURCE.licenceShort, licenceUrl: FAIR_CAM_SOURCE.licenceUrl, referenceUrl: FAIR_CAM_SOURCE.referenceUrl },
        curation: 'Classification of ATT&CK mitigations and D3FEND countermeasures into FAIR-CAM functions is this site’s, not the FAIR Institute’s. Availability of candidate controls only — not efficacy.',
        total: techniques.length,
        defaultRuleIds: [...new Set(techniques.flatMap((t) => t.defaultRule))].sort(),
        unmappedIds: [...new Set(techniques.flatMap((t) => t.unmapped))].sort(),
        controls,
        techniques,
      },
      CACHE_TTL,
    ),
  );
}
