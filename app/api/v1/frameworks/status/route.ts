import { NextRequest } from 'next/server';
import { query } from '../../lib/db';
import { jsonResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';
import { ECOSYSTEM_BY_CANONICAL } from '../../../../../src/lib/ecosystems';

export { OPTIONS };

// Approximate-count strategy: each COUNT(*) on a big table (cve_details ~26k,
// osv_affected ~500k, sigma_rules ~3k, affected_products ~100k, nist_controls
// ~5k) was a full seq scan — the union ran in ~10s. pg_class.reltuples is
// autovacuum-maintained and returns in <50ms regardless of table size.
// ±1% accuracy is fine for a dashboard row-count indicator. Tables that don't
// exist in the environment simply don't come back from pg_class — no need for
// per-group try/catch fallbacks.
const ESTIMATED_TABLES = [
  'owasp_top10', 'nist_controls', 'engage_mappings', 'defensive_mappings',
  'detection_strategies', 'detection_analytics', 'react_actions', 'veris_mappings',
  'cloud_control_mappings', 'sigma_rules', 'atomic_tests', 'external_actors',
  'applications', 'capec_mappings', 'cve_details', 'cve_weaknesses',
  'affected_products', 'atlas_xrefs',
  'csf_subcategories', 'csf_technique_mappings',
  'csf_implementation_examples', 'csf_informative_references',
  'capec_patterns', 'capec_mitigations',
  'ghsa_advisories', 'ghsa_weaknesses', 'ghsa_packages', 'packages',
  'osv_advisories', 'osv_affected',
];

export async function GET(_req: NextRequest) {
  const counts: Record<string, number> = Object.fromEntries(
    ESTIMATED_TABLES.map((t) => [t, 0]),
  );

  const estimates = await query<{ tbl: string; count: string }>(
    `SELECT relname AS tbl, GREATEST(reltuples::bigint, 0)::text AS count
     FROM pg_class
     WHERE relname = ANY($1::text[])
       AND relkind IN ('r', 'm')`,
    [ESTIMATED_TABLES],
  );
  for (const row of estimates.rows) {
    counts[row.tbl] = parseInt(row.count, 10);
  }

  // CTID direct mappings need a filtered COUNT — reltuples can't do WHERE.
  // capec_mappings is small (~2k rows), so this stays fast.
  try {
    const ctid = await query<{ count: string }>(
      `SELECT COUNT(*)::text AS count FROM capec_mappings WHERE capec_id = 'CTID-DIRECT'`,
    );
    counts.ctid_mappings = parseInt(ctid.rows[0]?.count ?? '0', 10);
  } catch {
    counts.ctid_mappings = 0;
  }

  // Ecosystem registry drift — compare distinct DB ecosystems to the registry
  // at src/lib/ecosystems.ts. Needs actual names, not counts, so stays exact.
  let ecosystemDrift: { registered: number; inDb: number; unknown: string[] } = {
    registered: ECOSYSTEM_BY_CANONICAL.size,
    inDb: 0,
    unknown: [],
  };
  try {
    const ecoRes = await query<{ ecosystem: string }>(
      `SELECT DISTINCT ecosystem FROM osv_advisories
       UNION
       SELECT DISTINCT LOWER(ecosystem) FROM packages`,
    );
    const dbEcos = ecoRes.rows.map((r) => r.ecosystem).filter(Boolean);
    const unknown = dbEcos.filter((e) => !ECOSYSTEM_BY_CANONICAL.has(e));
    ecosystemDrift = {
      registered: ECOSYSTEM_BY_CANONICAL.size,
      inDb: dbEcos.length,
      unknown,
    };
  } catch {
    // pre-migration env; leave defaults
  }

  return withCors(jsonResponse({ counts, ecosystemDrift }, 900));
}
