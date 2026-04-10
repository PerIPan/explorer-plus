import { NextRequest } from 'next/server';
import { query } from '../../lib/db';
import { jsonResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';

export { OPTIONS };

export async function GET(_req: NextRequest) {
  // Core query over tables guaranteed to exist in all environments
  const result = await query<{ tbl: string; count: string }>(`
    SELECT 'owasp_top10' AS tbl, COUNT(*)::text AS count FROM owasp_top10
    UNION ALL SELECT 'nist_controls', COUNT(*)::text FROM nist_controls
    UNION ALL SELECT 'engage_mappings', COUNT(*)::text FROM engage_mappings
    UNION ALL SELECT 'defensive_mappings', COUNT(*)::text FROM defensive_mappings
    UNION ALL SELECT 'detection_strategies', COUNT(*)::text FROM detection_strategies
    UNION ALL SELECT 'detection_analytics', COUNT(*)::text FROM detection_analytics
    UNION ALL SELECT 'react_actions', COUNT(*)::text FROM react_actions
    UNION ALL SELECT 'veris_mappings', COUNT(*)::text FROM veris_mappings
    UNION ALL SELECT 'cloud_control_mappings', COUNT(*)::text FROM cloud_control_mappings
    UNION ALL SELECT 'sigma_rules', COUNT(*)::text FROM sigma_rules
    UNION ALL SELECT 'atomic_tests', COUNT(*)::text FROM atomic_tests
    UNION ALL SELECT 'external_actors', COUNT(*)::text FROM external_actors
    UNION ALL SELECT 'applications', COUNT(*)::text FROM applications
    UNION ALL SELECT 'capec_mappings', COUNT(*)::text FROM capec_mappings
    UNION ALL SELECT 'cve_details', COUNT(*)::text FROM cve_details
    UNION ALL SELECT 'cve_weaknesses', COUNT(*)::text FROM cve_weaknesses
    UNION ALL SELECT 'affected_products', COUNT(*)::text FROM affected_products
    UNION ALL SELECT 'ctid_mappings', COUNT(*)::text FROM capec_mappings WHERE capec_id = 'CTID-DIRECT'
    UNION ALL SELECT 'atlas_xrefs', COUNT(*)::text FROM atlas_xrefs
    UNION ALL SELECT 'csf_subcategories', COUNT(*)::text FROM csf_subcategories
    UNION ALL SELECT 'csf_technique_mappings', COUNT(*)::text FROM csf_technique_mappings
  `);

  const counts: Record<string, number> = {};
  for (const row of result.rows) {
    counts[row.tbl] = parseInt(row.count, 10);
  }

  // Enrichment tables — may not exist on unmigrated environments, degrade to 0
  try {
    const enrich = await query<{ tbl: string; count: string }>(`
      SELECT 'csf_implementation_examples' AS tbl, COUNT(*)::text AS count FROM csf_implementation_examples
      UNION ALL SELECT 'csf_informative_references', COUNT(*)::text FROM csf_informative_references
    `);
    for (const row of enrich.rows) {
      counts[row.tbl] = parseInt(row.count, 10);
    }
  } catch {
    counts.csf_implementation_examples = 0;
    counts.csf_informative_references = 0;
  }

  return withCors(jsonResponse({ counts }, 300));
}
