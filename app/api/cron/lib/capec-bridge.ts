/**
 * CWE → ATT&CK technique bridge via CAPEC STIX data.
 * Downloads CAPEC once per process lifecycle, builds a static lookup,
 * then links CVE IOCs to techniques based on their CWE weakness type.
 */

import { query } from '../../v1/lib/db';
import { getParentId } from '../../v1/lib/getParentId';
import { CATCHALL_CWE_THRESHOLD } from '../../v1/lib/inference';

const CAPEC_STIX_URL =
  'https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json';

interface CapecStixObject {
  type: string;
  external_references?: Array<{
    source_name: string;
    external_id?: string;
  }>;
}

let cweToTechniques: Map<string, Set<string>> | null = null;

/** Download and parse CAPEC STIX, build CWE→technique lookup. Cached in memory. */
async function loadBridge(): Promise<Map<string, Set<string>>> {
  if (cweToTechniques) return cweToTechniques;

  const resp = await fetch(CAPEC_STIX_URL);
  if (!resp.ok) throw new Error(`CAPEC fetch failed: ${resp.status}`);
  const stix = (await resp.json()) as { objects: CapecStixObject[] };

  const result = new Map<string, Set<string>>();
  for (const obj of stix.objects) {
    if (obj.type !== 'attack-pattern') continue;
    const refs = obj.external_references ?? [];
    const attackIds: string[] = [];
    const cwes: string[] = [];
    for (const ref of refs) {
      if (ref.source_name === 'ATTACK' && ref.external_id) attackIds.push(ref.external_id);
      if (ref.source_name === 'cwe' && ref.external_id) cwes.push(ref.external_id);
    }
    if (cwes.length === 0 || attackIds.length === 0) continue;
    for (const cwe of cwes) {
      if (!result.has(cwe)) result.set(cwe, new Set());
      for (const tid of attackIds) {
        result.get(cwe)!.add(getParentId(tid)); // normalize to parent
      }
    }
  }
  // Drop catch-all CWEs (those mapping to more than CATCHALL_CWE_THRESHOLD
  // distinct techniques). Generic CWEs like CWE-200 / CWE-284 otherwise fan
  // every CVE that carries them out across dozens of unrelated techniques —
  // here that fan-out would leak back through the 'ioc' source via
  // technique_iocs. Mirrors the SQL exclusion in app/api/v1/lib/inference.ts.
  for (const [cwe, techs] of result) {
    if (techs.size > CATCHALL_CWE_THRESHOLD) result.delete(cwe);
  }

  // Only cache after successful full parse
  cweToTechniques = result;
  return cweToTechniques;
}

/**
 * Link CVE IOCs to techniques via CWE→CAPEC→ATT&CK bridge.
 * Call after NVD enrichment assigns CWE IDs, or after CISA KEV ingest.
 * Returns count of new technique links created.
 */
export async function linkCveTechniquesViaCwe(): Promise<number> {
  const bridge = await loadBridge();

  // Load technique UUID lookup
  const techResult = await query<{ id: string; attack_id: string }>(
    `SELECT id, attack_id FROM techniques WHERE is_revoked = false AND is_deprecated = false`,
  );
  const techMap = new Map<string, string>();
  for (const row of techResult.rows) techMap.set(row.attack_id, row.id);

  // Find CVE IOCs with CWE IDs that don't yet have technique links
  const cveResult = await query<{ ioc_id: string; cwe_id: string }>(
    `SELECT i.id AS ioc_id, cd.cwe_id
     FROM cve_details cd
     JOIN ioc_entries i ON i.value = cd.cve_id AND i.type = 'cve'
     WHERE cd.cwe_id IS NOT NULL AND cd.cwe_id != ''
       AND NOT EXISTS (
         SELECT 1 FROM technique_iocs ti WHERE ti.ioc_id = i.id
       )`,
  );

  // Collect all (techId, iocId) pairs, then batch insert
  const techIds: string[] = [];
  const iocIds: string[] = [];
  for (const cve of cveResult.rows) {
    const techniques = bridge.get(cve.cwe_id);
    if (!techniques) continue;
    for (const tid of techniques) {
      const techId = techMap.get(tid);
      if (!techId) continue;
      techIds.push(techId);
      iocIds.push(cve.ioc_id);
    }
  }

  if (techIds.length === 0) return 0;

  const result = await query(
    `INSERT INTO technique_iocs (technique_id, ioc_id, confidence)
     SELECT unnest($1::uuid[]), unnest($2::uuid[]), 'inferred'
     ON CONFLICT DO NOTHING`,
    [techIds, iocIds],
  );
  return result.rowCount ?? 0;
}
