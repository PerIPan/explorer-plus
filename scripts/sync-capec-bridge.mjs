#!/usr/bin/env node
/**
 * Build CWE → ATT&CK technique bridge via CAPEC STIX data.
 * Links CISA KEV CVEs (which have CWE IDs from NVD) to ATT&CK techniques.
 *
 * Usage: DATABASE_URL=... node scripts/sync-capec-bridge.mjs
 */

import pg from 'pg';

const CAPEC_STIX_URL =
  'https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json';

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error('DATABASE_URL required');
  process.exit(1);
}

const isProduction = DATABASE_URL.includes('neon') || DATABASE_URL.includes('vercel');
const pool = new pg.Pool({
  connectionString: DATABASE_URL,
  ssl: isProduction ? { rejectUnauthorized: true } : undefined,
});

async function main() {
  console.log('Fetching CAPEC STIX bundle...');
  const resp = await fetch(CAPEC_STIX_URL);
  if (!resp.ok) throw new Error(`CAPEC fetch failed: ${resp.status}`);
  const stix = await resp.json();

  // Build CWE → ATT&CK technique ID mapping from CAPEC attack-patterns
  const cweToTechniques = new Map();
  let capecWithAttack = 0;

  for (const obj of stix.objects) {
    if (obj.type !== 'attack-pattern') continue;
    const refs = obj.external_references || [];

    const attackIds = [];
    const cwes = [];
    for (const ref of refs) {
      if (ref.source_name === 'ATTACK' && ref.external_id) {
        attackIds.push(ref.external_id);
      }
      if (ref.source_name === 'cwe' && ref.external_id) {
        cwes.push(ref.external_id);
      }
    }

    if (attackIds.length > 0) capecWithAttack++;
    if (cwes.length === 0 || attackIds.length === 0) continue;

    for (const cwe of cwes) {
      if (!cweToTechniques.has(cwe)) cweToTechniques.set(cwe, new Set());
      for (const tid of attackIds) {
        // Normalize to parent technique (T1059.001 → T1059)
        cweToTechniques.get(cwe).add(tid.split('.')[0]);
      }
    }
  }

  console.log(`CAPEC patterns with ATT&CK refs: ${capecWithAttack}`);
  console.log(`CWEs with technique mapping: ${cweToTechniques.size}`);
  const totalMappings = [...cweToTechniques.values()].reduce((s, v) => s + v.size, 0);
  console.log(`Total CWE→technique mappings: ${totalMappings}`);

  // Load technique UUID lookup from DB
  const techResult = await pool.query(
    `SELECT id, attack_id FROM techniques WHERE is_revoked = false AND is_deprecated = false`
  );
  const techMap = new Map();
  for (const row of techResult.rows) {
    techMap.set(row.attack_id, row.id);
  }
  console.log(`Loaded ${techMap.size} techniques from DB`);

  // Find CVEs with CWE IDs that we can link
  const cveResult = await pool.query(
    `SELECT cd.id, cd.cve_id, cd.cwe_id, i.id as ioc_id
     FROM cve_details cd
     JOIN ioc_entries i ON i.value = cd.cve_id AND i.type = 'cve'
     WHERE cd.cwe_id IS NOT NULL AND cd.cwe_id != ''`
  );
  console.log(`CVEs with CWE IDs: ${cveResult.rows.length}`);

  let linked = 0;
  let skipped = 0;
  let alreadyLinked = 0;

  for (const cve of cveResult.rows) {
    const techniques = cweToTechniques.get(cve.cwe_id);
    if (!techniques) {
      skipped++;
      continue;
    }

    for (const tid of techniques) {
      const techId = techMap.get(tid);
      if (!techId) continue;

      try {
        await pool.query(
          `INSERT INTO technique_iocs (technique_id, ioc_id, confidence)
           VALUES ($1, $2, 'inferred')
           ON CONFLICT DO NOTHING`,
          [techId, cve.ioc_id]
        );
        linked++;
      } catch {
        alreadyLinked++;
      }
    }
  }

  console.log(`\nResults:`);
  console.log(`  Technique links created: ${linked}`);
  console.log(`  CVEs with no CWE→technique mapping: ${skipped}`);
  console.log(`  Already linked (skipped): ${alreadyLinked}`);

  await pool.end();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
