#!/usr/bin/env node
/**
 * Sync CAPEC bridge: CWE → CAPEC → ATT&CK technique.
 * Downloads STIX CAPEC bundle and populates capec_mappings table.
 *
 * Usage: DATABASE_URL=... node scripts/sync-capec-bridge.mjs
 */

import pg from 'pg';

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) { console.error('DATABASE_URL required'); process.exit(1); }

const isProduction = DATABASE_URL.includes('neon') || DATABASE_URL.includes('vercel');
const pool = new pg.Pool({
  connectionString: DATABASE_URL,
  ssl: isProduction ? { rejectUnauthorized: true } : undefined,
});

const CAPEC_URL = 'https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json';

async function main() {
  console.log('Downloading CAPEC STIX bundle...');
  const res = await fetch(CAPEC_URL);
  if (!res.ok) { console.error(`Failed: ${res.status}`); process.exit(1); }
  const data = await res.json();

  const capecs = data.objects.filter(o => o.type === 'attack-pattern');
  console.log(`Loaded ${capecs.length} CAPEC patterns`);

  // Build technique UUID lookup
  const techResult = await pool.query('SELECT id, attack_id FROM techniques WHERE is_revoked = false');
  const techMap = new Map();
  for (const row of techResult.rows) techMap.set(row.attack_id, row.id);
  console.log(`Loaded ${techMap.size} techniques for FK resolution`);

  // Parse CAPEC → rows
  const rows = [];
  for (const ap of capecs) {
    const refs = ap.external_references ?? [];
    let capecId = null;
    const cwes = [];
    const techniques = [];

    for (const ref of refs) {
      if (ref.source_name === 'capec') capecId = ref.external_id;
      else if (ref.source_name === 'cwe') cwes.push(ref.external_id);
      else if (ref.source_name === 'ATTACK' && ref.external_id?.startsWith('T'))
        techniques.push(ref.external_id);
    }
    if (!capecId || cwes.length === 0) continue;

    const name = ap.name ?? null;
    const desc = ap.description ? ap.description.slice(0, 500) : null;

    if (techniques.length === 0) {
      // Store CWE→CAPEC without technique (for completeness)
      for (const cwe of cwes)
        rows.push([capecId, name, desc, cwe, null, null]);
    } else {
      for (const cwe of cwes)
        for (const tech of techniques)
          rows.push([capecId, name, desc, cwe, tech, techMap.get(tech) ?? null]);
    }
  }

  console.log(`Generated ${rows.length} mappings`);

  if (rows.length < 100) {
    console.error(`Only ${rows.length} mappings generated — expected 1000+. Aborting to prevent data loss.`);
    process.exit(1);
  }

  // Clear + insert
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM capec_mappings');

    for (let i = 0; i < rows.length; i += 50) {
      const batch = rows.slice(i, i + 50);
      const values = [];
      const params = [];
      for (const r of batch) {
        const o = params.length;
        values.push(`($${o+1},$${o+2},$${o+3},$${o+4},$${o+5},$${o+6})`);
        params.push(...r);
      }
      await client.query(
        `INSERT INTO capec_mappings (capec_id, capec_name, capec_description, cwe_id, attack_technique_id, technique_id)
         VALUES ${values.join(',')} ON CONFLICT DO NOTHING`,
        params,
      );
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }

  // Stats
  const s = (await pool.query(`
    SELECT COUNT(*) AS total,
      COUNT(DISTINCT capec_id) AS capecs,
      COUNT(DISTINCT cwe_id) AS cwes,
      COUNT(DISTINCT attack_technique_id) FILTER (WHERE attack_technique_id IS NOT NULL) AS techniques,
      COUNT(*) FILTER (WHERE technique_id IS NOT NULL) AS with_fk
    FROM capec_mappings
  `)).rows[0];

  console.log(`\nResults:`);
  console.log(`  Total mappings:    ${s.total}`);
  console.log(`  Unique CAPECs:     ${s.capecs}`);
  console.log(`  Unique CWEs:       ${s.cwes}`);
  console.log(`  Unique techniques: ${s.techniques}`);
  console.log(`  With technique FK: ${s.with_fk}`);

  await pool.end();
}

main().catch(e => { console.error(e); process.exit(1); });
