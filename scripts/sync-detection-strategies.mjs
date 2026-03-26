#!/usr/bin/env node
/**
 * Extract detection strategies + analytics from ATT&CK STIX bundle.
 * Also re-syncs D3FEND defensive mappings.
 *
 * Usage: DATABASE_URL=... node scripts/sync-detection-strategies.mjs
 */

import pg from 'pg';
import fs from 'fs';

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) { console.error('DATABASE_URL required'); process.exit(1); }

const isProduction = DATABASE_URL.includes('neon') || DATABASE_URL.includes('vercel');
const pool = new pg.Pool({
  connectionString: DATABASE_URL,
  ssl: isProduction ? { rejectUnauthorized: true } : undefined,
});

const STIX_PATH = 'data/enterprise-attack.json';

async function main() {
  if (!fs.existsSync(STIX_PATH)) {
    console.error(`STIX file not found: ${STIX_PATH}. Run seed.py --update first.`);
    process.exit(1);
  }

  console.log('Loading ATT&CK STIX bundle...');
  const stix = JSON.parse(fs.readFileSync(STIX_PATH, 'utf8'));
  const objects = stix.objects;

  // Build technique UUID lookup
  const techResult = await pool.query('SELECT id, attack_id FROM techniques WHERE is_revoked = false');
  const techMap = new Map();
  for (const row of techResult.rows) techMap.set(row.attack_id, row.id);
  console.log(`Loaded ${techMap.size} techniques`);

  // ── Detection Strategies ──────────────────────────────────────────────────
  console.log('\n[Detection Strategies]');

  const detStrategies = objects.filter(o => o.type === 'x-mitre-detection-strategy' && !o.x_mitre_deprecated);
  const analytics = {};
  for (const o of objects) {
    if (o.type === 'x-mitre-analytic' && !o.x_mitre_deprecated) {
      const extId = o.external_references?.find(r => r.source_name === 'mitre-attack')?.external_id;
      if (extId) analytics[o.id] = { ...o, extId };
    }
  }

  // Find detection_strategy -> technique relationships
  const detRels = objects.filter(o =>
    o.type === 'relationship' &&
    o.relationship_type === 'detects' &&
    o.source_ref?.startsWith('x-mitre-detection-strategy')
  );

  console.log(`  Strategies: ${detStrategies.length}, Analytics: ${Object.keys(analytics).length}, Relationships: ${detRels.length}`);

  // Build technique attack-pattern STIX ID -> attack_id map
  const apMap = new Map();
  for (const o of objects) {
    if (o.type === 'attack-pattern') {
      const extId = o.external_references?.find(r => r.source_name === 'mitre-attack')?.external_id;
      if (extId) apMap.set(o.id, extId);
    }
  }

  const client = await pool.connect();
  let dsInserted = 0, anInserted = 0;

  try {
    // Clear old data
    await client.query('DELETE FROM detection_analytics');
    await client.query('DELETE FROM detection_strategies');

    // Insert detection strategies
    for (const rel of detRels) {
      const ds = detStrategies.find(d => d.id === rel.source_ref);
      if (!ds) continue;

      const detId = ds.external_references?.find(r => r.source_name === 'mitre-attack')?.external_id;
      const attackId = apMap.get(rel.target_ref);
      if (!detId || !attackId) continue;

      const techUuid = techMap.get(attackId) ?? null;
      const domain = ds.x_mitre_domains?.[0] ?? 'enterprise-attack';

      try {
        await client.query(
          `INSERT INTO detection_strategies (det_id, name, technique_id, attack_technique_id, domain)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (det_id, attack_technique_id) DO NOTHING`,
          [detId, ds.name, techUuid, attackId, domain]
        );
        dsInserted++;
      } catch { /* skip */ }

      // Insert analytics for this strategy
      const analyticRefs = ds.x_mitre_analytic_refs ?? [];
      for (const anRef of analyticRefs) {
        const an = analytics[anRef];
        if (!an) continue;

        try {
          await client.query(
            `INSERT INTO detection_analytics (analytic_id, name, description, platforms, det_id, domain)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (analytic_id) DO NOTHING`,
            [an.extId, an.name, an.description ?? null, an.x_mitre_platforms ?? [], detId, domain]
          );
          anInserted++;
        } catch { /* skip */ }
      }
    }
  } finally {
    client.release();
  }

  console.log(`  Strategies inserted: ${dsInserted}`);
  console.log(`  Analytics inserted: ${anInserted}`);

  // ── D3FEND ────────────────────────────────────────────────────────────────
  console.log('\n[D3FEND]');

  const D3FEND_URL = 'https://d3fend.mitre.org/api/offensive-technique/attack/';

  // Fetch D3FEND mappings for each technique
  let d3Inserted = 0;
  const d3Client = await pool.connect();
  try {
    await d3Client.query('DELETE FROM defensive_mappings');

    // Batch: get all technique attack_ids, then fetch D3FEND for each
    const techIds = [...techMap.keys()].filter(id => id.startsWith('T'));
    console.log(`  Fetching D3FEND for ${techIds.length} techniques...`);

    for (let i = 0; i < techIds.length; i += 50) {
      const batch = techIds.slice(i, i + 50);
      for (const tid of batch) {
        try {
          const resp = await fetch(`${D3FEND_URL}${tid}.json`);
          if (!resp.ok) continue;
          const d3data = await resp.json();

          const bindings = d3data?.results?.bindings ?? [];
          for (const b of bindings) {
            const d3fendId = b.def_tech_label?.value ?? null;
            const d3fendName = b.def_tech_label?.value ?? null;
            const d3fendTactic = b.def_tactic_label?.value ?? null;
            const d3fendUrl = b.def_tech?.value ?? null;
            const relationship = b.def_tech_parent_is_toplevel?.value === 'true' ? 'counters' : 'related';

            if (!d3fendId) continue;

            try {
              await d3Client.query(
                `INSERT INTO defensive_mappings (technique_id, attack_technique_id, d3fend_id, d3fend_name, d3fend_tactic, relationship, d3fend_url)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)
                 ON CONFLICT DO NOTHING`,
                [techMap.get(tid) ?? null, tid, d3fendId, d3fendName, d3fendTactic, relationship, d3fendUrl]
              );
              d3Inserted++;
            } catch { /* skip */ }
          }
        } catch { /* skip technique */ }
      }
      if (i % 100 === 0) process.stdout.write(`  ${i}/${techIds.length}\r`);
    }
  } finally {
    d3Client.release();
  }

  console.log(`  D3FEND mappings inserted: ${d3Inserted}`);

  await pool.end();
  console.log('\nDone.');
}

main().catch(err => { console.error(err); process.exit(1); });
