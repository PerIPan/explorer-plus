#!/usr/bin/env node
/**
 * Sync MITRE ATLAS data: tactics, techniques, mitigations, cross-references.
 * Downloads ATLAS.yaml from GitHub, parses with safe YAML, upserts to DB.
 *
 * Usage: DATABASE_URL=... node scripts/sync-atlas.mjs
 */

import pg from 'pg';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const yaml = require('js-yaml');

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) { console.error('DATABASE_URL required'); process.exit(1); }

const isProduction = DATABASE_URL.includes('neon') || DATABASE_URL.includes('vercel');
const pool = new pg.Pool({
  connectionString: DATABASE_URL,
  ssl: isProduction ? { rejectUnauthorized: true } : undefined,
});

const ATLAS_URL = 'https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml';
const DOMAIN = 'atlas-attack';

async function main() {
  // Download ATLAS YAML
  console.log('Downloading ATLAS.yaml...');
  const res = await fetch(ATLAS_URL);
  if (!res.ok) { console.error(`Failed: ${res.status}`); process.exit(1); }
  const text = await res.text();

  // Verify not truncated
  if (text.length < 10000) {
    console.error(`ATLAS YAML too small (${text.length} bytes) — likely truncated`);
    process.exit(1);
  }

  // Parse with safe schema (prevents RCE via !!js/function)
  const data = yaml.load(text, { schema: yaml.DEFAULT_SCHEMA });
  const matrix = data.matrices[0];
  const tactics = matrix.tactics ?? [];
  const techniques = matrix.techniques ?? [];
  const mitigations = matrix.mitigations ?? [];

  console.log(`Parsed: ${tactics.length} tactics, ${techniques.length} techniques, ${mitigations.length} mitigations`);
  console.log(`Version: ${data.version}`);

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // ── Tactics ────────────────────────────────────────────────────────────
    console.log('\n[Tactics]');
    let tacticMap = new Map(); // attack_id → uuid
    for (let i = 0; i < tactics.length; i++) {
      const t = tactics[i];
      const r = await client.query(
        `INSERT INTO tactics (attack_id, name, description, domain, sort_order, url)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (attack_id) DO UPDATE SET
           name = EXCLUDED.name, description = EXCLUDED.description,
           domain = EXCLUDED.domain, sort_order = EXCLUDED.sort_order,
           updated_at = now()
         RETURNING id`,
        [t.id, t.name, t.description ?? null, DOMAIN, i + 1,
         `https://atlas.mitre.org/tactics/${t.id}`],
      );
      tacticMap.set(t.id, r.rows[0].id);
    }
    console.log(`  Upserted ${tacticMap.size} tactics`);

    // ── Techniques ─────────────────────────────────────────────────────────
    console.log('\n[Techniques]');
    const parents = techniques.filter(t => !t.id.match(/\.\d{3}$/));
    const subs = techniques.filter(t => t.id.match(/\.\d{3}$/));
    let techMap = new Map(); // attack_id → uuid

    // Parents first
    for (const t of parents) {
      const r = await client.query(
        `INSERT INTO techniques (attack_id, name, description, domain, is_subtechnique, maturity, url,
           is_revoked, is_deprecated)
         VALUES ($1, $2, $3, $4, false, $5, $6, false, false)
         ON CONFLICT (attack_id) DO UPDATE SET
           name = EXCLUDED.name, description = EXCLUDED.description,
           domain = EXCLUDED.domain, maturity = EXCLUDED.maturity,
           url = EXCLUDED.url, updated_at = now()
         RETURNING id`,
        [t.id, t.name, t.description ?? null, DOMAIN, t.maturity ?? null,
         `https://atlas.mitre.org/techniques/${t.id}`],
      );
      techMap.set(t.id, r.rows[0].id);
    }

    // Sub-techniques
    for (const t of subs) {
      const parentId = t.id.replace(/\.\d{3}$/, '');
      const parentUuid = techMap.get(parentId) ?? null;
      const r = await client.query(
        `INSERT INTO techniques (attack_id, name, description, domain, is_subtechnique,
           parent_technique_id, maturity, url, is_revoked, is_deprecated)
         VALUES ($1, $2, $3, $4, true, $5, $6, $7, false, false)
         ON CONFLICT (attack_id) DO UPDATE SET
           name = EXCLUDED.name, description = EXCLUDED.description,
           domain = EXCLUDED.domain, parent_technique_id = EXCLUDED.parent_technique_id,
           maturity = EXCLUDED.maturity, url = EXCLUDED.url, updated_at = now()
         RETURNING id`,
        [t.id, t.name, t.description ?? null, DOMAIN, parentUuid, t.maturity ?? null,
         `https://atlas.mitre.org/techniques/${t.id}`],
      );
      techMap.set(t.id, r.rows[0].id);
    }
    console.log(`  Upserted ${techMap.size} techniques (${parents.length} parent + ${subs.length} sub)`);

    // ── Technique → Tactic junction ────────────────────────────────────────
    console.log('\n[Technique-Tactic links]');
    let ttLinks = 0;
    for (const t of techniques) {
      const techUuid = techMap.get(t.id);
      if (!techUuid) continue;
      for (const tacticId of (t.tactics ?? [])) {
        const tacticUuid = tacticMap.get(tacticId);
        if (!tacticUuid) continue;
        await client.query(
          `INSERT INTO technique_tactics (technique_id, tactic_id)
           VALUES ($1, $2) ON CONFLICT DO NOTHING`,
          [techUuid, tacticUuid],
        );
        ttLinks++;
      }
    }
    console.log(`  Inserted ${ttLinks} links`);

    // ── Mitigations ────────────────────────────────────────────────────────
    console.log('\n[Mitigations]');
    let mitigMap = new Map();
    for (const m of mitigations) {
      const r = await client.query(
        `INSERT INTO mitigations (attack_id, name, description, domain, url,
           is_revoked, is_deprecated)
         VALUES ($1, $2, $3, $4, $5, false, false)
         ON CONFLICT (attack_id) DO UPDATE SET
           name = EXCLUDED.name, description = EXCLUDED.description,
           domain = EXCLUDED.domain, url = EXCLUDED.url, updated_at = now()
         RETURNING id`,
        [m.id, m.name, m.description ?? null, DOMAIN,
         `https://atlas.mitre.org/mitigations/${m.id}`],
      );
      mitigMap.set(m.id, r.rows[0].id);
    }
    console.log(`  Upserted ${mitigMap.size} mitigations`);

    // ── Mitigation → Technique junction ────────────────────────────────────
    console.log('\n[Mitigation-Technique links]');
    let mtLinks = 0;
    for (const m of mitigations) {
      const mitigUuid = mitigMap.get(m.id);
      if (!mitigUuid) continue;
      for (const link of (m.techniques ?? [])) {
        const techUuid = techMap.get(link.id);
        if (!techUuid) continue;
        await client.query(
          `INSERT INTO mitigation_techniques (mitigation_id, technique_id, description)
           VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
          [mitigUuid, techUuid, link.use ?? null],
        );
        mtLinks++;
      }
    }
    console.log(`  Inserted ${mtLinks} links`);

    // ── ATT&CK Cross-references ────────────────────────────────────────────
    console.log('\n[ATT&CK Cross-references]');
    // Clear old xrefs
    await client.query('DELETE FROM atlas_xrefs');
    let xrefCount = 0;
    for (const t of techniques) {
      const ref = t['ATT&CK-reference'];
      if (!ref?.id) continue;
      const atlasUuid = techMap.get(t.id);
      if (!atlasUuid) continue;
      // Look up ATT&CK technique UUID
      const attackResult = await client.query(
        `SELECT id FROM techniques WHERE attack_id = $1 AND domain != $2 LIMIT 1`,
        [ref.id, DOMAIN],
      );
      if (attackResult.rows.length === 0) continue;
      await client.query(
        `INSERT INTO atlas_xrefs (atlas_technique_id, attack_technique_id)
         VALUES ($1, $2) ON CONFLICT DO NOTHING`,
        [atlasUuid, attackResult.rows[0].id],
      );
      xrefCount++;
    }
    console.log(`  Inserted ${xrefCount} cross-references`);

    await client.query('COMMIT');
    console.log('\n✓ ATLAS sync complete');

  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Sync failed, rolled back:', err);
    process.exit(1);
  } finally {
    client.release();
  }

  // Final stats
  const stats = await pool.query(`
    SELECT
      (SELECT COUNT(*) FROM tactics WHERE domain = $1) AS tactics,
      (SELECT COUNT(*) FROM techniques WHERE domain = $1) AS techniques,
      (SELECT COUNT(*) FROM mitigations WHERE domain = $1) AS mitigations,
      (SELECT COUNT(*) FROM atlas_xrefs) AS xrefs
  `, [DOMAIN]);
  const s = stats.rows[0];
  console.log(`\nATLAS in DB: ${s.tactics} tactics, ${s.techniques} techniques, ${s.mitigations} mitigations, ${s.xrefs} xrefs`);

  await pool.end();
}

main().catch(e => { console.error(e); process.exit(1); });
