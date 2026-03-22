/**
 * sync-thaicert.mjs
 * Downloads ThaiCERT/ETDA threat actor encyclopedia and upserts into external_actors.
 *
 * Usage:
 *   DATABASE_URL=postgresql://postgres@localhost:5432/mitre_attack node scripts/sync-thaicert.mjs
 */

import pg from 'pg';

const { Pool } = pg;

const SOURCE_URL = 'https://apt.etda.or.th/cgi-bin/getmisp.cgi?o=g';

const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
  console.error('DATABASE_URL environment variable is required');
  process.exit(1);
}

const isProduction =
  connectionString.includes('neon') || connectionString.includes('vercel');

const pool = new Pool({
  connectionString,
  max: isProduction ? 1 : 5,
  ssl: isProduction ? { rejectUnauthorized: false } : undefined,
});

/** Fetch JSON from a URL with simple retry. */
async function fetchJson(url) {
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const res = await fetch(url);
      if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
      return res.json();
    } catch (err) {
      if (attempt === 3) throw err;
      console.warn(`  Retry ${attempt} for ${url}: ${err.message}`);
      await new Promise((r) => setTimeout(r, 1000 * attempt));
    }
  }
}

/**
 * Build a lookup set of all known MITRE group names and aliases -> attack_id.
 * Used to auto-link ThaiCERT actors to ATT&CK groups via synonym matching.
 */
async function buildMitreGroupLookup() {
  const result = await pool.query(`
    SELECT attack_id, name, aliases
    FROM threat_groups
    WHERE is_revoked = false AND is_deprecated = false
  `);

  /** @type {Map<string, string>} normalised-name -> attack_id */
  const lookup = new Map();
  for (const row of result.rows) {
    lookup.set(row.name.toLowerCase().trim(), row.attack_id);
    if (Array.isArray(row.aliases)) {
      for (const alias of row.aliases) {
        if (alias) lookup.set(alias.toLowerCase().trim(), row.attack_id);
      }
    }
  }
  return lookup;
}

/**
 * Try to find a MITRE ATT&CK group ID for the actor using synonym matching.
 * @param {string} name
 * @param {string[]} synonyms
 * @param {Map<string, string>} lookup
 * @returns {string | null}
 */
function findMitreGroupId(name, synonyms, lookup) {
  const candidates = [name, ...(synonyms ?? [])];
  for (const candidate of candidates) {
    const match = lookup.get(candidate.toLowerCase().trim());
    if (match) return match;
  }
  return null;
}

async function main() {
  console.log('Fetching ThaiCERT/ETDA threat actor data...');
  const data = await fetchJson(SOURCE_URL);

  if (!data || !Array.isArray(data.values)) {
    console.error('Unexpected response shape — expected { values: [...] }');
    process.exit(1);
  }

  console.log(`Fetched ${data.values.length} actor entries.`);
  console.log('Building MITRE ATT&CK group lookup...');
  const mitreGroupLookup = await buildMitreGroupLookup();
  console.log(`Loaded ${mitreGroupLookup.size} MITRE group name/alias entries.`);

  let upserted = 0;
  let linked = 0;
  let errors = 0;

  for (const entry of data.values) {
    try {
      const name = (entry.value ?? '').trim();
      if (!name) continue;

      const description = entry.description ?? null;
      const meta = entry.meta ?? {};
      const country = meta.country ?? null;
      const synonyms = Array.isArray(meta.synonyms) ? meta.synonyms.filter(Boolean) : null;
      const refs = Array.isArray(meta.refs) ? meta.refs.filter(Boolean) : null;
      const category = meta.category ?? meta.type ?? null;
      const uuid = entry.uuid ?? null;
      const motivation = Array.isArray(meta.motivation) ? meta.motivation.join(', ') : (meta.motivation ?? null);
      const firstSeen = meta.date ?? null;
      const suspectedVictims = Array.isArray(meta['cfr-suspected-victims']) ? meta['cfr-suspected-victims'].filter(Boolean) : null;
      const targetCategories = Array.isArray(meta['cfr-target-category']) ? meta['cfr-target-category'].filter(Boolean) : null;
      const suspectedStateSponsor = meta['cfr-suspected-state-sponsor'] ?? null;
      const attributionConfidence = meta['attribution-confidence'] ?? null;

      const mitreGroupId = findMitreGroupId(name, synonyms ?? [], mitreGroupLookup);
      if (mitreGroupId) linked++;

      await pool.query(
        `INSERT INTO external_actors
           (name, description, source, country, category, synonyms, refs, mitre_group_id, uuid,
            motivation, first_seen, suspected_victims, target_categories, suspected_state_sponsor, attribution_confidence, updated_at)
         VALUES ($1, $2, 'thaicert', $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, now())
         ON CONFLICT (uuid) DO UPDATE SET
           name          = EXCLUDED.name,
           description   = EXCLUDED.description,
           country       = EXCLUDED.country,
           category      = EXCLUDED.category,
           synonyms      = EXCLUDED.synonyms,
           refs          = EXCLUDED.refs,
           mitre_group_id = EXCLUDED.mitre_group_id,
           motivation    = EXCLUDED.motivation,
           first_seen    = EXCLUDED.first_seen,
           suspected_victims = EXCLUDED.suspected_victims,
           target_categories = EXCLUDED.target_categories,
           suspected_state_sponsor = EXCLUDED.suspected_state_sponsor,
           attribution_confidence = EXCLUDED.attribution_confidence,
           updated_at    = now()`,
        [name, description, country, category, synonyms, refs, mitreGroupId, uuid,
         motivation, firstSeen, suspectedVictims, targetCategories, suspectedStateSponsor, attributionConfidence],
      );

      upserted++;
    } catch (err) {
      console.error(`  Error processing entry "${entry.value}": ${err.message}`);
      errors++;
    }
  }

  console.log(`Done. Upserted: ${upserted}, ATT&CK linked: ${linked}, Errors: ${errors}`);
  await pool.end();
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
