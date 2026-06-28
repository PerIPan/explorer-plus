/**
 * sync-frameworks.mjs
 * Downloads and syncs NIST 800-53, MITRE Engage, and RE&CT into the database.
 *
 * Usage:
 *   DATABASE_URL=postgresql://postgres@localhost:5432/mitre_attack node scripts/sync-frameworks.mjs
 */

import pg from 'pg';

const { Pool } = pg;

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
  ssl: isProduction ? { rejectUnauthorized: true } : undefined,
});

/** Fetch JSON from a URL with a simple retry. */
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

/** Fetch raw text from a URL. */
async function fetchText(url) {
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const res = await fetch(url);
      if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
      return res.text();
    } catch (err) {
      if (attempt === 3) throw err;
      console.warn(`  Retry ${attempt} for ${url}: ${err.message}`);
      await new Promise((r) => setTimeout(r, 1000 * attempt));
    }
  }
}

/**
 * Build a lookup map: attack_id -> UUID from the techniques table.
 * Includes both parent and sub-techniques.
 */
async function buildTechniqueMap(client) {
  const result = await client.query(
    'SELECT id, attack_id FROM techniques',
  );
  const map = new Map();
  for (const row of result.rows) {
    map.set(row.attack_id, row.id);
  }
  return map;
}

// ── NIST family prefix map ────────────────────────────────────────────────────

const NIST_FAMILY_MAP = {
  AC: 'Access Control',
  AT: 'Awareness and Training',
  AU: 'Audit and Accountability',
  CA: 'Assessment, Authorization, and Monitoring',
  CM: 'Configuration Management',
  CP: 'Contingency Planning',
  IA: 'Identification and Authentication',
  IR: 'Incident Response',
  MA: 'Maintenance',
  MP: 'Media Protection',
  PE: 'Physical and Environmental Protection',
  PL: 'Planning',
  PM: 'Program Management',
  PS: 'Personnel Security',
  PT: 'Personally Identifiable Information Processing and Transparency',
  RA: 'Risk Assessment',
  SA: 'System and Services Acquisition',
  SC: 'System and Communications Protection',
  SI: 'System and Information Integrity',
  SR: 'Supply Chain Risk Management',
};

function nistFamily(controlId) {
  const prefix = controlId.split('-')[0];
  return NIST_FAMILY_MAP[prefix] ?? prefix;
}

// ── NIST 800-53 Rev5 sync ─────────────────────────────────────────────────────

async function syncNist(techniqueMap) {
  console.log('\n[NIST 800-53] Downloading mappings...');
  const url =
    'https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/mappings/nist_800_53/attack-16.1/nist_800_53-rev5/enterprise/nist_800_53-rev5_attack-16.1-enterprise.json';

  const data = await fetchJson(url);
  const objects = data.mapping_objects ?? [];
  console.log(`  Raw records: ${objects.length}`);

  // Filter non-mappable and null technique IDs
  const valid = objects.filter(
    (o) => o.status !== 'non_mappable' && o.attack_object_id,
  );
  console.log(`  After filter: ${valid.length}`);

  const client = await pool.connect();
  let inserted = 0;
  let skipped = 0;

  try {
    for (const obj of valid) {
      const attackId = obj.attack_object_id;
      const controlId = obj.capability_id;

      if (!attackId || !controlId) {
        skipped++;
        continue;
      }

      const techniqueUuid = techniqueMap.get(attackId) ?? null;
      const family = nistFamily(controlId);

      try {
        await client.query(
          `INSERT INTO nist_controls
             (control_id, control_name, control_family, technique_id, attack_technique_id, mapping_type, status)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           ON CONFLICT (control_id, attack_technique_id)
           DO UPDATE SET
             control_name        = EXCLUDED.control_name,
             control_family      = EXCLUDED.control_family,
             technique_id        = EXCLUDED.technique_id,
             mapping_type        = EXCLUDED.mapping_type,
             status              = EXCLUDED.status`,
          [
            controlId,
            obj.capability_description ?? null,
            family,
            techniqueUuid,
            attackId,
            obj.mapping_type ?? null,
            obj.status ?? null,
          ],
        );
        inserted++;
      } catch (err) {
        console.warn(`  DB error for ${controlId}/${attackId}: ${err.message}`);
        skipped++;
      }
    }
  } finally {
    client.release();
  }

  console.log(`  Upserted: ${inserted}, skipped: ${skipped}`);
}

// ── MITRE Engage sync ─────────────────────────────────────────────────────────

async function syncEngage(techniqueMap) {
  console.log('\n[MITRE Engage] Downloading mappings...');

  const baseUrl = 'https://raw.githubusercontent.com/mitre/engage/main/Data/json';

  // Download required files in parallel
  const [attackMapping, activityDetails, goals, approaches] =
    await Promise.all([
      fetchJson(`${baseUrl}/attack_mapping.json`).catch(() => []),
      fetchJson(`${baseUrl}/activity_details.json`).catch(() => ({})),
      fetchJson(`${baseUrl}/goals.json`).catch(() => []),
      fetchJson(`${baseUrl}/approaches.json`).catch(() => []),
    ]);

  console.log(`  Attack mapping records: ${attackMapping.length}`);

  /**
   * activityDetails may be an array or an object keyed by ID.
   * Each entry has: goals: ["EGO0001"], approaches: ["EAP0001"], description, etc.
   * Normalise to a Map: id -> { description, goals, approaches, ... }
   */
  const detailsMap = new Map();
  if (Array.isArray(activityDetails)) {
    for (const item of activityDetails) {
      if (item.id) detailsMap.set(item.id, item);
      if (item.eav_id) detailsMap.set(item.eav_id, item);
      if (item.eac_id) detailsMap.set(item.eac_id, item);
    }
  } else {
    for (const [k, v] of Object.entries(activityDetails)) {
      detailsMap.set(k, v);
    }
  }

  /** Map goal IDs (EGO0001) and approach IDs (EAP0001) to their names */
  const goalNameMap = new Map();
  const approachArr = Array.isArray(goals) ? goals : Object.entries(goals).map(([k, v]) => ({ id: k, ...(typeof v === 'string' ? { name: v } : v) }));
  for (const g of approachArr) {
    if (g.id) goalNameMap.set(g.id, g.name ?? g.id);
  }

  const approachNameMap = new Map();
  const appArr = Array.isArray(approaches) ? approaches : Object.entries(approaches).map(([k, v]) => ({ id: k, ...(typeof v === 'string' ? { name: v } : v) }));
  for (const a of appArr) {
    if (a.id) approachNameMap.set(a.id, a.name ?? a.id);
  }

  const client = await pool.connect();
  let inserted = 0;
  let skipped = 0;

  try {
    for (const obj of attackMapping) {
      const attackId = obj.attack_id;
      if (!attackId) { skipped++; continue; }

      // An entry can reference either eav or eac activities
      const entries = [];

      if (obj.eav_id && obj.eav) {
        entries.push({ id: obj.eav_id, name: obj.eav, type: 'eav' });
      }
      if (obj.eac_id && obj.eac) {
        entries.push({ id: obj.eac_id, name: obj.eac, type: 'eac' });
      }
      // If neither sub-key exists, treat the whole object as one entry
      if (entries.length === 0 && (obj.activity_id || obj.id)) {
        entries.push({
          id: obj.activity_id ?? obj.id,
          name: obj.activity ?? obj.name ?? obj.activity_id ?? obj.id,
          type: 'activity',
        });
      }

      for (const entry of entries) {
        const techniqueUuid = techniqueMap.get(attackId) ?? null;
        const detail = detailsMap.get(entry.id) ?? {};
        // activity_details.json stores goals/approaches as arrays of IDs
        const goalId = detail.goals?.[0] ?? null;
        const approachId = detail.approaches?.[0] ?? null;
        const goalName = goalNameMap.get(goalId) ?? goalId;

        try {
          await client.query(
            `INSERT INTO engage_mappings
               (engage_id, engage_name, engage_description, goal, approach, technique_id, attack_technique_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (engage_id, attack_technique_id)
             DO UPDATE SET
               engage_name        = EXCLUDED.engage_name,
               engage_description = EXCLUDED.engage_description,
               goal               = EXCLUDED.goal,
               approach           = EXCLUDED.approach,
               technique_id       = EXCLUDED.technique_id`,
            [
              entry.id,
              entry.name,
              detail.description ?? null,
              goalName,
              approachNameMap.get(approachId) ?? approachId,
              techniqueUuid,
              attackId,
            ],
          );
          inserted++;
        } catch (err) {
          console.warn(`  DB error for ${entry.id}/${attackId}: ${err.message}`);
          skipped++;
        }
      }
    }
  } finally {
    client.release();
  }

  console.log(`  Upserted: ${inserted}, skipped: ${skipped}`);
}

// ── RE&CT sync ────────────────────────────────────────────────────────────────

/**
 * Very minimal YAML parser for the RE&CT RA_*.yml format.
 * Only handles simple key: value and multi-line block scalars.
 */
function parseReactYaml(text) {
  const result = {};

  // Simple single-line key: value
  const simple = ['id', 'title', 'stage'];
  for (const key of simple) {
    const m = text.match(new RegExp(`^${key}:\\s*(.+)$`, 'm'));
    if (m) result[key] = m[1].trim().replace(/^['"]|['"]$/g, '');
  }

  // Multi-line block scalar fields: description and workflow
  const block = ['description', 'workflow'];
  for (const key of block) {
    const start = new RegExp(`^${key}:\\s*[|>]?\\s*\n`, 'm');
    const startMatch = start.exec(text);
    if (startMatch) {
      const afterKey = text.slice(startMatch.index + startMatch[0].length);
      // Collect lines that are indented (at least 2 spaces) or blank
      const lines = afterKey.split('\n');
      const collected = [];
      for (const line of lines) {
        if (line === '' || line.startsWith(' ') || line.startsWith('\t')) {
          collected.push(line.replace(/^\s{2}/, '')); // strip 2-space indent
        } else {
          break;
        }
      }
      result[key] = collected.join('\n').trim() || null;
    } else {
      // Inline single-line fallback
      const inline = text.match(new RegExp(`^${key}:\\s*(.+)$`, 'm'));
      if (inline) result[key] = inline[1].trim().replace(/^['"]|['"]$/g, '');
    }
  }

  return result;
}

async function syncReact() {
  console.log('\n[RE&CT] Fetching file tree...');

  const treeData = await fetchJson(
    'https://api.github.com/repos/atc-project/atc-react/git/trees/master?recursive=1',
  );

  const raFiles = (treeData.tree ?? []).filter(
    (item) =>
      item.type === 'blob' &&
      item.path.startsWith('response_actions/RA_') &&
      item.path.endsWith('.yml'),
  );

  console.log(`  Found ${raFiles.length} RA_*.yml files`);

  const client = await pool.connect();
  let inserted = 0;
  let skipped = 0;

  try {
    for (const file of raFiles) {
      const rawUrl = `https://raw.githubusercontent.com/atc-project/atc-react/master/${file.path}`;
      let text;
      try {
        text = await fetchText(rawUrl);
      } catch (err) {
        console.warn(`  Failed to fetch ${file.path}: ${err.message}`);
        skipped++;
        continue;
      }

      const parsed = parseReactYaml(text);
      if (!parsed.id || !parsed.title) {
        skipped++;
        continue;
      }

      try {
        await client.query(
          `INSERT INTO react_actions (action_id, title, description, stage, workflow)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (action_id)
           DO UPDATE SET
             title       = EXCLUDED.title,
             description = EXCLUDED.description,
             stage       = EXCLUDED.stage,
             workflow    = EXCLUDED.workflow`,
          [
            parsed.id,
            parsed.title,
            parsed.description ?? null,
            parsed.stage ?? null,
            parsed.workflow ?? null,
          ],
        );
        inserted++;
      } catch (err) {
        console.warn(`  DB error for ${parsed.id}: ${err.message}`);
        skipped++;
      }
    }
  } finally {
    client.release();
  }

  console.log(`  Upserted: ${inserted}, skipped: ${skipped}`);
}

// ── CIS Controls ──────────────────────────────────────────────────────────────

async function checkCis() {
  console.log('\n[CIS Controls] Checking mappings-explorer for CIS data...');
  // The mappings-explorer repo includes cri_profile, csa_ccm, and nist_800_53
  // but does NOT include CIS Controls v8 as a downloadable JSON mapping.
  // CIS Controls mappings require a manual download from cisecurity.org
  // and are not publicly available as machine-readable ATT&CK mappings.
  console.log(
    '  CIS Controls v8 mappings are not available as a public JSON in the\n' +
    '  Center for Threat-Informed Defense mappings-explorer repo.\n' +
    '  The cis_controls table has been created but will remain empty until\n' +
    '  mappings are manually curated from https://www.cisecurity.org/controls/cis-controls-navigator',
  );
}

// ── VERIS sync ────────────────────────────────────────────────────────────────

async function syncVeris(techniqueMap) {
  console.log('\n[VERIS] Downloading mappings...');
  const url =
    'https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/src/mapex_convert/mappings/Veris/veris-1_3_7-mappings-enterprise.json';

  const data = await fetchJson(url);
  const attackToVeris = data.attack_to_veris ?? {};
  const entries = Object.entries(attackToVeris);
  console.log(`  Techniques with VERIS mappings: ${entries.length}`);

  const client = await pool.connect();
  let inserted = 0;
  let skipped = 0;

  try {
    for (const [attackId, entry] of entries) {
      if (!attackId || !entry) { skipped++; continue; }

      const verisCategories = entry.veris;
      if (!Array.isArray(verisCategories) || verisCategories.length === 0) {
        skipped++;
        continue;
      }

      const techniqueUuid = techniqueMap.get(attackId) ?? null;

      for (const verisId of verisCategories) {
        if (!verisId) { skipped++; continue; }

        try {
          await client.query(
            `INSERT INTO veris_mappings
               (technique_id, attack_technique_id, veris_id)
             VALUES ($1, $2, $3)
             ON CONFLICT (attack_technique_id, veris_id)
             DO UPDATE SET technique_id = EXCLUDED.technique_id`,
            [techniqueUuid, attackId, verisId],
          );
          inserted++;
        } catch (err) {
          console.warn(`  DB error for VERIS ${attackId}/${verisId}: ${err.message}`);
          skipped++;
        }
      }
    }
  } finally {
    client.release();
  }

  console.log(`  Upserted: ${inserted}, skipped: ${skipped}`);
}

// ── Cloud controls sync (STIX bundle format) ──────────────────────────────────

/**
 * Extract technique ATT&CK ID from a STIX attack-pattern external reference.
 * The external_references array contains objects with source_name 'mitre-attack'
 * and an external_id like 'T1078'.
 */
function extractAttackId(stixObj) {
  const refs = stixObj.external_references ?? [];
  const ref = refs.find((r) => r.source_name === 'mitre-attack');
  return ref?.external_id ?? null;
}

/**
 * Sync a STIX 2.x bundle of cloud security control mappings.
 * Relationships with type 'mitigates' link a course-of-action (control)
 * to an attack-pattern (technique).
 */
async function syncCloudProvider(provider, url, techniqueMap) {
  console.log(`\n[Cloud/${provider.toUpperCase()}] Downloading mappings from ${url}`);

  let data;
  try {
    data = await fetchJson(url);
  } catch (err) {
    console.warn(`  Failed to download ${provider}: ${err.message}`);
    return;
  }

  // CTID uses mapping_objects format (not STIX relationships)
  const mappingObjects = data.mapping_objects ?? [];
  console.log(`  Mapping objects: ${mappingObjects.length}`);

  const client = await pool.connect();
  let inserted = 0;
  let skipped = 0;

  try {
    for (const m of mappingObjects) {
      const attackId = m.attack_object_id;
      if (!attackId || !attackId.startsWith('T')) { skipped++; continue; }

      const controlId = m.capability_id ?? m.capability_group ?? 'unknown';
      const controlName = m.capability_description ?? controlId;
      const mappingType = m.score_category ?? null; // detect, protect, respond

      const techniqueUuid = techniqueMap.get(attackId) ?? techniqueMap.get(attackId.split('.')[0]) ?? null;

      try {
        await client.query(
          `INSERT INTO cloud_control_mappings
             (technique_id, attack_technique_id, provider, control_id, control_name, control_description, mapping_type)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           ON CONFLICT (attack_technique_id, provider, control_id)
           DO UPDATE SET
             technique_id        = EXCLUDED.technique_id,
             control_name        = EXCLUDED.control_name,
             control_description = EXCLUDED.control_description,
             mapping_type        = EXCLUDED.mapping_type`,
          [
            techniqueUuid,
            attackId,
            provider,
            controlId,
            controlName,
            null, // description not in mapping_objects format
            mappingType,
          ],
        );
        inserted++;
      } catch (err) {
        console.warn(`  DB error ${provider} ${controlId}/${attackId}: ${err.message}`);
        skipped++;
      }
    }
  } finally {
    client.release();
  }

  console.log(`  Upserted: ${inserted}, skipped: ${skipped}`);
}

async function syncCloudControls(techniqueMap) {
  const providers = [
    {
      provider: 'azure',
      url: 'https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/mappings/azure/attack-16.1/azure-04.26.2025/enterprise/azure-04.26.2025_attack-16.1-enterprise.json',
    },
    {
      provider: 'gcp',
      url: 'https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/mappings/gcp/attack-16.1/gcp-03.06.2025/enterprise/gcp-03.06.2025_attack-16.1-enterprise.json',
    },
  ];

  for (const { provider, url } of providers) {
    await syncCloudProvider(provider, url, techniqueMap);
  }
}

// ── CAPEC Bridge (CWE → ATT&CK via CAPEC) ────────────────────────────────────

const CAPEC_STIX_URL = 'https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json';

async function syncCapecBridge(techniqueMap) {
  console.log('\n[CAPEC Bridge] Downloading CAPEC STIX...');
  let data;
  try { data = await fetchJson(CAPEC_STIX_URL); } catch (err) {
    console.warn(`  Failed: ${err.message}`);
    return;
  }

  // Build CWE → technique ID set
  const cweToTechs = new Map();
  for (const obj of data.objects ?? []) {
    if (obj.type !== 'attack-pattern') continue;
    const refs = obj.external_references ?? [];
    const attackIds = [], cwes = [];
    for (const r of refs) {
      if (r.source_name === 'ATTACK' && r.external_id) attackIds.push(r.external_id.split('.')[0]);
      if (r.source_name === 'cwe' && r.external_id) cwes.push(r.external_id);
    }
    if (!cwes.length || !attackIds.length) continue;
    for (const cwe of cwes) {
      if (!cweToTechs.has(cwe)) cweToTechs.set(cwe, new Set());
      for (const tid of attackIds) cweToTechs.get(cwe).add(tid);
    }
  }
  // Drop catch-all CWEs (mapping to >10 distinct techniques) so generic CWEs
  // like CWE-200 don't fan every CVE IOC out across unrelated techniques.
  // Threshold mirrors CATCHALL_CWE_THRESHOLD in app/api/v1/lib/inference.ts.
  for (const [cwe, techs] of cweToTechs) {
    if (techs.size > 10) cweToTechs.delete(cwe);
  }
  console.log(`  CWEs mapped (after catch-all exclusion): ${cweToTechs.size}`);

  // Find CVE IOCs with CWE IDs that have no technique links yet
  const client = await pool.connect();
  let linked = 0;
  try {
    const cveResult = await client.query(
      `SELECT i.id AS ioc_id, cd.cwe_id
       FROM cve_details cd
       JOIN ioc_entries i ON i.value = cd.cve_id AND i.type = 'cve'
       WHERE cd.cwe_id IS NOT NULL AND cd.cwe_id != ''
         AND NOT EXISTS (SELECT 1 FROM technique_iocs ti WHERE ti.ioc_id = i.id)`
    );

    for (const cve of cveResult.rows) {
      const techs = cweToTechs.get(cve.cwe_id);
      if (!techs) continue;
      for (const tid of techs) {
        const techId = techniqueMap.get(tid);
        if (!techId) continue;
        try {
          const r = await client.query(
            `INSERT INTO technique_iocs (technique_id, ioc_id, confidence)
             VALUES ($1, $2, 'inferred') ON CONFLICT (technique_id, ioc_id) DO NOTHING`,
            [techId, cve.ioc_id]
          );
          if (r.rowCount > 0) linked++;
        } catch { /* skip */ }
      }
    }
  } finally {
    client.release();
  }
  console.log(`  CVE→technique links created: ${linked}`);
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  console.log('Framework sync starting...');
  console.log(`Database: ${connectionString.replace(/:[^:@]+@/, ':***@')}`);

  const client = await pool.connect();
  let techniqueMap;
  try {
    techniqueMap = await buildTechniqueMap(client);
    console.log(`Loaded ${techniqueMap.size} techniques from DB`);
  } finally {
    client.release();
  }

  await syncNist(techniqueMap);
  await syncEngage(techniqueMap);
  await syncReact();
  await checkCis();
  await syncVeris(techniqueMap);
  await syncCloudControls(techniqueMap);
  await syncCapecBridge(techniqueMap);

  await pool.end();
  console.log('\nSync complete.');
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
