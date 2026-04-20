#!/usr/bin/env node
// scripts/sync-capec-full.mjs
//
// One-shot ingest of the full CAPEC taxonomy from the pinned MITRE CTI STIX
// bundle. Populates capec_patterns, capec_mitigations, capec_pattern_mitigations
// and capec_related. Idempotent — safe to re-run whenever the seed file is
// refreshed (CAPEC publishes annually).
//
// Run: DATABASE_URL=postgres://... node scripts/sync-capec-full.mjs
//
// Refresh seed:
//   curl -sL https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json \
//     | gzip > seed/data/capec-stix.json.gz

import { createReadStream } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createGunzip } from 'node:zlib';
import pg from 'pg';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SEED_PATH = resolve(__dirname, '../seed/data/capec-stix.json.gz');

const DATABASE_URL = process.env.DATABASE_URL || process.env.POSTGRES_URL;
if (!DATABASE_URL) {
  console.error('DATABASE_URL or POSTGRES_URL required');
  process.exit(1);
}

// Strip embedded xhtml:p tags from CAPEC description fields — they carry
// structure that we render as plain text with paragraph breaks.
function stripHtml(s) {
  if (!s) return null;
  return s
    .replace(/<\/?xhtml:p[^>]*>/g, '\n')
    .replace(/<[^>]+>/g, '')
    .replace(/\s+\n/g, '\n')
    .replace(/\n\s+/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim() || null;
}

async function loadStix() {
  const chunks = [];
  const stream = createReadStream(SEED_PATH).pipe(createGunzip());
  for await (const c of stream) chunks.push(c);
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

function capecIdFrom(obj) {
  const ref = (obj.external_references ?? []).find(
    (r) => r.source_name === 'capec' && typeof r.external_id === 'string' && r.external_id.startsWith('CAPEC-'),
  );
  return ref?.external_id ?? null;
}

function cweIdsFrom(obj) {
  return (obj.external_references ?? [])
    .filter((r) => r.source_name === 'cwe' && typeof r.external_id === 'string')
    .map((r) => r.external_id);
}

async function run() {
  console.log(`Loading CAPEC STIX from ${SEED_PATH}...`);
  const stix = await loadStix();
  const objects = stix.objects ?? [];
  console.log(`  ${objects.length} STIX objects`);

  // Build UUID → CAPEC-N map for relationship resolution
  const uuidToCapec = new Map();
  for (const o of objects) {
    if (o.type === 'attack-pattern') {
      const cid = capecIdFrom(o);
      if (cid) uuidToCapec.set(o.id, cid);
    }
  }
  console.log(`  ${uuidToCapec.size} attack-patterns with CAPEC IDs`);

  const client = new pg.Client({ connectionString: DATABASE_URL });
  await client.connect();

  try {
    await client.query('BEGIN');

    // 1. Patterns
    let patternCount = 0;
    for (const o of objects) {
      if (o.type !== 'attack-pattern') continue;
      const capecId = capecIdFrom(o);
      if (!capecId) continue;
      await client.query(
        `INSERT INTO capec_patterns
           (id, name, description, abstraction, status, likelihood, severity,
            prerequisites, resources_required, skills_required, consequences,
            example_instances, cwe_ids, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::jsonb, $12, $13, NOW())
         ON CONFLICT (id) DO UPDATE SET
           name = EXCLUDED.name,
           description = EXCLUDED.description,
           abstraction = EXCLUDED.abstraction,
           status = EXCLUDED.status,
           likelihood = EXCLUDED.likelihood,
           severity = EXCLUDED.severity,
           prerequisites = EXCLUDED.prerequisites,
           resources_required = EXCLUDED.resources_required,
           skills_required = EXCLUDED.skills_required,
           consequences = EXCLUDED.consequences,
           example_instances = EXCLUDED.example_instances,
           cwe_ids = EXCLUDED.cwe_ids,
           updated_at = NOW()`,
        [
          capecId,
          o.name ?? capecId,
          stripHtml(o.description),
          o.x_capec_abstraction ?? null,
          o.x_capec_status ?? null,
          o.x_capec_likelihood_of_attack ?? null,
          o.x_capec_typical_severity ?? null,
          (o.x_capec_prerequisites ?? []).map(stripHtml).filter(Boolean),
          (o.x_capec_resources_required ?? []).map(stripHtml).filter(Boolean),
          JSON.stringify(o.x_capec_skills_required ?? {}),
          JSON.stringify(o.x_capec_consequences ?? {}),
          (o.x_capec_example_instances ?? []).map(stripHtml).filter(Boolean),
          cweIdsFrom(o),
        ],
      );
      patternCount++;
    }

    // 2. Mitigations (course-of-action objects)
    let mitigationCount = 0;
    for (const o of objects) {
      if (o.type !== 'course-of-action') continue;
      await client.query(
        `INSERT INTO capec_mitigations (id, name, description)
         VALUES ($1, $2, $3)
         ON CONFLICT (id) DO UPDATE SET
           name = EXCLUDED.name,
           description = EXCLUDED.description`,
        [o.id, o.name ?? null, stripHtml(o.description)],
      );
      mitigationCount++;
    }

    // 3. Pattern → mitigation links (from relationship objects)
    let patternMitCount = 0;
    for (const o of objects) {
      if (o.type !== 'relationship' || o.relationship_type !== 'mitigates') continue;
      const targetCapec = uuidToCapec.get(o.target_ref);
      if (!targetCapec) continue;
      await client.query(
        `INSERT INTO capec_pattern_mitigations (capec_id, mitigation_id)
         VALUES ($1, $2) ON CONFLICT DO NOTHING`,
        [targetCapec, o.source_ref],
      );
      patternMitCount++;
    }

    // 4. Pattern ↔ pattern relationships (ChildOf / ParentOf / CanPrecede / CanFollow)
    let relatedCount = 0;
    for (const o of objects) {
      if (o.type !== 'attack-pattern') continue;
      const capecId = capecIdFrom(o);
      if (!capecId) continue;

      const relationSpecs = [
        { field: 'x_capec_child_of_refs', nature: 'ChildOf' },
        { field: 'x_capec_parent_of_refs', nature: 'ParentOf' },
        { field: 'x_capec_can_precede_refs', nature: 'CanPrecede' },
        { field: 'x_capec_can_follow_refs', nature: 'CanFollow' },
      ];
      for (const spec of relationSpecs) {
        for (const uuid of o[spec.field] ?? []) {
          const related = uuidToCapec.get(uuid);
          if (!related) continue;
          await client.query(
            `INSERT INTO capec_related (capec_id, related_capec_id, nature)
             VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
            [capecId, related, spec.nature],
          );
          relatedCount++;
        }
      }
    }

    await client.query('COMMIT');
    console.log(
      `Done. patterns=${patternCount}, mitigations=${mitigationCount}, pattern_mitigations=${patternMitCount}, related=${relatedCount}`,
    );
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    await client.end();
  }
}

run().catch((err) => { console.error(err); process.exit(1); });
