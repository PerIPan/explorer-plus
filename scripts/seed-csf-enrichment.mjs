#!/usr/bin/env node
// scripts/seed-csf-enrichment.mjs
//
// Loads NIST CSF v2 Implementation Examples + Category descriptions from the
// official OSCAL catalog (mirrored into seed/data/) and upserts them into the DB.
//
// Run:  DATABASE_URL=postgres://... node scripts/seed-csf-enrichment.mjs
// Safe to re-run (idempotent upserts keyed on natural IDs).
//
// Source: https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/CSF/v2.0/json/NIST_CSF_v2.0_catalog.json
//
// The snapshot lives at seed/data/csf-v2-oscal-catalog.json and is read from
// disk here — pinned to the exact bytes committed in the repo. No runtime
// network fetch, so no supply-chain risk from a moving `main` branch.
// Refresh: re-download the file and commit alongside a code change.
//
// Informative References (800-53, CIS, ISO, 800-221A) are intentionally NOT
// pulled here — NIST publishes them as separate XLSX files with unstable URLs.
// That's a follow-up; this script handles the two datasets NIST ships in the
// core OSCAL catalog.

import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CATALOG_PATH = resolve(__dirname, '../seed/data/csf-v2-oscal-catalog.json');

const DATABASE_URL = process.env.DATABASE_URL || process.env.POSTGRES_URL;
if (!DATABASE_URL) {
  console.error('DATABASE_URL or POSTGRES_URL required');
  process.exit(1);
}

console.log(`Loading NIST CSF v2 OSCAL catalog from ${CATALOG_PATH}...`);
const catalog = JSON.parse(readFileSync(CATALOG_PATH, 'utf8'));

// OSCAL structure:
//   catalog.groups[]            → Functions (GV, ID, PR, DE, RS, RC)
//   catalog.groups[].controls[] → Categories (GV.OC, GV.RM, ...)
//     .parts[0].prose           → Category description
//   catalog.groups[].controls[].controls[] → Subcategories (GV.OC-01, ...)
//     .parts[] where name='example' → Implementation examples

const categoryDescriptions = new Map();    // category_id → description
const examples = [];                       // { subcategoryId, exampleId, ordinal, text }

for (const fn of catalog.catalog.groups ?? []) {
  for (const cat of fn.controls ?? []) {
    // Category description from the `statement` part
    const stmt = (cat.parts ?? []).find((p) => p.name === 'statement');
    if (stmt?.prose) {
      categoryDescriptions.set(cat.id, stmt.prose);
    }

    for (const sub of cat.controls ?? []) {
      const parts = sub.parts ?? [];
      const exampleParts = parts.filter((p) => p.name === 'example');
      exampleParts.forEach((p, i) => {
        if (p.prose) {
          examples.push({
            subcategoryId: sub.id,
            exampleId: p.id,
            ordinal: i + 1,
            text: p.prose,
          });
        }
      });
    }
  }
}

console.log(
  `Parsed ${categoryDescriptions.size} category descriptions + ${examples.length} implementation examples`,
);

const client = new pg.Client({ connectionString: DATABASE_URL });
await client.connect();

try {
  await client.query('BEGIN');

  // Update category_description on csf_subcategories
  let catUpdated = 0;
  for (const [categoryId, description] of categoryDescriptions) {
    const r = await client.query(
      `UPDATE csf_subcategories
       SET category_description = $2, updated_at = NOW()
       WHERE category_id = $1 AND version = '2.0'`,
      [categoryId, description],
    );
    catUpdated += r.rowCount ?? 0;
  }

  // Implementation examples — upsert
  let exInserted = 0;
  let exUpdated = 0;
  for (const ex of examples) {
    // Look up the subcategory UUID
    const sub = await client.query(
      `SELECT id FROM csf_subcategories WHERE subcategory_id = $1 AND version = '2.0' LIMIT 1`,
      [ex.subcategoryId],
    );
    if (sub.rows.length === 0) {
      console.warn(`  skip: subcategory ${ex.subcategoryId} not in DB`);
      continue;
    }
    const subUuid = sub.rows[0].id;

    const result = await client.query(
      `INSERT INTO csf_implementation_examples
         (csf_subcategory_uuid, subcategory_id, example_id, ordinal, text)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (subcategory_id, example_id)
       DO UPDATE SET
         ordinal = EXCLUDED.ordinal,
         text = EXCLUDED.text,
         updated_at = NOW()
       RETURNING xmax = 0 AS inserted`,
      [subUuid, ex.subcategoryId, ex.exampleId, ex.ordinal, ex.text],
    );
    if (result.rows[0].inserted) exInserted++;
    else exUpdated++;
  }

  await client.query('COMMIT');
  console.log(
    `Done. category_description rows updated: ${catUpdated}. examples inserted: ${exInserted}, updated: ${exUpdated}`,
  );
} catch (err) {
  await client.query('ROLLBACK');
  console.error('Seed failed:', err);
  process.exit(1);
} finally {
  await client.end();
}
