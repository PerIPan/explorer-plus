#!/usr/bin/env node
// seed/seed-csf-subcategories.mjs
// One-time seed of NIST CSF v2 subcategories from NIST OSCAL catalog.
// Re-run safely: uses ON CONFLICT DO UPDATE.
//
// Source: https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/CSF/v2.0/json/NIST_CSF_v2.0_catalog-min.json

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import pg from 'pg';

const __dirname = dirname(fileURLToPath(import.meta.url));
const JSON_PATH = resolve(__dirname, 'data/csf-v2-subcategories.json');

const DATABASE_URL = process.env.DATABASE_URL || process.env.POSTGRES_URL;
if (!DATABASE_URL) {
  console.error('DATABASE_URL or POSTGRES_URL required');
  process.exit(1);
}

const subcategories = JSON.parse(readFileSync(JSON_PATH, 'utf8'));
console.log(`Loading ${subcategories.length} CSF v2 subcategories...`);

const client = new pg.Client({ connectionString: DATABASE_URL });
await client.connect();

try {
  await client.query('BEGIN');
  let inserted = 0;
  let updated = 0;

  for (const s of subcategories) {
    const result = await client.query(
      `INSERT INTO csf_subcategories
         (subcategory_id, function, function_name, category_id, category_name, name, description, version)
       VALUES ($1, $2, $3, $4, $5, $6, $7, '2.0')
       ON CONFLICT (subcategory_id, version)
       DO UPDATE SET
         function = EXCLUDED.function,
         function_name = EXCLUDED.function_name,
         category_id = EXCLUDED.category_id,
         category_name = EXCLUDED.category_name,
         name = EXCLUDED.name,
         description = EXCLUDED.description,
         updated_at = NOW()
       RETURNING xmax = 0 AS inserted`,
      [
        s.subcategory_id,
        s.function,
        s.function_name,
        s.category_id,
        s.category_name,
        s.name,
        s.description ?? null,
      ]
    );
    if (result.rows[0].inserted) inserted++;
    else updated++;
  }

  await client.query('COMMIT');
  console.log(`Done. Inserted: ${inserted}, Updated: ${updated}`);
} catch (err) {
  await client.query('ROLLBACK');
  console.error('Seed failed:', err);
  process.exit(1);
} finally {
  await client.end();
}
