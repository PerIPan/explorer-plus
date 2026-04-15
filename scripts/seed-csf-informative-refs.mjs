#!/usr/bin/env node
// scripts/seed-csf-informative-refs.mjs
//
// Parses NIST CSF v2.0 Reference Tool XLSX export and upserts informative
// references into csf_informative_references.
//
// Run:  DATABASE_URL=postgres://... node scripts/seed-csf-informative-refs.mjs
//
// Source file: seed/data/csf-v2-informative-references.xlsx
// Re-generate with:
//   curl -L "https://csrc.nist.gov/extensions/nudp/services/json/csf/download?olirids=all" \
//        -o seed/data/csf-v2-informative-references.xlsx
//
// Frameworks loaded (see FRAMEWORK_SPECS below):
//   - SP 800-53 Rev 5      → target_framework = '800-53r5'
//     Connects to ATT&CK techniques via nist_controls + nist_control_mappings.
//   - ISO/IEC 27001:2022   → target_framework = 'iso-27001-2022'
//     No technique bridge yet — surfaced as compliance crosswalk only.
//
// Everything else in the source (PCI DSS, NICE, CCM, SSDF, ...) is deliberately
// skipped for now; add a new FRAMEWORK_SPECS entry when we're ready to surface
// them.

import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import XLSX from 'xlsx';

const __dirname = dirname(fileURLToPath(import.meta.url));
const XLSX_PATH = resolve(__dirname, '../seed/data/csf-v2-informative-references.xlsx');

const DATABASE_URL = process.env.DATABASE_URL || process.env.POSTGRES_URL;
if (!DATABASE_URL) {
  console.error('DATABASE_URL or POSTGRES_URL required');
  process.exit(1);
}

/**
 * Each spec defines how to recognise a framework's lines and normalise the
 * control/reference ID. The raw ref column is a \n-separated list of
 * `<label>: <id>` lines. `match` is run against the full line, and the first
 * capture group is used as target_id.
 */
const FRAMEWORK_SPECS = [
  {
    targetFramework: '800-53r5',
    // Matches "SP 800-53 Rev 5.1.1: PM-11" and "SP 800-53 Rev 5.2.0: PM-11".
    // Revisions are consolidated under one code — upserts dedupe so loading
    // both revisions is safe.
    match: /^SP 800-53 Rev 5(?:\.\d+\.\d+)?:\s*(.+?)\s*$/i,
  },
  {
    targetFramework: 'iso-27001-2022',
    // Matches e.g. "ISO/IEC 27001:2022: Mandatory Clause: 6.1" and
    // "ISO/IEC 27001:2022: Annex A Controls: 5.20". We keep the second
    // segment + id together as target_id so "Annex A 5.20" stays distinct
    // from "Mandatory Clause 5.20".
    match: /^ISO\/IEC 27001:2022:\s*(.+?)\s*$/i,
  },
];

const SUBCATEGORY_RE = /^([A-Z]{2}\.[A-Z]{2}-\d{2}):/;

console.log(`Loading XLSX from ${XLSX_PATH}...`);
const wb = XLSX.readFile(XLSX_PATH);
if (!wb.SheetNames.includes('CSF 2.0')) {
  console.error('Expected sheet "CSF 2.0" not found in workbook');
  process.exit(1);
}

const rows = XLSX.utils.sheet_to_json(wb.Sheets['CSF 2.0'], { header: 1, raw: false });

// Each row: [Function, Category, Subcategory, Implementation Examples, Informative References]
const refs = []; // { subcategoryId, targetFramework, targetId }
const seen = new Set();
const stats = new Map(FRAMEWORK_SPECS.map((s) => [s.targetFramework, 0]));

for (const row of rows) {
  const subcatCell = row[2];
  const refsCell = row[4];
  if (typeof subcatCell !== 'string' || typeof refsCell !== 'string') continue;
  const subMatch = subcatCell.match(SUBCATEGORY_RE);
  if (!subMatch) continue;
  const subcategoryId = subMatch[1];

  for (const rawLine of refsCell.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;

    for (const spec of FRAMEWORK_SPECS) {
      const m = line.match(spec.match);
      if (!m) continue;
      // Normalise: collapse whitespace, strip trailing punctuation
      const targetId = m[1].replace(/\s+/g, ' ').replace(/[,;.]+$/, '').trim();
      if (!targetId) break;

      const key = `${subcategoryId}|${spec.targetFramework}|${targetId}`;
      if (seen.has(key)) break;
      seen.add(key);
      refs.push({ subcategoryId, targetFramework: spec.targetFramework, targetId });
      stats.set(spec.targetFramework, (stats.get(spec.targetFramework) ?? 0) + 1);
      break; // first matching spec wins
    }
  }
}

console.log('Parsed unique references by framework:');
for (const [fw, n] of stats) console.log(`  ${fw}: ${n}`);
console.log(`Total: ${refs.length}`);

if (refs.length === 0) {
  console.error('No references parsed — aborting so we don\'t wipe existing data.');
  process.exit(1);
}

const client = new pg.Client({ connectionString: DATABASE_URL });
await client.connect();

try {
  await client.query('BEGIN');

  const subRes = await client.query(
    `SELECT id, subcategory_id FROM csf_subcategories WHERE version = '2.0'`,
  );
  const subMap = new Map(subRes.rows.map((r) => [r.subcategory_id, r.id]));

  let inserted = 0;
  let updated = 0;
  let skipped = 0;

  for (const r of refs) {
    const subUuid = subMap.get(r.subcategoryId);
    if (!subUuid) { skipped++; continue; }

    const result = await client.query(
      `INSERT INTO csf_informative_references
         (csf_subcategory_uuid, subcategory_id, target_framework, target_id, source)
       VALUES ($1, $2, $3, $4, 'nist-csf-v2-oscal-catalog')
       ON CONFLICT (subcategory_id, target_framework, target_id)
       DO UPDATE SET
         csf_subcategory_uuid = EXCLUDED.csf_subcategory_uuid,
         source = EXCLUDED.source,
         updated_at = NOW()
       RETURNING xmax = 0 AS inserted`,
      [subUuid, r.subcategoryId, r.targetFramework, r.targetId],
    );
    if (result.rows[0].inserted) inserted++;
    else updated++;
  }

  await client.query('COMMIT');
  console.log(
    `Done. inserted: ${inserted}, updated: ${updated}, skipped (unknown subcategory): ${skipped}`,
  );
} catch (err) {
  await client.query('ROLLBACK');
  console.error('Seed failed:', err);
  process.exit(1);
} finally {
  await client.end();
}
