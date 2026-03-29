#!/usr/bin/env node
/**
 * Bulk ingest CVElistV5 data: CVEs → applications → affected_products.
 * Reads directly from the zip file. Only onboards CVEs with CWE→CAPEC→technique path.
 *
 * Usage: DATABASE_URL=... node scripts/ingest-cvelistv5.mjs /path/to/cvelistV5-main.zip [startYear]
 *
 * Example: DATABASE_URL=postgresql://user@localhost/mitre_attack node scripts/ingest-cvelistv5.mjs ~/Downloads/cvelistV5-main.zip 2023
 */

import pg from 'pg';
import fs from 'fs';
import { createRequire } from 'module';

// yauzl for zip reading
const require = createRequire(import.meta.url);
let yauzl;
try {
  yauzl = require('yauzl');
} catch {
  console.error('Install yauzl: npm install yauzl');
  process.exit(1);
}

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) { console.error('DATABASE_URL required'); process.exit(1); }

const ZIP_PATH = process.argv[2];
if (!ZIP_PATH || !fs.existsSync(ZIP_PATH)) {
  console.error(`Usage: node scripts/ingest-cvelistv5.mjs <path-to-zip> [startYear]`);
  process.exit(1);
}

const START_YEAR = parseInt(process.argv[3] ?? '2023', 10);
const BATCH_SIZE = 100;

const isProduction = DATABASE_URL.includes('neon') || DATABASE_URL.includes('vercel');
const pool = new pg.Pool({
  connectionString: DATABASE_URL,
  ssl: isProduction ? { rejectUnauthorized: true } : undefined,
  max: 3,
});

/** Normalize vendor/product for dedup — strips non-alphanum per part, joins with / */
function normalize(vendor, product) {
  const v = vendor.toLowerCase().replace(/[^a-z0-9]/g, '');
  const p = product.toLowerCase().replace(/[^a-z0-9]/g, '');
  return `${v}/${p}`;
}

/** Read all JSON entries from zip matching year filter */
function readZipEntries(zipPath, yearFilter) {
  return new Promise((resolve, reject) => {
    const entries = [];
    yauzl.open(zipPath, { lazyEntries: true, autoClose: true }, (err, zipfile) => {
      if (err) return reject(err);
      zipfile.readEntry();
      zipfile.on('entry', (entry) => {
        const name = entry.fileName;
        if (!name.endsWith('.json') || !name.includes('/cves/')) {
          zipfile.readEntry();
          return;
        }
        // Extract year from path like cvelistV5-main/cves/2024/1xxx/CVE-2024-1234.json
        const yearMatch = name.match(/\/cves\/(\d{4})\//);
        if (!yearMatch || parseInt(yearMatch[1], 10) < yearFilter) {
          zipfile.readEntry();
          return;
        }

        zipfile.openReadStream(entry, (err2, stream) => {
          if (err2) { zipfile.readEntry(); return; }
          const chunks = [];
          stream.on('data', (chunk) => chunks.push(chunk));
          stream.on('end', () => {
            try {
              const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
              entries.push(data);
            } catch { /* skip malformed */ }
            zipfile.readEntry();
          });
        });
      });
      zipfile.on('end', () => resolve(entries));
      zipfile.on('error', reject);
    });
  });
}

async function main() {
  console.log(`Reading zip: ${ZIP_PATH}`);
  console.log(`Year filter: >= ${START_YEAR}`);

  // Load CAPEC bridge: which CWEs have technique paths?
  const capecResult = await pool.query(
    `SELECT DISTINCT cwe_id FROM capec_mappings WHERE technique_id IS NOT NULL`
  );
  const cwesWithTechnique = new Set(capecResult.rows.map(r => r.cwe_id));
  console.log(`CWEs with technique path: ${cwesWithTechnique.size}`);

  // Read all CVE entries from zip
  console.log('Reading zip entries (this takes a few minutes)...');
  const allEntries = await readZipEntries(ZIP_PATH, START_YEAR);
  console.log(`Read ${allEntries.length.toLocaleString()} CVE JSON files`);

  // Filter and parse
  const cves = [];
  let skippedState = 0, skippedNoCwe = 0, skippedNoTech = 0, skippedNoAffected = 0;

  for (const data of allEntries) {
    const meta = data.cveMetadata ?? {};
    if (meta.state !== 'PUBLISHED') { skippedState++; continue; }

    const cveId = meta.cveId;
    const cna = data.containers?.cna ?? {};

    // Extract CWEs
    const cwes = [];
    for (const pt of (cna.problemTypes ?? [])) {
      for (const d of (pt.descriptions ?? [])) {
        const cweId = d.cweId || d.value || '';
        if (cweId.startsWith('CWE-')) cwes.push(cweId);
      }
    }
    if (cwes.length === 0) { skippedNoCwe++; continue; }

    // Check: any CWE maps to technique?
    if (!cwes.some(c => cwesWithTechnique.has(c))) { skippedNoTech++; continue; }

    // Extract affected products (only status=affected or no explicit status)
    const affected = [];
    for (const a of (cna.affected ?? [])) {
      const vendor = a.vendor?.trim();
      const product = a.product?.trim();
      if (!vendor || !product) continue;
      if (vendor === 'n/a' || vendor === 'n' || vendor === 'Unknown' || vendor === 'unknown') continue;
      if (a.defaultStatus === 'unaffected') continue;

      const versions = a.versions ?? [];
      if (versions.length === 0) {
        affected.push({ vendor, product, versionStart: null, versionEnd: null, cpe: a.cpes?.[0] ?? null });
      } else {
        for (const v of versions) {
          if (v.status === 'unaffected') continue;
          affected.push({
            vendor, product,
            versionStart: v.version ?? null,
            versionEnd: v.lessThan ?? v.lessThanOrEqual ?? null,
            cpe: a.cpes?.[0] ?? null,
          });
        }
      }
    }
    if (affected.length === 0) { skippedNoAffected++; continue; }

    // Extract CVSS
    let cvssScore = null, cvssSeverity = null, cvssVector = null;
    for (const m of (cna.metrics ?? [])) {
      const v31 = m.cvssV3_1 ?? m.cvssV3_0 ?? m.cvssV31 ?? m.cvssV30 ?? null;
      if (v31) {
        cvssScore = v31.baseScore ?? null;
        cvssSeverity = v31.baseSeverity ?? null;
        cvssVector = v31.vectorString ?? null;
        break;
      }
    }

    // Extract description (truncate to 500 chars)
    let description = null;
    for (const d of (cna.descriptions ?? [])) {
      if (d.lang === 'en' || !description) {
        description = d.value?.slice(0, 500) ?? null;
      }
    }

    // Extract published date
    const publishedAt = meta.datePublished ?? null;

    cves.push({ cveId, description, cvssScore, cvssSeverity, cvssVector, cwes, affected, publishedAt });
  }

  console.log(`\nFiltered:`);
  console.log(`  Skipped (not published): ${skippedState.toLocaleString()}`);
  console.log(`  Skipped (no CWE):        ${skippedNoCwe.toLocaleString()}`);
  console.log(`  Skipped (no technique):  ${skippedNoTech.toLocaleString()}`);
  console.log(`  Skipped (no affected):   ${skippedNoAffected.toLocaleString()}`);
  console.log(`  ✓ CVEs to ingest:        ${cves.length.toLocaleString()}`);

  // Unique apps
  const appSet = new Set();
  for (const cve of cves) {
    for (const a of cve.affected) {
      appSet.add(normalize(a.vendor, a.product));
    }
  }
  console.log(`  ✓ Unique applications:   ${appSet.size.toLocaleString()}`);

  // ── Ingest in batches ──────────────────────────────────────────────────────
  console.log(`\nIngesting ${cves.length.toLocaleString()} CVEs in batches of ${BATCH_SIZE}...`);

  // Disable trigger during bulk load for performance — re-enable in finally block
  const triggerClient = await pool.connect();
  await triggerClient.query('ALTER TABLE affected_products DISABLE TRIGGER trg_affected_products_count');
  triggerClient.release();

  let totalCves = 0, totalApps = 0, totalAffected = 0, totalWeaknesses = 0;
  const appCache = new Map(); // normalized → UUID

  try {
  for (let i = 0; i < cves.length; i += BATCH_SIZE) {
    const batch = cves.slice(i, i + BATCH_SIZE);
    const batchClient = await pool.connect();

    try {
      await batchClient.query('BEGIN');

      for (const cve of batch) {
        // 1. Upsert cve_details
        await batchClient.query(
          `INSERT INTO cve_details (cve_id, description, cvss_score, cvss_severity, cvss_vector, cwe_id, published_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           ON CONFLICT (cve_id) DO UPDATE SET
             description = EXCLUDED.description,
             cvss_score = EXCLUDED.cvss_score,
             cvss_severity = EXCLUDED.cvss_severity,
             cvss_vector = EXCLUDED.cvss_vector,
             cwe_id = EXCLUDED.cwe_id,
             published_at = EXCLUDED.published_at,
             updated_at = now()`,
          [cve.cveId, cve.description, cve.cvssScore, cve.cvssSeverity, cve.cvssVector, cve.cwes[0], cve.publishedAt],
        );
        totalCves++;

        // 2. Upsert cve_weaknesses (multi-CWE)
        for (const cwe of cve.cwes) {
          await batchClient.query(
            `INSERT INTO cve_weaknesses (cve_id, cwe_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
            [cve.cveId, cwe],
          );
          totalWeaknesses++;
        }

        // 3. Upsert applications + affected_products
        for (const a of cve.affected) {
          const norm = normalize(a.vendor, a.product);

          let appId = appCache.get(norm);
          if (!appId) {
            const r = await batchClient.query(
              `INSERT INTO applications (vendor, product, normalized, cpe_prefix)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (normalized) DO UPDATE SET
                 cpe_prefix = COALESCE(EXCLUDED.cpe_prefix, applications.cpe_prefix),
                 updated_at = now()
               RETURNING id`,
              [a.vendor, a.product, norm, a.cpe],
            );
            appId = r.rows[0].id;
            appCache.set(norm, appId);
            totalApps++;
          }

          await batchClient.query(
            `INSERT INTO affected_products (cve_id, application_id, version_start, version_end)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT DO NOTHING`,
            [cve.cveId, appId, a.versionStart, a.versionEnd],
          );
          totalAffected++;
        }
      }

      await batchClient.query('COMMIT');
    } catch (err) {
      await batchClient.query('ROLLBACK');
      console.error(`Batch ${i}-${i+BATCH_SIZE} failed:`, err.message);
    } finally {
      batchClient.release();
    }

    if ((i + BATCH_SIZE) % 5000 === 0 || i + BATCH_SIZE >= cves.length) {
      const pct = Math.round(100 * (i + BATCH_SIZE) / cves.length);
      console.log(`  ${Math.min(i + BATCH_SIZE, cves.length).toLocaleString()} / ${cves.length.toLocaleString()} (${pct}%)`);
    }
  }

  } finally {
    // Always re-enable trigger, even on crash
    console.log('\nRe-enabling trigger...');
    const enableClient = await pool.connect();
    await enableClient.query('ALTER TABLE affected_products ENABLE TRIGGER trg_affected_products_count');
    enableClient.release();
  }

  // Update counts
  console.log('Updating cve_count...');
  await pool.query(`
    UPDATE applications a SET
      cve_count = (SELECT COUNT(DISTINCT cve_id) FROM affected_products WHERE application_id = a.id),
      updated_at = now()
  `);

  // Create or refresh materialized view
  console.log('Refreshing materialized view...');
  const mvExists = await pool.query(
    `SELECT 1 FROM pg_matviews WHERE matviewname = 'app_technique_groups'`
  );
  if (mvExists.rows.length > 0) {
    await pool.query('REFRESH MATERIALIZED VIEW CONCURRENTLY app_technique_groups');
  } else {
    await pool.query(`
      CREATE MATERIALIZED VIEW app_technique_groups AS
      SELECT DISTINCT
        ap.application_id,
        cm.attack_technique_id,
        t.id            AS technique_id,
        t.name          AS technique_name,
        tg.attack_id    AS group_attack_id,
        tg.name         AS group_name
      FROM affected_products ap
      JOIN cve_weaknesses cw     ON cw.cve_id = ap.cve_id
      JOIN capec_mappings cm     ON cm.cwe_id = cw.cwe_id AND cm.technique_id IS NOT NULL
      JOIN techniques t          ON t.id = cm.technique_id
      JOIN group_techniques gt   ON gt.technique_id = t.id
      JOIN threat_groups tg      ON tg.id = gt.group_id
    `);
    await pool.query('CREATE INDEX ON app_technique_groups(application_id)');
    await pool.query('CREATE INDEX ON app_technique_groups(technique_id)');
    await pool.query('CREATE INDEX ON app_technique_groups(group_attack_id)');
  }

  // Final stats
  const stats = await pool.query(`
    SELECT
      (SELECT COUNT(*) FROM cve_details) AS cves,
      (SELECT COUNT(*) FROM applications) AS apps,
      (SELECT COUNT(*) FROM affected_products) AS affected,
      (SELECT COUNT(*) FROM cve_weaknesses) AS weaknesses,
      (SELECT COUNT(*) FROM app_technique_groups) AS mv_rows,
      (SELECT COUNT(DISTINCT technique_id) FROM app_technique_groups) AS mv_techniques,
      (SELECT COUNT(DISTINCT group_attack_id) FROM app_technique_groups) AS mv_groups
  `);
  const s = stats.rows[0];

  console.log(`\n${'='.repeat(50)}`);
  console.log(`INGESTION COMPLETE`);
  console.log(`${'='.repeat(50)}`);
  console.log(`  CVEs:              ${parseInt(s.cves).toLocaleString()}`);
  console.log(`  Applications:      ${parseInt(s.apps).toLocaleString()}`);
  console.log(`  Affected products: ${parseInt(s.affected).toLocaleString()}`);
  console.log(`  CWE weaknesses:    ${parseInt(s.weaknesses).toLocaleString()}`);
  console.log(`  MV rows:           ${parseInt(s.mv_rows).toLocaleString()}`);
  console.log(`  MV techniques:     ${parseInt(s.mv_techniques).toLocaleString()}`);
  console.log(`  MV groups:         ${parseInt(s.mv_groups).toLocaleString()}`);

  await pool.end();
}

main().catch(e => { console.error(e); process.exit(1); });
