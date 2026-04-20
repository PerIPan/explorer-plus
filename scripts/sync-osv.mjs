#!/usr/bin/env node
// scripts/sync-osv.mjs
//
// Ingest OSV advisories for NON-GHSA ecosystems only.
//
// Rationale: our `ghsa_advisories` table already covers the reviewed subset
// of GHSA (which is exactly what OSV republishes for npm/PyPI/Maven/Go/etc.).
// OSV's unique value is Linux kernel, distros, Android, Chrome, OSS-Fuzz,
// and the other OS-level ecosystems listed at:
//   https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt
//
// Two filters:
//   1. Skip GHSA-covered ecosystems at fetch time (no overlap fetched at all)
//   2. Drop any record whose aliases[] intersect an existing ghsa_id
//      (defense-in-depth for rare cross-eco references)
//
// Usage (local / one-shot):
//   DATABASE_URL=postgres://... node scripts/sync-osv.mjs
//
// The Vercel cron at /api/cron/sync-osv runs an equivalent pipeline daily.

import pg from 'pg';
import cvss from 'cvss';
import JSZip from 'jszip';

const OSV_BASE = 'https://osv-vulnerabilities.storage.googleapis.com';
const BATCH_SIZE = 500;

// Ecosystems where GHSA already is the source of truth. OSV mirrors these —
// skipping them avoids duplicate storage and eliminates the need for any
// display-time dedup. GitHub upgrades PYSEC/GO/RUSTSEC/DRUPAL/PSF etc. to
// GHSA quickly, so we lose very few unique records.
const GHSA_COVERED = new Set([
  'npm',
  'PyPI',
  'Maven',
  'Go',
  'NuGet',
  'RubyGems',
  'Packagist',      // Composer
  'crates.io',
  'Pub',
  'Hex',
  'GitHub Actions',
]);

const DATABASE_URL = process.env.DATABASE_URL || process.env.POSTGRES_URL;
if (!DATABASE_URL) {
  console.error('DATABASE_URL required');
  process.exit(1);
}

// --- CVSS parsing ------------------------------------------------------------

/**
 * Parse the OSV `severity[]` array and return a computed score/severity.
 * Falls back to nulls on unknown vector types (v2, v4) or malformed vectors.
 *
 * Note: the `cvss` npm package supports only the CVSS v3.0 prefix. v3.0 and
 * v3.1 use identical scoring formulas, so we rewrite the prefix before
 * scoring. v4 and v2 vectors fall through to the null branch — fine for now;
 * we still preserve the raw vector in `severity_raw` for later.
 */
function parseCvss(severityArray) {
  if (!Array.isArray(severityArray) || severityArray.length === 0) {
    return { vector: null, score: null, severity: null };
  }
  // Prefer v3.x; fall back to first entry if only v2 or v4 present.
  const v3 = severityArray.find((s) => s?.type === 'CVSS_V3');
  const entry = v3 || severityArray[0];
  if (!entry?.score) return { vector: null, score: null, severity: null };

  // Only attempt to score v3 vectors — we don't ship a v4 scorer yet.
  if (!v3) return { vector: entry.score, score: null, severity: null };

  try {
    const rewritten = entry.score.replace(/^CVSS:3\.1\//, 'CVSS:3.0/');
    const score = cvss.getScore(rewritten);
    if (typeof score !== 'number' || isNaN(score) || score === 0) {
      return { vector: entry.score, score: null, severity: null };
    }
    const rating = cvss.getRating(score);
    return {
      vector: entry.score,
      score: Number(score.toFixed(1)),
      severity: (rating || '').toUpperCase() || null,
    };
  } catch {
    return { vector: entry.score, score: null, severity: null };
  }
}

// --- Ingest helpers ----------------------------------------------------------

async function fetchEcosystems() {
  const resp = await fetch(`${OSV_BASE}/ecosystems.txt`);
  if (!resp.ok) throw new Error(`ecosystems.txt HTTP ${resp.status}`);
  return (await resp.text())
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);
}

async function loadGhsaAliasSet(client) {
  const result = await client.query(`SELECT ghsa_id FROM ghsa_advisories`);
  return new Set(result.rows.map((r) => r.ghsa_id));
}

/**
 * Ingest a single ecosystem's all.zip into osv_advisories + osv_affected.
 * Returns { scanned, upserted, skippedGhsa, skippedMalformed, errors }.
 */
async function syncEcosystem(client, ecosystem, ghsaAliases) {
  const url = `${OSV_BASE}/${encodeURIComponent(ecosystem)}/all.zip`;
  const resp = await fetch(url);
  if (!resp.ok) {
    return { scanned: 0, upserted: 0, skippedGhsa: 0, skippedMalformed: 0, errors: 1 };
  }

  const buf = Buffer.from(await resp.arrayBuffer());
  const zip = await JSZip.loadAsync(buf);
  const entries = Object.values(zip.files).filter((e) => e.name.endsWith('.json'));

  let scanned = 0;
  let upserted = 0;
  let skippedGhsa = 0;
  let skippedMalformed = 0;
  let errors = 0;

  let advBatch = [];
  let affBatch = [];

  // Upsert advisories in multi-row INSERT batches. 11 cols × 500 rows = 5500
  // bind parameters, well inside the 65535 protocol ceiling.
  //
  // IMPORTANT: de-dupe by (osv_id, ecosystem) before sending — the same OSV
  // zip can repeat an advisory across multiple JSON files, and Postgres
  // rejects ON CONFLICT DO UPDATE when the same key appears twice in one
  // INSERT ("command cannot affect row a second time").
  const flushAdv = async () => {
    if (advBatch.length === 0) return;
    const byKey = new Map();
    for (const r of advBatch) byKey.set(`${r.osv_id}\0${r.ecosystem}`, r);
    const rows = [...byKey.values()];
    const values = rows
      .map(
        (_, i) =>
          `($${i * 11 + 1}, $${i * 11 + 2}, $${i * 11 + 3}, $${i * 11 + 4}, $${i * 11 + 5},` +
          ` $${i * 11 + 6}::jsonb, $${i * 11 + 7}, $${i * 11 + 8}::numeric,` +
          ` $${i * 11 + 9}, $${i * 11 + 10}, $${i * 11 + 11})`,
      )
      .join(', ');
    const params = rows.flatMap((r) => [
      r.osv_id,
      r.ecosystem,
      r.aliases,
      r.summary,
      r.details,
      JSON.stringify(r.severity_raw ?? []),
      r.cvss_vector,
      r.cvss_score,
      r.cvss_severity,
      r.published,
      r.modified,
    ]);
    await client.query(
      `INSERT INTO osv_advisories
         (osv_id, ecosystem, aliases, summary, details, severity_raw,
          cvss_vector, cvss_score, cvss_severity, published, modified)
       VALUES ${values}
       ON CONFLICT (osv_id, ecosystem) DO UPDATE SET
         aliases       = EXCLUDED.aliases,
         summary       = EXCLUDED.summary,
         details       = EXCLUDED.details,
         severity_raw  = EXCLUDED.severity_raw,
         cvss_vector   = EXCLUDED.cvss_vector,
         cvss_score    = EXCLUDED.cvss_score,
         cvss_severity = EXCLUDED.cvss_severity,
         published     = EXCLUDED.published,
         modified      = EXCLUDED.modified,
         updated_at    = NOW()`,
      params,
    );
    upserted += rows.length;
    advBatch = [];
  };

  // Same de-dupe concern on the (osv_id, ecosystem, pkg_eco, pkg_name) key.
  const flushAff = async () => {
    if (affBatch.length === 0) return;
    const byKey = new Map();
    for (const r of affBatch) {
      byKey.set(`${r.osv_id}\0${r.ecosystem}\0${r.package_ecosystem}\0${r.package_name}`, r);
    }
    const rows = [...byKey.values()];
    const values = rows
      .map(
        (_, i) =>
          `($${i * 6 + 1}, $${i * 6 + 2}, $${i * 6 + 3}, $${i * 6 + 4},` +
          ` $${i * 6 + 5}, $${i * 6 + 6}::jsonb)`,
      )
      .join(', ');
    const params = rows.flatMap((r) => [
      r.osv_id,
      r.ecosystem,
      r.package_name,
      r.package_ecosystem,
      r.versions,
      JSON.stringify(r.ranges ?? []),
    ]);
    await client.query(
      `INSERT INTO osv_affected
         (osv_id, ecosystem, package_name, package_ecosystem, versions, ranges)
       VALUES ${values}
       ON CONFLICT (osv_id, ecosystem, package_ecosystem, package_name) DO UPDATE SET
         versions = EXCLUDED.versions,
         ranges   = EXCLUDED.ranges`,
      params,
    );
    affBatch = [];
  };

  // Ensure parent rows (advisories) are inserted BEFORE child rows (affected)
  // so the composite FK is satisfied. Call this instead of flushAff alone.
  const flushBoth = async () => {
    await flushAdv();
    await flushAff();
  };

  for (const entry of entries) {
    scanned++;
    let json;
    try {
      const text = await entry.async('string');
      json = JSON.parse(text);
    } catch {
      skippedMalformed++;
      continue;
    }

    const osvId = json.id;
    if (!osvId || typeof osvId !== 'string') {
      skippedMalformed++;
      continue;
    }

    const aliases = Array.isArray(json.aliases) ? json.aliases : [];

    // Belt-and-suspenders: drop records that alias an existing GHSA row.
    if (aliases.some((a) => ghsaAliases.has(a))) {
      skippedGhsa++;
      continue;
    }

    const { vector, score, severity } = parseCvss(json.severity);

    advBatch.push({
      osv_id: osvId,
      ecosystem,
      aliases: aliases,
      summary: json.summary ?? null,
      details: json.details ?? null,
      severity_raw: json.severity ?? [],
      cvss_vector: vector,
      cvss_score: score,
      cvss_severity: severity,
      published: json.published ?? null,
      modified: json.modified ?? null,
    });

    if (Array.isArray(json.affected)) {
      for (const aff of json.affected) {
        const pkg = aff?.package;
        if (!pkg?.name || !pkg?.ecosystem) continue;
        affBatch.push({
          osv_id: osvId,
          ecosystem,
          package_name: pkg.name,
          package_ecosystem: pkg.ecosystem,
          versions: Array.isArray(aff.versions) ? aff.versions : null,
          ranges: aff.ranges ?? [],
        });
        // Never flush affBatch alone — composite FK requires the parent
        // advisory row to exist first.
        if (affBatch.length >= BATCH_SIZE) await flushBoth();
      }
    }

    if (advBatch.length >= BATCH_SIZE) await flushBoth();
  }

  await flushBoth();

  return { scanned, upserted, skippedGhsa, skippedMalformed, errors };
}

// --- Main --------------------------------------------------------------------

async function main() {
  const client = new pg.Client({ connectionString: DATABASE_URL });
  await client.connect();

  try {
    console.log('[osv] loading GHSA alias set...');
    const ghsaAliases = await loadGhsaAliasSet(client);
    console.log(`[osv] GHSA alias set: ${ghsaAliases.size} ids`);

    const allEcos = await fetchEcosystems();
    const targets = allEcos.filter((e) => !GHSA_COVERED.has(e));
    console.log(`[osv] ${targets.length} target ecosystems (skipped ${allEcos.length - targets.length} GHSA-covered)`);

    const totals = { scanned: 0, upserted: 0, skippedGhsa: 0, skippedMalformed: 0, errors: 0 };

    for (const eco of targets) {
      const t0 = Date.now();
      try {
        const r = await syncEcosystem(client, eco, ghsaAliases);
        totals.scanned += r.scanned;
        totals.upserted += r.upserted;
        totals.skippedGhsa += r.skippedGhsa;
        totals.skippedMalformed += r.skippedMalformed;
        totals.errors += r.errors;
        console.log(
          `[osv] ${eco.padEnd(20)} scanned=${r.scanned} upserted=${r.upserted}` +
            ` skippedGhsa=${r.skippedGhsa} skippedMalformed=${r.skippedMalformed}` +
            ` errors=${r.errors} (${Date.now() - t0}ms)`,
        );
      } catch (err) {
        totals.errors++;
        console.error(`[osv] ${eco} FAILED:`, err.message);
      }
    }

    console.log('[osv] totals:', totals);
  } finally {
    await client.end();
  }
}

main().catch((err) => {
  console.error('[osv] fatal:', err);
  process.exit(1);
});
