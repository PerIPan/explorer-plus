#!/usr/bin/env node
// scripts/sync-ghsa-bulk.mjs
//
// Bulk ingest of GitHub Security Advisories from a locally-cloned checkout of
// github/advisory-database. Orders of magnitude faster than paginated GraphQL
// because:
//   1. No HTTP rate limits, no per-page latency
//   2. Batched multi-row inserts via unnest, one transaction per 500 advisories
//
// Usage:
//   DATABASE_URL=... node scripts/sync-ghsa-bulk.mjs <advisories/github-reviewed path>
//
// Typical workflow step:
//   git clone --depth 1 --filter=blob:none --sparse https://github.com/github/advisory-database.git /tmp/advdb
//   cd /tmp/advdb && git sparse-checkout set advisories/github-reviewed
//   node scripts/sync-ghsa-bulk.mjs /tmp/advdb/advisories/github-reviewed
//
// Idempotent. Safe to re-run. The 2017+ filter matches our CVE cutoff.

import { readFile, readdir, stat } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import pg from 'pg';

const DATABASE_URL = process.env.DATABASE_URL || process.env.POSTGRES_URL;
if (!DATABASE_URL) {
  console.error('DATABASE_URL (or POSTGRES_URL) required');
  process.exit(1);
}

const rootArg = process.argv[2];
if (!rootArg) {
  console.error('Usage: node scripts/sync-ghsa-bulk.mjs <advisories/github-reviewed path>');
  process.exit(1);
}
const ROOT = resolve(rootArg);

const YEAR_CUTOFF_ISO = '2017-01-01T00:00:00Z';
const BATCH_SIZE = 500;

// ── Ecosystem + severity normalization ──────────────────────────────────

const ECOSYSTEM_MAP = {
  npm: 'npm',
  pypi: 'pypi',
  go: 'go',
  maven: 'maven',
  rubygems: 'rubygems',
  nuget: 'nuget',
  packagist: 'composer',
  'crates.io': 'rust',
  hex: 'erlang',
  pub: 'pub',
  swifturl: 'swift',
  'github actions': 'actions',
};

function normalizeEcosystem(raw) {
  if (!raw) return null;
  const key = String(raw).trim().toLowerCase();
  return ECOSYSTEM_MAP[key] ?? null;
}

const SEVERITY_ALLOWLIST = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);

function normalizeSeverity(raw) {
  if (!raw) return null;
  const up = String(raw).toUpperCase();
  const mapped = up === 'MODERATE' ? 'MEDIUM' : up;
  return SEVERITY_ALLOWLIST.has(mapped) ? mapped : null;
}

// ── CVSS v3.1 base score calculator ─────────────────────────────────────
// OSV stores the vector string in `severity[].score` (misleading field name);
// the numeric 0-10 base score isn't directly in OSV, so we compute it.

const CVSS3_METRICS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  C: { H: 0.56, L: 0.22, N: 0.0 },
  I: { H: 0.56, L: 0.22, N: 0.0 },
  A: { H: 0.56, L: 0.22, N: 0.0 },
};

function cvss3Score(vector) {
  if (!vector || typeof vector !== 'string') return null;
  const parts = vector.split('/').filter((p) => p.includes(':'));
  const m = {};
  for (const p of parts) {
    const [k, v] = p.split(':');
    m[k] = v;
  }
  if (!m.AV || !m.AC || !m.PR || !m.UI || !m.S || !m.C || !m.I || !m.A) return null;
  const scopeChanged = m.S === 'C';
  const PR = scopeChanged
    ? { N: 0.85, L: 0.68, H: 0.5 }[m.PR]
    : { N: 0.85, L: 0.62, H: 0.27 }[m.PR];
  const AV = CVSS3_METRICS.AV[m.AV];
  const AC = CVSS3_METRICS.AC[m.AC];
  const UI = CVSS3_METRICS.UI[m.UI];
  const C = CVSS3_METRICS.C[m.C];
  const I = CVSS3_METRICS.I[m.I];
  const A = CVSS3_METRICS.A[m.A];
  if ([AV, AC, PR, UI, C, I, A].some((v) => v === undefined)) return null;

  const iss = 1 - (1 - C) * (1 - I) * (1 - A);
  const impact = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * AV * AC * PR * UI;
  const raw = scopeChanged
    ? Math.min(10, 1.08 * (impact + exploitability))
    : Math.min(10, impact + exploitability);
  return Math.ceil(raw * 10) / 10;
}

// ── purl (per ecosystem) ────────────────────────────────────────────────

function purlFor(ecosystem, name) {
  if (!ecosystem || !name) return null;
  const enc = encodeURIComponent;
  switch (ecosystem) {
    case 'npm': {
      if (name.startsWith('@')) {
        const slash = name.indexOf('/');
        if (slash > 0) return `pkg:npm/${enc(name.slice(0, slash))}/${enc(name.slice(slash + 1))}`;
      }
      return `pkg:npm/${enc(name)}`;
    }
    case 'pypi':
      return `pkg:pypi/${enc(name.toLowerCase())}`;
    case 'go':
      return `pkg:golang/${name.split('/').map((seg, i) => (i === 0 ? seg.toLowerCase() : enc(seg))).join('/')}`;
    case 'maven': {
      const [group, artifact] = name.split(':');
      if (!group || !artifact) return `pkg:maven/${enc(name)}`;
      return `pkg:maven/${enc(group)}/${enc(artifact)}`;
    }
    case 'rubygems': return `pkg:gem/${enc(name)}`;
    case 'nuget':    return `pkg:nuget/${enc(name)}`;
    case 'composer': {
      const [vendor, nm] = name.split('/');
      if (!vendor || !nm) return `pkg:composer/${enc(name)}`;
      return `pkg:composer/${enc(vendor)}/${enc(nm)}`;
    }
    case 'rust':    return `pkg:cargo/${enc(name)}`;
    case 'erlang':  return `pkg:hex/${enc(name)}`;
    case 'pub':     return `pkg:pub/${enc(name)}`;
    case 'swift':   return `pkg:swift/${enc(name)}`;
    case 'actions': {
      const [owner, nm] = name.split('/');
      if (!owner || !nm) return `pkg:github/${enc(name)}`;
      return `pkg:github/${enc(owner)}/${enc(nm)}`;
    }
    default: return null;
  }
}

// ── Version range helpers ───────────────────────────────────────────────

function formatRange(events) {
  if (!events || events.length === 0) return null;
  const parts = [];
  let intro = null;
  for (const ev of events) {
    if (ev.introduced) intro = ev.introduced;
    if (ev.fixed) {
      parts.push(intro && intro !== '0' ? `>= ${intro}, < ${ev.fixed}` : `< ${ev.fixed}`);
      intro = null;
    } else if (ev.last_affected) {
      parts.push(intro && intro !== '0' ? `>= ${intro}, <= ${ev.last_affected}` : `<= ${ev.last_affected}`);
      intro = null;
    }
  }
  if (intro) parts.push(`>= ${intro}`);
  return parts.length > 0 ? parts.join(' || ') : null;
}

function firstFixed(events) {
  for (const ev of events ?? []) if (ev.fixed) return ev.fixed;
  return null;
}

// ── OSV JSON → normalized record ────────────────────────────────────────

function parseAdvisory(json) {
  const ghsaId = json.id;
  if (!ghsaId || !ghsaId.startsWith('GHSA-')) return null;

  const published = json.published;
  if (!published || published < YEAR_CUTOFF_ISO) return null;

  const cveId =
    (json.aliases ?? []).find((a) => typeof a === 'string' && a.startsWith('CVE-')) ?? null;

  // Severity: database_specific.severity is the text level (HIGH/MODERATE/etc.)
  const severity = normalizeSeverity(json.database_specific?.severity);

  // CVSS vectors
  let cvssV3Vector = null;
  let cvssV4Vector = null;
  for (const s of json.severity ?? []) {
    if (!s?.score) continue;
    if (s.type === 'CVSS_V3') cvssV3Vector = s.score;
    if (s.type === 'CVSS_V4') cvssV4Vector = s.score;
  }
  const cvssScore = cvss3Score(cvssV3Vector);

  const cwes = (json.database_specific?.cwe_ids ?? []).filter(
    (c) => typeof c === 'string' && /^CWE-\d+$/.test(c),
  );

  const packageRows = [];
  for (const aff of json.affected ?? []) {
    const ecosystem = normalizeEcosystem(aff.package?.ecosystem);
    const packageName = aff.package?.name;
    if (!ecosystem || !packageName) continue;
    for (const range of aff.ranges ?? []) {
      const vRange = formatRange(range.events);
      const fixed = firstFixed(range.events);
      packageRows.push({
        ecosystem,
        packageName,
        vulnerableRange: vRange,
        fixedVersion: fixed,
      });
    }
    if ((aff.ranges ?? []).length === 0) {
      // affected package with no range — still record it
      packageRows.push({
        ecosystem,
        packageName,
        vulnerableRange: null,
        fixedVersion: null,
      });
    }
  }

  return {
    ghsaId,
    cveId,
    summary: json.summary ?? null,
    description: json.details ?? null,
    severity,
    cvssScore,
    cvssVector: cvssV3Vector,
    cvssV4Score: null, // v4 numeric calc out of scope; vector stored only
    cvssV4Vector,
    publishedAt: published,
    upstreamUpdatedAt: json.modified ?? null,
    withdrawnAt: json.withdrawn ?? null,
    cwes: Array.from(new Set(cwes)),
    packages: packageRows,
  };
}

// ── Filesystem walker ───────────────────────────────────────────────────

async function* walkJson(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      yield* walkJson(full);
    } else if (entry.isFile() && entry.name.endsWith('.json')) {
      yield full;
    }
  }
}

// ── DB batch writers ────────────────────────────────────────────────────

async function processBatch(client, batch, stats) {
  if (batch.length === 0) return;

  // 1. Check which CVE IDs exist in cve_details; set non-existent to NULL on GHSA FK
  const cveIds = Array.from(
    new Set(batch.map((a) => a.cveId).filter((v) => v && typeof v === 'string')),
  );
  let existingCves = new Set();
  if (cveIds.length > 0) {
    const r = await client.query(
      `SELECT cve_id FROM cve_details WHERE cve_id = ANY($1::text[])`,
      [cveIds],
    );
    existingCves = new Set(r.rows.map((row) => row.cve_id));
  }

  // 2. Upsert packages — collect unique (ecosystem, name) pairs
  const pkgMap = new Map(); // key "eco|name" → { ecosystem, name, purl }
  for (const adv of batch) {
    for (const p of adv.packages) {
      const key = `${p.ecosystem}|${p.packageName}`;
      if (!pkgMap.has(key)) {
        pkgMap.set(key, {
          ecosystem: p.ecosystem,
          name: p.packageName,
          purl: purlFor(p.ecosystem, p.packageName),
        });
      }
    }
  }
  const pkgEcos = [];
  const pkgNames = [];
  const pkgPurls = [];
  for (const p of pkgMap.values()) {
    pkgEcos.push(p.ecosystem);
    pkgNames.push(p.name);
    pkgPurls.push(p.purl);
  }

  if (pkgEcos.length > 0) {
    await client.query(
      `INSERT INTO packages (ecosystem, package_name, purl)
       SELECT u.eco, u.nm, u.pu
       FROM unnest($1::text[], $2::text[], $3::text[]) AS u(eco, nm, pu)
       ON CONFLICT (ecosystem, package_name) DO UPDATE
         SET last_seen_at = NOW(),
             purl = COALESCE(EXCLUDED.purl, packages.purl)
         WHERE packages.last_seen_at < NOW() - interval '1 hour'
            OR packages.purl IS DISTINCT FROM EXCLUDED.purl`,
      [pkgEcos, pkgNames, pkgPurls],
    );
  }

  // 3. Resolve package UUIDs
  const pkgIdMap = new Map(); // "eco|name" → uuid
  if (pkgEcos.length > 0) {
    const r = await client.query(
      `SELECT id, ecosystem, package_name FROM packages
       WHERE (ecosystem, package_name) IN (
         SELECT * FROM unnest($1::text[], $2::text[])
       )`,
      [pkgEcos, pkgNames],
    );
    for (const row of r.rows) {
      pkgIdMap.set(`${row.ecosystem}|${row.package_name}`, row.id);
    }
  }

  // 4. Bulk upsert advisories
  const advCols = {
    ghsaId: [], cveId: [], summary: [], description: [], severity: [],
    cvssScore: [], cvssVector: [], cvssV4Score: [], cvssV4Vector: [],
    publishedAt: [], upstreamUpdatedAt: [], withdrawnAt: [],
  };
  for (const adv of batch) {
    advCols.ghsaId.push(adv.ghsaId);
    advCols.cveId.push(adv.cveId && existingCves.has(adv.cveId) ? adv.cveId : null);
    if (adv.cveId && !existingCves.has(adv.cveId)) stats.fkNullFallbacks++;
    advCols.summary.push(adv.summary);
    advCols.description.push(adv.description);
    advCols.severity.push(adv.severity);
    advCols.cvssScore.push(adv.cvssScore);
    advCols.cvssVector.push(adv.cvssVector);
    advCols.cvssV4Score.push(adv.cvssV4Score);
    advCols.cvssV4Vector.push(adv.cvssV4Vector);
    advCols.publishedAt.push(adv.publishedAt);
    advCols.upstreamUpdatedAt.push(adv.upstreamUpdatedAt);
    advCols.withdrawnAt.push(adv.withdrawnAt);
  }

  await client.query(
    `INSERT INTO ghsa_advisories
       (ghsa_id, cve_id, summary, description, severity, cvss_score, cvss_vector,
        cvss_v4_score, cvss_v4_vector, published_at, upstream_updated_at, withdrawn_at,
        ghsa_enriched_at, row_updated_at)
     SELECT u.ghsa_id, u.cve_id, u.summary, u.description, u.severity,
            u.cvss_score::numeric(3,1), u.cvss_vector,
            u.cvss_v4_score::numeric(3,1), u.cvss_v4_vector,
            u.published_at::timestamptz, u.upstream_updated_at::timestamptz,
            u.withdrawn_at::timestamptz, NOW(), NOW()
     FROM unnest(
       $1::text[], $2::text[], $3::text[], $4::text[], $5::text[],
       $6::text[], $7::text[], $8::text[], $9::text[],
       $10::text[], $11::text[], $12::text[]
     ) AS u(ghsa_id, cve_id, summary, description, severity,
             cvss_score, cvss_vector, cvss_v4_score, cvss_v4_vector,
             published_at, upstream_updated_at, withdrawn_at)
     ON CONFLICT (ghsa_id) DO UPDATE SET
       cve_id = EXCLUDED.cve_id,
       summary = EXCLUDED.summary,
       description = EXCLUDED.description,
       severity = EXCLUDED.severity,
       cvss_score = EXCLUDED.cvss_score,
       cvss_vector = EXCLUDED.cvss_vector,
       cvss_v4_score = EXCLUDED.cvss_v4_score,
       cvss_v4_vector = EXCLUDED.cvss_v4_vector,
       published_at = EXCLUDED.published_at,
       upstream_updated_at = EXCLUDED.upstream_updated_at,
       withdrawn_at = EXCLUDED.withdrawn_at,
       ghsa_enriched_at = NOW(),
       row_updated_at = NOW()`,
    [
      advCols.ghsaId, advCols.cveId, advCols.summary, advCols.description, advCols.severity,
      advCols.cvssScore.map((v) => v == null ? null : String(v)),
      advCols.cvssVector,
      advCols.cvssV4Score.map((v) => v == null ? null : String(v)),
      advCols.cvssV4Vector,
      advCols.publishedAt, advCols.upstreamUpdatedAt, advCols.withdrawnAt,
    ],
  );

  // 5. Bulk insert weaknesses (ON CONFLICT DO NOTHING — orphans cleaned nightly if needed)
  const wGhsas = [];
  const wCwes = [];
  for (const adv of batch) {
    for (const cwe of adv.cwes) {
      wGhsas.push(adv.ghsaId);
      wCwes.push(cwe);
    }
  }
  if (wGhsas.length > 0) {
    await client.query(
      `INSERT INTO ghsa_weaknesses (ghsa_id, cwe_id)
       SELECT * FROM unnest($1::text[], $2::text[])
       ON CONFLICT (ghsa_id, cwe_id) DO NOTHING`,
      [wGhsas, wCwes],
    );
    stats.weaknessesInserted += wGhsas.length;
  }

  // 6. Bulk insert ghsa_packages
  const pkGhsas = [];
  const pkPkgIds = [];
  const pkRanges = [];
  const pkFixed = [];
  for (const adv of batch) {
    for (const p of adv.packages) {
      const pkgId = pkgIdMap.get(`${p.ecosystem}|${p.packageName}`);
      if (!pkgId) continue;
      pkGhsas.push(adv.ghsaId);
      pkPkgIds.push(pkgId);
      pkRanges.push(p.vulnerableRange);
      pkFixed.push(p.fixedVersion);
    }
  }
  if (pkGhsas.length > 0) {
    await client.query(
      `INSERT INTO ghsa_packages (ghsa_id, package_id, vulnerable_range, fixed_version)
       SELECT u.ghsa_id, u.pkg_id::uuid, u.vr, u.fx
       FROM unnest($1::text[], $2::text[], $3::text[], $4::text[]) AS u(ghsa_id, pkg_id, vr, fx)
       ON CONFLICT (ghsa_id, package_id, vulnerable_range_key) DO UPDATE
         SET fixed_version = EXCLUDED.fixed_version
         WHERE ghsa_packages.fixed_version IS DISTINCT FROM EXCLUDED.fixed_version`,
      [pkGhsas, pkPkgIds, pkRanges, pkFixed],
    );
    stats.ghsaPackagesInserted += pkGhsas.length;
  }

  stats.advisoriesProcessed += batch.length;
}

// ── Main ────────────────────────────────────────────────────────────────

const client = new pg.Client({ connectionString: DATABASE_URL });
await client.connect();

const stats = {
  filesRead: 0,
  skippedPreCutoff: 0,
  skippedMalformed: 0,
  advisoriesProcessed: 0,
  fkNullFallbacks: 0,
  weaknessesInserted: 0,
  ghsaPackagesInserted: 0,
  batches: 0,
};

try {
  console.log(`Loading advisories from ${ROOT} ...`);
  await client.query('SELECT 1'); // Neon warmup

  let batch = [];
  const flush = async () => {
    if (batch.length === 0) return;
    await client.query('BEGIN');
    try {
      await processBatch(client, batch, stats);
      await client.query('COMMIT');
      stats.batches++;
      console.log(
        `  batch ${stats.batches} committed (${batch.length} advisories, total ${stats.advisoriesProcessed})`,
      );
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    }
    batch = [];
  };

  for await (const path of walkJson(ROOT)) {
    stats.filesRead++;
    let json;
    try {
      const buf = await readFile(path, 'utf8');
      json = JSON.parse(buf);
    } catch (err) {
      stats.skippedMalformed++;
      console.warn(`  skip malformed: ${path}`);
      continue;
    }
    const record = parseAdvisory(json);
    if (!record) {
      stats.skippedPreCutoff++;
      continue;
    }
    batch.push(record);
    if (batch.length >= BATCH_SIZE) await flush();
  }
  await flush();

  console.log('\nRefreshing package_summary (concurrent) ...');
  await client.query('REFRESH MATERIALIZED VIEW CONCURRENTLY package_summary');

  console.log('\n=== Bulk sync complete ===');
  console.log(JSON.stringify(stats, null, 2));
} catch (err) {
  console.error('\nSync failed:', err);
  console.log(JSON.stringify(stats, null, 2));
  process.exit(1);
} finally {
  await client.end();
}
