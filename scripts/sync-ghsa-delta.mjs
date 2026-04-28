#!/usr/bin/env node
// scripts/sync-ghsa-delta.mjs
//
// Daily incremental sync using the GitHub REST /advisories endpoint filtered
// by the `updated` timestamp. Reads a JSON stream on stdin that is produced by
// `gh api /advisories --paginate` in the workflow, so we can leverage `gh`'s
// built-in auth + pagination.
//
// Complements the weekly `sync-ghsa-bulk.mjs` full rebase:
//   - Bulk: clones github/advisory-database, re-processes everything. Weekly.
//   - Delta: fetches only advisories with `updated >= <since>` via REST API,
//     converts to our schema, upserts. Daily.
//
// Usage in CI:
//   gh api "/advisories?per_page=100&type=reviewed&updated=>=2026-04-14" \
//     --paginate --jq '.[]' \
//     | node scripts/sync-ghsa-delta.mjs
//
// Safe to re-run. Idempotent.

import { createInterface } from 'node:readline';
import pg from 'pg';

const DATABASE_URL = process.env.DATABASE_URL || process.env.POSTGRES_URL;
if (!DATABASE_URL) {
  console.error('DATABASE_URL (or POSTGRES_URL) required');
  process.exit(1);
}

// ── Normalization helpers (mirrors sync-ghsa-bulk.mjs) ──────────────────

const ECOSYSTEM_MAP = {
  npm: 'npm', pypi: 'pypi', go: 'go', maven: 'maven', rubygems: 'rubygems',
  nuget: 'nuget', composer: 'composer', rust: 'rust', erlang: 'erlang',
  pub: 'pub', swift: 'swift', actions: 'actions',
  // REST API variants
  'crates.io': 'rust', packagist: 'composer', swifturl: 'swift',
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
    case 'pypi': return `pkg:pypi/${enc(name.toLowerCase())}`;
    case 'go':
      return `pkg:golang/${name.split('/').map((s, i) => (i === 0 ? s.toLowerCase() : enc(s))).join('/')}`;
    case 'maven': {
      const [g, a] = name.split(':');
      if (!g || !a) return `pkg:maven/${enc(name)}`;
      return `pkg:maven/${enc(g)}/${enc(a)}`;
    }
    case 'rubygems': return `pkg:gem/${enc(name)}`;
    case 'nuget':    return `pkg:nuget/${enc(name)}`;
    case 'composer': {
      const [v, n] = name.split('/');
      if (!v || !n) return `pkg:composer/${enc(name)}`;
      return `pkg:composer/${enc(v)}/${enc(n)}`;
    }
    case 'rust':   return `pkg:cargo/${enc(name)}`;
    case 'erlang': return `pkg:hex/${enc(name)}`;
    case 'pub':    return `pkg:pub/${enc(name)}`;
    case 'swift':  return `pkg:swift/${enc(name)}`;
    case 'actions': {
      const [o, n] = name.split('/');
      if (!o || !n) return `pkg:github/${enc(name)}`;
      return `pkg:github/${enc(o)}/${enc(n)}`;
    }
    default: return null;
  }
}

// REST API uses a slightly different shape than OSV JSON.
// Ranges are inline in `vulnerabilities[].vulnerable_version_range` (string).
// Fixed version is `vulnerabilities[].patched_versions` (string, may be comma-separated).
function normalizeVulnerableRange(raw) {
  if (!raw) return null;
  const trimmed = String(raw).trim();
  return trimmed.length > 0 ? trimmed : null;
}

function firstPatched(raw) {
  if (!raw) return null;
  const trimmed = String(raw).trim();
  if (!trimmed) return null;
  // REST returns things like "2.17.1, 1.12.4" — take the first.
  return trimmed.split(',')[0].trim() || null;
}

function parseAdvisory(json) {
  const ghsaId = json.ghsa_id;
  if (!ghsaId || !ghsaId.startsWith('GHSA-')) return null;

  const cveId =
    (json.identifiers ?? []).find((i) => i?.type === 'CVE')?.value ??
    json.cve_id ?? null;

  const severity = normalizeSeverity(json.severity);

  // REST response: cvss is an object { vector_string, score }
  const cvss = json.cvss ?? {};
  const cvssVector = cvss.vector_string ?? null;
  const cvssScore = typeof cvss.score === 'number' ? cvss.score : null;

  const cwes = (json.cwes ?? [])
    .map((c) => c?.cwe_id)
    .filter((id) => typeof id === 'string' && /^CWE-\d+$/.test(id));

  const packages = [];
  for (const vuln of json.vulnerabilities ?? []) {
    const ecosystem = normalizeEcosystem(vuln?.package?.ecosystem);
    const packageName = vuln?.package?.name;
    if (!ecosystem || !packageName) continue;
    packages.push({
      ecosystem,
      packageName,
      vulnerableRange: normalizeVulnerableRange(vuln.vulnerable_version_range),
      fixedVersion: firstPatched(vuln.patched_versions ?? vuln.first_patched_version),
    });
  }

  return {
    ghsaId,
    cveId,
    summary: json.summary ?? null,
    description: json.description ?? null,
    severity,
    cvssScore,
    cvssVector,
    cvssV4Score: null,
    cvssV4Vector: null,
    publishedAt: json.published_at ?? null,
    upstreamUpdatedAt: json.updated_at ?? null,
    withdrawnAt: json.withdrawn_at ?? null,
    cwes: Array.from(new Set(cwes)),
    packages,
  };
}

// ── Stdin stream reader — one JSON object per line ──────────────────────

async function readAdvisories() {
  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
  const advisories = [];
  for await (const line of rl) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const obj = JSON.parse(trimmed);
      const record = parseAdvisory(obj);
      if (record) advisories.push(record);
    } catch (err) {
      console.warn(`  skip malformed line: ${err.message}`);
    }
  }
  return advisories;
}

// ── Upsert (one-by-one via savepoints, small N) ─────────────────────────

async function upsertAdvisory(client, adv, stats) {
  // Resolve package UUIDs first
  for (const p of adv.packages) {
    const purl = purlFor(p.ecosystem, p.packageName);
    await client.query(
      `INSERT INTO packages (ecosystem, package_name, purl)
       VALUES ($1, $2, $3)
       ON CONFLICT (ecosystem, package_name) DO UPDATE
         SET last_seen_at = NOW(),
             purl = COALESCE(EXCLUDED.purl, packages.purl)
         WHERE packages.last_seen_at < NOW() - interval '1 hour'
            OR packages.purl IS DISTINCT FROM EXCLUDED.purl`,
      [p.ecosystem, p.packageName, purl],
    );
    const r = await client.query(
      `SELECT id FROM packages WHERE ecosystem = $1 AND package_name = $2`,
      [p.ecosystem, p.packageName],
    );
    p.packageId = r.rows[0]?.id ?? null;
  }

  // FK-safe cve_id (savepoint retry)
  await client.query('SAVEPOINT adv_upsert');
  try {
    await client.query(
      `INSERT INTO ghsa_advisories
         (ghsa_id, cve_id, summary, description, severity, cvss_score, cvss_vector,
          cvss_v4_score, cvss_v4_vector, published_at, upstream_updated_at, withdrawn_at,
          ghsa_enriched_at, row_updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW(), NOW())
       ON CONFLICT (ghsa_id) DO UPDATE SET
         cve_id = EXCLUDED.cve_id, summary = EXCLUDED.summary,
         description = EXCLUDED.description, severity = EXCLUDED.severity,
         cvss_score = EXCLUDED.cvss_score, cvss_vector = EXCLUDED.cvss_vector,
         cvss_v4_score = EXCLUDED.cvss_v4_score, cvss_v4_vector = EXCLUDED.cvss_v4_vector,
         published_at = EXCLUDED.published_at,
         upstream_updated_at = EXCLUDED.upstream_updated_at,
         withdrawn_at = EXCLUDED.withdrawn_at,
         ghsa_enriched_at = NOW(), row_updated_at = NOW()`,
      [
        adv.ghsaId, adv.cveId, adv.summary, adv.description, adv.severity,
        adv.cvssScore, adv.cvssVector, adv.cvssV4Score, adv.cvssV4Vector,
        adv.publishedAt, adv.upstreamUpdatedAt, adv.withdrawnAt,
      ],
    );
    await client.query('RELEASE SAVEPOINT adv_upsert');
  } catch (err) {
    if (err?.code === '23503' && adv.cveId) {
      await client.query('ROLLBACK TO SAVEPOINT adv_upsert');
      stats.fkNullFallbacks++;
      await client.query(
        `INSERT INTO ghsa_advisories
           (ghsa_id, cve_id, summary, description, severity, cvss_score, cvss_vector,
            cvss_v4_score, cvss_v4_vector, published_at, upstream_updated_at, withdrawn_at,
            ghsa_enriched_at, row_updated_at)
         VALUES ($1, NULL, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW())
         ON CONFLICT (ghsa_id) DO UPDATE SET
           cve_id = NULL, summary = EXCLUDED.summary, description = EXCLUDED.description,
           severity = EXCLUDED.severity, cvss_score = EXCLUDED.cvss_score,
           cvss_vector = EXCLUDED.cvss_vector, cvss_v4_score = EXCLUDED.cvss_v4_score,
           cvss_v4_vector = EXCLUDED.cvss_v4_vector,
           published_at = EXCLUDED.published_at,
           upstream_updated_at = EXCLUDED.upstream_updated_at,
           withdrawn_at = EXCLUDED.withdrawn_at,
           ghsa_enriched_at = NOW(), row_updated_at = NOW()`,
        [
          adv.ghsaId, adv.summary, adv.description, adv.severity,
          adv.cvssScore, adv.cvssVector, adv.cvssV4Score, adv.cvssV4Vector,
          adv.publishedAt, adv.upstreamUpdatedAt, adv.withdrawnAt,
        ],
      );
      await client.query('RELEASE SAVEPOINT adv_upsert');
    } else {
      await client.query('ROLLBACK TO SAVEPOINT adv_upsert');
      throw err;
    }
  }

  // Weaknesses — replace set
  if (adv.cwes.length > 0) {
    await client.query(
      `INSERT INTO ghsa_weaknesses (ghsa_id, cwe_id)
       SELECT $1, unnest($2::text[])
       ON CONFLICT (ghsa_id, cwe_id) DO NOTHING`,
      [adv.ghsaId, adv.cwes],
    );
  }
  await client.query(
    `DELETE FROM ghsa_weaknesses
     WHERE ghsa_id = $1 AND cwe_id <> ALL($2::text[])`,
    [adv.ghsaId, adv.cwes],
  );

  // Packages — replace set
  const resolvedPkgs = adv.packages.filter((p) => p.packageId);
  if (resolvedPkgs.length > 0) {
    await client.query(
      `INSERT INTO ghsa_packages (ghsa_id, package_id, vulnerable_range, fixed_version)
       SELECT $1, u.pkg::uuid, u.rng, u.fx
       FROM unnest($2::uuid[], $3::text[], $4::text[]) AS u(pkg, rng, fx)
       ON CONFLICT (ghsa_id, package_id, vulnerable_range_key) DO UPDATE
         SET fixed_version = EXCLUDED.fixed_version
         WHERE ghsa_packages.fixed_version IS DISTINCT FROM EXCLUDED.fixed_version`,
      [
        adv.ghsaId,
        resolvedPkgs.map((p) => p.packageId),
        resolvedPkgs.map((p) => p.vulnerableRange),
        resolvedPkgs.map((p) => p.fixedVersion),
      ],
    );
  }

  stats.advisoriesUpserted++;
}

// ── Sync-log helpers ────────────────────────────────────────────────────

async function insertLogStart(client) {
  await client.query(
    `UPDATE feed_sync_log SET status='error', completed_at=NOW(),
       error_message='Stale (auto-cleaned on new run start)'
     WHERE source='ghsa_delta' AND status='running' AND started_at < NOW() - INTERVAL '30 minutes'`,
  );
  const r = await client.query(
    `INSERT INTO feed_sync_log (source, status, started_at)
     VALUES ('ghsa_delta', 'running', NOW()) RETURNING id`,
  );
  return r.rows[0].id;
}

async function updateLogDone(client, logId, status, stats, errorMessage) {
  await client.query(
    `UPDATE feed_sync_log
     SET status=$1, completed_at=NOW(),
         records_inserted=$2, records_skipped=$3,
         metadata=$4, error_message=$5
     WHERE id=$6`,
    [
      status,
      stats.advisoriesUpserted,
      stats.advisoriesFailed,
      JSON.stringify({ ...stats, trigger: 'github-actions', mode: 'delta' }),
      errorMessage?.slice(0, 500) ?? null,
      logId,
    ],
  );
}

// ── Main ─────────────────────────────────────────────────────────────────

const stats = {
  advisoriesRead: 0,
  advisoriesUpserted: 0,
  advisoriesFailed: 0,
  fkNullFallbacks: 0,
};

const client = new pg.Client({ connectionString: DATABASE_URL });
await client.connect();

const startedAt = Date.now();
let logId;

try {
  console.log('Reading advisories from stdin ...');
  await client.query('SELECT 1'); // Neon warmup
  logId = await insertLogStart(client);
  console.log(`feed_sync_log id=${logId}`);

  const advisories = await readAdvisories();
  stats.advisoriesRead = advisories.length;
  console.log(`Received ${advisories.length} advisories`);

  if (advisories.length === 0) {
    console.log('No new advisories. Nothing to do.');
  } else {
    await client.query('BEGIN');
    try {
      for (const adv of advisories) {
        try {
          await upsertAdvisory(client, adv, stats);
        } catch (err) {
          stats.advisoriesFailed++;
          console.error(`  FAILED ${adv.ghsaId}: ${err.message?.slice(0, 200)}`);
        }
      }
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    }

    console.log('Refreshing package_summary (concurrent) ...');
    await client.query('REFRESH MATERIALIZED VIEW CONCURRENTLY package_summary');
  }

  stats.elapsedMs = Date.now() - startedAt;
  console.log('\n=== Delta sync complete ===');
  console.log(JSON.stringify(stats, null, 2));
  if (logId) await updateLogDone(client, logId, 'success', stats, null);
} catch (err) {
  console.error('\nDelta sync failed:', err);
  console.log(JSON.stringify(stats, null, 2));
  stats.elapsedMs = Date.now() - startedAt;
  if (logId) {
    try { await updateLogDone(client, logId, 'error', stats, err.message); }
    catch (logErr) { console.error('Also failed to write error log row:', logErr.message); }
  }
  process.exit(1);
} finally {
  await client.end();
}
