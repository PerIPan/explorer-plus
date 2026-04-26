#!/usr/bin/env node
// scripts/sync-ghsa.mjs
//
// Pulls GitHub Security Advisories via GraphQL and upserts into ghsa_*, packages tables.
// Spec: docs/superpowers/specs/2026-04-15-ghsa-packages-integration-design.md
//
// Run: TOKEN_GHSA=... DATABASE_URL=... node scripts/sync-ghsa.mjs
// Safe to re-run (idempotent upserts keyed on natural IDs).

import pg from 'pg';

const TOKEN_GHSA = process.env.TOKEN_GHSA;
const DATABASE_URL = process.env.DATABASE_URL || process.env.POSTGRES_URL;

if (!TOKEN_GHSA) {
  console.error('TOKEN_GHSA env var required (fine-grained PAT, public-read)');
  process.exit(1);
}
if (!DATABASE_URL) {
  console.error('DATABASE_URL (or POSTGRES_URL) required');
  process.exit(1);
}

const PUBLISHED_SINCE = '2017-01-01T00:00:00Z';
const GRAPHQL_URL = 'https://api.github.com/graphql';

// GraphQL query — paginated, fetches all child relations in one round-trip per advisory.
const QUERY = /* GraphQL */ `
  query($after: String, $publishedSince: DateTime!) {
    securityAdvisories(
      first: 100
      after: $after
      publishedSince: $publishedSince
      orderBy: { field: PUBLISHED_AT, direction: ASC }
    ) {
      pageInfo { hasNextPage endCursor }
      nodes {
        ghsaId
        identifiers { type value }
        summary
        description
        severity
        cvss { score vectorString }
        cwes(first: 25) { nodes { cweId } }
        publishedAt
        updatedAt
        withdrawnAt
        vulnerabilities(first: 50) {
          nodes {
            package { name ecosystem }
            vulnerableVersionRange
            firstPatchedVersion { identifier }
          }
        }
      }
    }
  }
`;

// ── Normalization helpers ──────────────────────────────────────────────

const SEVERITY_ALLOWLIST = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);

function normalizeSeverity(upstream) {
  if (!upstream) return null;
  const up = String(upstream).toUpperCase();
  const s = up === 'MODERATE' ? 'MEDIUM' : up;
  return SEVERITY_ALLOWLIST.has(s) ? s : null;
}

const KNOWN_ECOSYSTEMS = new Set([
  'npm', 'pypi', 'go', 'maven', 'rubygems', 'nuget',
  'composer', 'rust', 'erlang', 'pub', 'swift', 'actions',
]);

// GitHub returns enum names like NPM, PIP, GO — map to our lowercase slugs.
const ECOSYSTEM_ALIASES = {
  pip: 'pypi',
  npm: 'npm',
  go: 'go',
  maven: 'maven',
  rubygems: 'rubygems',
  nuget: 'nuget',
  composer: 'composer',
  rust: 'rust',
  erlang: 'erlang',
  pub: 'pub',
  swift: 'swift',
  actions: 'actions',
};

function normalizeEcosystem(upstream) {
  if (!upstream) return null;
  const slug = ECOSYSTEM_ALIASES[upstream.toLowerCase()] ?? upstream.toLowerCase();
  return KNOWN_ECOSYSTEMS.has(slug) ? slug : null;
}

/** Per-ecosystem purl formatting. Returns null if ecosystem has no public registry URL. */
function purlFor(ecosystem, packageName) {
  if (!ecosystem || !packageName) return null;
  const enc = encodeURIComponent;
  switch (ecosystem) {
    case 'npm': {
      // @scope/name stays as @scope encoded, slash preserved between scope and name
      if (packageName.startsWith('@')) {
        const slash = packageName.indexOf('/');
        if (slash > 0) {
          const scope = packageName.slice(0, slash);
          const rest = packageName.slice(slash + 1);
          return `pkg:npm/${enc(scope)}/${enc(rest)}`;
        }
      }
      return `pkg:npm/${enc(packageName)}`;
    }
    case 'pypi':
      return `pkg:pypi/${enc(packageName.toLowerCase())}`;
    case 'go':
      // Preserve internal slashes, lowercase only the host segment
      return `pkg:golang/${packageName.split('/').map((seg, i) => i === 0 ? seg.toLowerCase() : enc(seg)).join('/')}`;
    case 'maven': {
      // GHSA emits group:artifact; purl spec wants pkg:maven/group/artifact
      const [group, artifact] = packageName.split(':');
      if (!group || !artifact) return `pkg:maven/${enc(packageName)}`;
      return `pkg:maven/${enc(group)}/${enc(artifact)}`;
    }
    case 'rubygems':
      return `pkg:gem/${enc(packageName)}`;
    case 'nuget':
      return `pkg:nuget/${enc(packageName)}`;
    case 'composer': {
      // vendor/name — slash preserved
      const [vendor, name] = packageName.split('/');
      if (!vendor || !name) return `pkg:composer/${enc(packageName)}`;
      return `pkg:composer/${enc(vendor)}/${enc(name)}`;
    }
    case 'rust':
      return `pkg:cargo/${enc(packageName)}`;
    case 'erlang':
      return `pkg:hex/${enc(packageName)}`;
    case 'pub':
      return `pkg:pub/${enc(packageName)}`;
    case 'swift':
      return `pkg:swift/${enc(packageName)}`;
    case 'actions': {
      // owner/name
      const [owner, name] = packageName.split('/');
      if (!owner || !name) return `pkg:github/${enc(packageName)}`;
      return `pkg:github/${enc(owner)}/${enc(name)}`;
    }
    default:
      return null;
  }
}

// ── GraphQL fetch with rate-limit handling ──────────────────────────────

async function fetchPage(after) {
  const resp = await fetch(GRAPHQL_URL, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${TOKEN_GHSA}`,
      'Content-Type': 'application/json',
      'Accept': 'application/vnd.github+json',
      'User-Agent': 'mitre-explorer-ghsa-sync',
    },
    body: JSON.stringify({
      query: QUERY,
      variables: { after, publishedSince: PUBLISHED_SINCE },
    }),
  });

  const remaining = parseInt(resp.headers.get('x-ratelimit-remaining') ?? '5000', 10);
  const reset = parseInt(resp.headers.get('x-ratelimit-reset') ?? '0', 10);

  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`GraphQL ${resp.status} ${resp.statusText}: ${body.slice(0, 500)}`);
  }

  const json = await resp.json();
  if (json.errors) {
    throw new Error(`GraphQL errors: ${JSON.stringify(json.errors).slice(0, 500)}`);
  }

  // Sleep if we're close to the rate limit
  if (remaining < 100 && reset > 0) {
    const sleepMs = Math.max(0, reset * 1000 - Date.now()) + 1000;
    console.log(`  rate limit low (${remaining} remaining), sleeping ${Math.round(sleepMs / 1000)}s...`);
    await new Promise((r) => setTimeout(r, sleepMs));
  }

  return json.data.securityAdvisories;
}

// ── DB helpers ──────────────────────────────────────────────────────────

async function upsertPackage(client, ecosystem, packageName) {
  const purl = purlFor(ecosystem, packageName);
  const result = await client.query(
    `INSERT INTO packages (ecosystem, package_name, purl)
     VALUES ($1, $2, $3)
     ON CONFLICT (ecosystem, package_name) DO UPDATE
       SET last_seen_at = NOW(),
           purl = COALESCE(EXCLUDED.purl, packages.purl)
       WHERE packages.last_seen_at < NOW() - interval '1 hour'
          OR packages.purl IS DISTINCT FROM EXCLUDED.purl
     RETURNING id`,
    [ecosystem, packageName, purl],
  );
  if (result.rows.length > 0) return result.rows[0].id;
  // No row returned from DO UPDATE WHERE (nothing changed) — SELECT to fetch id
  const fetch2 = await client.query(
    `SELECT id FROM packages WHERE ecosystem=$1 AND package_name=$2`,
    [ecosystem, packageName],
  );
  return fetch2.rows[0].id;
}

async function upsertAdvisory(client, adv) {
  // Try with cve_id; on FK violation, rollback savepoint and retry with NULL.
  await client.query('SAVEPOINT adv_upsert');
  try {
    await client.query(
      `INSERT INTO ghsa_advisories
         (ghsa_id, cve_id, summary, description, severity, cvss_score, cvss_vector,
          cvss_v4_score, cvss_v4_vector, published_at, upstream_updated_at, withdrawn_at,
          ghsa_enriched_at, row_updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW(), NOW())
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
        adv.ghsaId, adv.cveId, adv.summary, adv.description, adv.severity,
        adv.cvssScore, adv.cvssVector, adv.cvssV4Score, adv.cvssV4Vector,
        adv.publishedAt, adv.upstreamUpdatedAt, adv.withdrawnAt,
      ],
    );
    await client.query('RELEASE SAVEPOINT adv_upsert');
    return { cveNulled: false };
  } catch (err) {
    if (err && err.code === '23503' && adv.cveId) {
      await client.query('ROLLBACK TO SAVEPOINT adv_upsert');
      // Retry without cve_id (will reconcile next weekly sync when NVD catches up)
      await client.query(
        `INSERT INTO ghsa_advisories
           (ghsa_id, cve_id, summary, description, severity, cvss_score, cvss_vector,
            cvss_v4_score, cvss_v4_vector, published_at, upstream_updated_at, withdrawn_at,
            ghsa_enriched_at, row_updated_at)
         VALUES ($1, NULL, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW())
         ON CONFLICT (ghsa_id) DO UPDATE SET
           cve_id = NULL,
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
          adv.ghsaId, adv.summary, adv.description, adv.severity,
          adv.cvssScore, adv.cvssVector, adv.cvssV4Score, adv.cvssV4Vector,
          adv.publishedAt, adv.upstreamUpdatedAt, adv.withdrawnAt,
        ],
      );
      await client.query('RELEASE SAVEPOINT adv_upsert');
      return { cveNulled: true };
    }
    await client.query('ROLLBACK TO SAVEPOINT adv_upsert');
    throw err;
  }
}

async function upsertWeaknesses(client, ghsaId, cweIds) {
  // Insert new CWE mappings
  if (cweIds.length > 0) {
    await client.query(
      `INSERT INTO ghsa_weaknesses (ghsa_id, cwe_id)
       SELECT $1, unnest($2::text[])
       ON CONFLICT (ghsa_id, cwe_id) DO NOTHING`,
      [ghsaId, cweIds],
    );
  }
  // Delete orphans (previously linked CWEs no longer present)
  await client.query(
    `DELETE FROM ghsa_weaknesses
     WHERE ghsa_id = $1 AND cwe_id <> ALL($2::text[])`,
    [ghsaId, cweIds],
  );
}

async function upsertGhsaPackages(client, ghsaId, rows) {
  // rows: [{ packageId, vulnerableRange, fixedVersion }]
  if (rows.length > 0) {
    const packageIds = rows.map((r) => r.packageId);
    const ranges = rows.map((r) => r.vulnerableRange);
    const fixed = rows.map((r) => r.fixedVersion);
    // Insert; DO UPDATE fixed_version if changed
    await client.query(
      `INSERT INTO ghsa_packages (ghsa_id, package_id, vulnerable_range, fixed_version)
       SELECT $1, u.pkg::uuid, u.range_raw, u.fixed
       FROM unnest($2::uuid[], $3::text[], $4::text[]) AS u(pkg, range_raw, fixed)
       ON CONFLICT (ghsa_id, package_id, vulnerable_range_key) DO UPDATE
         SET fixed_version = EXCLUDED.fixed_version
         WHERE ghsa_packages.fixed_version IS DISTINCT FROM EXCLUDED.fixed_version`,
      [ghsaId, packageIds, ranges, fixed],
    );
  }
  // Delete orphans — rows in DB not in the new set
  const keys = rows.map((r) => [r.packageId, r.vulnerableRange ?? '']);
  await client.query(
    `DELETE FROM ghsa_packages
     WHERE ghsa_id = $1
       AND (package_id, vulnerable_range_key) NOT IN (
         SELECT u.pkg::uuid, u.rkey
         FROM unnest($2::uuid[], $3::text[]) AS u(pkg, rkey)
       )`,
    [ghsaId, keys.map((k) => k[0]), keys.map((k) => k[1])],
  );
}

// ── Sync-log helpers ────────────────────────────────────────────────────

async function insertLogStart(client) {
  await client.query(
    `UPDATE feed_sync_log SET status='error', completed_at=NOW(),
       error_message='Stale (auto-cleaned on new run start)'
     WHERE source='ghsa' AND status='running' AND started_at < NOW() - INTERVAL '4 hours'`,
  );
  const res = await client.query(
    `INSERT INTO feed_sync_log (source, status, started_at)
     VALUES ('ghsa', 'running', NOW()) RETURNING id`,
  );
  return res.rows[0].id;
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
      stats.advisories_updated,
      stats.errors,
      JSON.stringify({ ...stats, trigger: 'github-actions', mode: 'full' }),
      errorMessage?.slice(0, 500) ?? null,
      logId,
    ],
  );
}

// ── Main ────────────────────────────────────────────────────────────────

const client = new pg.Client({ connectionString: DATABASE_URL });
await client.connect();

const stats = {
  pages: 0,
  advisories_inserted: 0,
  advisories_updated: 0,
  packages_seen: 0,
  ghsa_weaknesses_rows: 0,
  ghsa_packages_rows: 0,
  rate_limit_waits: 0,
  unknown_ecosystems: 0,
  unknown_severities: 0,
  fk_null_fallbacks: 0,
  withdrawn_count: 0,
  errors: 0,
};

const startedAt = Date.now();
let logId;

try {
  // Neon cold-start warmup
  console.log('Warming up Neon connection...');
  await client.query('SELECT 1');

  logId = await insertLogStart(client);
  console.log(`feed_sync_log id=${logId}`);

  console.log(`Syncing GHSA advisories publishedSince=${PUBLISHED_SINCE}...`);
  let after = null;
  let hasNext = true;

  while (hasNext) {
    const page = await fetchPage(after);
    stats.pages++;
    const advisories = page.nodes;
    console.log(`Page ${stats.pages}: ${advisories.length} advisories`);

    await client.query('BEGIN');
    try {
      for (const node of advisories) {
        const ghsaId = node.ghsaId;
        const identifiers = node.identifiers ?? [];
        const cveId = identifiers.find((i) => i.type === 'CVE')?.value ?? null;
        const rawSeverity = node.severity;
        const severity = normalizeSeverity(rawSeverity);
        if (rawSeverity && !severity) stats.unknown_severities++;

        const adv = {
          ghsaId,
          cveId,
          summary: node.summary ?? null,
          description: node.description ?? null,
          severity,
          cvssScore: node.cvss?.score ?? null,
          cvssVector: node.cvss?.vectorString ?? null,
          // CVSS v4 currently not exposed on the SecurityAdvisory GraphQL type
          // in a stable form; leave columns null until GitHub documents it GA.
          cvssV4Score: null,
          cvssV4Vector: null,
          publishedAt: node.publishedAt,
          upstreamUpdatedAt: node.updatedAt ?? null,
          withdrawnAt: node.withdrawnAt ?? null,
        };

        if (adv.withdrawnAt) stats.withdrawn_count++;

        const advResult = await upsertAdvisory(client, adv);
        if (advResult.cveNulled) stats.fk_null_fallbacks++;
        stats.advisories_updated++;

        // CWE mappings
        const cweIds = (node.cwes?.nodes ?? []).map((c) => c.cweId).filter(Boolean);
        await upsertWeaknesses(client, ghsaId, cweIds);
        stats.ghsa_weaknesses_rows += cweIds.length;

        // Package mappings
        const vulnNodes = node.vulnerabilities?.nodes ?? [];
        const packageRows = [];
        for (const v of vulnNodes) {
          const ecosystem = normalizeEcosystem(v.package?.ecosystem);
          const packageName = v.package?.name;
          if (!ecosystem) {
            stats.unknown_ecosystems++;
            continue;
          }
          if (!packageName) continue;
          const packageId = await upsertPackage(client, ecosystem, packageName);
          stats.packages_seen++;
          const range = v.vulnerableVersionRange?.trim();
          packageRows.push({
            packageId,
            vulnerableRange: range && range.length > 0 ? range : null,
            fixedVersion: v.firstPatchedVersion?.identifier ?? null,
          });
        }
        await upsertGhsaPackages(client, ghsaId, packageRows);
        stats.ghsa_packages_rows += packageRows.length;
      }
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      stats.errors++;
      console.error(`  page ${stats.pages} failed, rolled back:`, err.message);
      throw err;
    }

    hasNext = page.pageInfo.hasNextPage;
    after = page.pageInfo.endCursor;
  }

  // Refresh mat view on a FRESH client. The original client may have been
  // idle for tens of minutes during the GraphQL crawl; Neon's idle reaper
  // can drop it just as the long REFRESH starts. Isolating the refresh on
  // a brand-new connection sidesteps that whole class of failure.
  console.log('Refreshing package_summary (concurrent, fresh client)...');
  const refreshClient = new pg.Client({ connectionString: DATABASE_URL });
  await refreshClient.connect();
  try {
    await refreshClient.query('REFRESH MATERIALIZED VIEW CONCURRENTLY package_summary');
  } finally {
    await refreshClient.end();
  }

  stats.elapsedMs = Date.now() - startedAt;
  console.log('\n=== Sync complete ===');
  console.log(JSON.stringify(stats, null, 2));
  if (logId) await updateLogDone(client, logId, 'success', stats, null);
} catch (err) {
  console.error('\nSync failed:', err);
  console.log(JSON.stringify(stats, null, 2));
  stats.elapsedMs = Date.now() - startedAt;
  if (logId) {
    try {
      await updateLogDone(client, logId, 'error', stats, err.message);
    } catch (logErr) {
      console.error('Also failed to write error log row:', logErr.message);
    }
  }
  process.exit(1);
} finally {
  await client.end();
}
