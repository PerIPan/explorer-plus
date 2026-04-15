# GitHub Security Advisories (GHSA) + Packages Integration — Design

**Date:** 2026-04-15
**Status:** v3.1 — third review pass applied; polish fixes for CTE orphan handling, composite-key diff-delete, first-sync docs
**Related:** [2026-04-08 OpenCRE research](./2026-04-08-opencre-research.md) (deferred)

## Problem

Mitre Explorer's CVE coverage is NVD-centric. NVD has structural gaps:

1. **~2,000 GitHub-only advisories** exist with no CVE ID at all. Actively-exploited open-source library vulnerabilities, invisible to our current pipeline.
2. **NVD often lacks curated CWE mappings** — many CVEs have no CWE or only generic `CWE-20`. Limits CAPEC→ATT&CK technique bridging for open-source exploits.
3. **NVD doesn't expose per-ecosystem package version metadata.** Our `affected_products` maps CVEs to vendor products via CPE; library-level queries like "is `npm/log4js-node@2.14.0` vulnerable?" aren't answerable.
4. **NVD publication lag** — GHSA often publishes days before a CVE is assigned.

The Applications feature succeeds at the vendor-product layer but misses the library layer (npm, PyPI, Go modules, Maven, RubyGems, NuGet, Composer, Rust crates) entirely. GHSA fills this gap.

## Goals

- Ingest GitHub Security Advisories (2017+) via direct GraphQL (no Vunnel Python pipeline)
- Surface the ~2K GHSA-only advisories at `/cti/ghsa`
- Introduce Packages as a first-class browse dimension at `/packages` (library-centric, parallel to vendor-centric Applications)
- Extend ATT&CK technique bridge to GHSA advisories via their CWE mappings
- Add "Affected Packages" sections to entity pages that have "Affected Applications"
- Enrich CVE detail when a GHSA alias exists (summary, fixed versions, package pointers)

## Non-Goals

- Don't adopt the Vunnel Python pipeline — only GHSA is worth pulling; direct GraphQL is simpler
- Don't ingest Linux distro advisories (Alpine, Debian, RedHat, Ubuntu, Oracle, SLES, Amazon, Azure, Mariner, Wolfi, Chainguard, Echo) — duplicate NVD CVEs without adding technique value
- Don't merge GHSAs into `cve_details` — library-package model doesn't fit vendor-product model
- Don't mix GHSAs into the landing "Recent Vulnerabilities" card (CVE-only)
- No CVSS v4 UI surfacing in MVP (data stored, display deferred)
- No reference-URL list per advisory in MVP
- No automatic Applications↔Packages linking in MVP (see Connection section)
- No ActorProfileView "Affected Packages" card in MVP (no data path — actors don't link to packages)

## Data Source

**Endpoint:** GitHub GraphQL at `https://api.github.com/graphql`

**Query:**
```graphql
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
      identifiers { type value }    # yields CVE alias when present
      summary
      description
      severity                       # LOW | MODERATE | HIGH | CRITICAL
      cvss { score vectorString }
      cvssV4 { score vectorString }  # nullable
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
```

**Auth:** Fine-grained PAT with public-read only, stored as `TOKEN_GHSA` GitHub Actions secret. Unlocks 5,000 req/h vs 60/h anonymous. Backfill needs ~130 paginated requests.

**Rate limit handling:** Inspect `X-RateLimit-Remaining` / `X-RateLimit-Reset` after each response; sleep to reset if < 100 remaining.

**Filter:** `publishedSince: "2017-01-01T00:00:00Z"` matches existing CVE coverage.

## Schema

### New extension

```sql
CREATE EXTENSION IF NOT EXISTS pg_trgm;
```

Required for substring search on `package_name` (see indexes below).

### `ecosystems` (reference table)

```sql
CREATE TABLE ecosystems (
  code text PRIMARY KEY,            -- lowercased: 'npm' | 'pypi' | 'go' | 'maven' | ...
  label text NOT NULL,              -- display name: 'npm' | 'PyPI' | 'Go' | 'Maven'
  url_template text,                -- e.g. 'https://www.npmjs.com/package/{name}'
  created_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO ecosystems (code, label, url_template) VALUES
  ('npm',      'npm',      'https://www.npmjs.com/package/{name}'),
  ('pypi',     'PyPI',     'https://pypi.org/project/{name}'),
  ('go',       'Go',       'https://pkg.go.dev/{name}'),
  ('maven',    'Maven',    'https://central.sonatype.com/artifact/{name}'),
  ('rubygems', 'RubyGems', 'https://rubygems.org/gems/{name}'),
  ('nuget',    'NuGet',    'https://www.nuget.org/packages/{name}'),
  ('composer', 'Composer', 'https://packagist.org/packages/{name}'),
  ('rust',     'crates.io','https://crates.io/crates/{name}'),
  ('erlang',   'Hex',      'https://hex.pm/packages/{name}'),
  ('pub',      'pub.dev',  'https://pub.dev/packages/{name}'),
  ('swift',    'Swift',     NULL),
  ('actions',  'GitHub Actions', NULL)
ON CONFLICT (code) DO NOTHING;
```

At ingest, an advisory referencing an unknown ecosystem code logs a warning and skips that package row (doesn't fail the advisory). New codes get added via a later PR after inspection.

### `packages` (dimension table)

```sql
CREATE TABLE packages (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ecosystem text NOT NULL REFERENCES ecosystems(code),
  package_name text NOT NULL,
  purl text,                                   -- Package URL, e.g. 'pkg:npm/log4js-node'
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (ecosystem, package_name)
);

CREATE INDEX idx_packages_ecosystem ON packages(ecosystem);
CREATE INDEX idx_packages_name_trgm ON packages USING gin (package_name gin_trgm_ops);
```

**Why a dimension table** (architect review HIGH): gives us a stable ID for FKs, a place to attach metadata later (homepage, repo, maintainer), a natural target for future watchlist / user-pinned features, and a `purl` column as the industry-standard bridge toward Applications/CPE without committing to the mapping today.

**Upsert at ingest:** insert-or-update by `(ecosystem, package_name)`, stamping `last_seen_at` only when stale (guard below).

**`purl` formatting is per-ecosystem** (not a single generic URL-encode — correctness issue flagged by architect review). The purl spec defines namespace-aware rules:

| Ecosystem | purl format | Example |
|---|---|---|
| `npm` | `pkg:npm/{name}` (scope encoded, `/` preserved) | `pkg:npm/%40angular/core` |
| `pypi` | `pkg:pypi/{name}` (lowercase name) | `pkg:pypi/django` |
| `go` | `pkg:golang/{name}` (path segments preserved) | `pkg:golang/github.com/foo/bar` |
| `maven` | `pkg:maven/{group}/{artifact}` (colon split → slash) | `pkg:maven/com.fasterxml.jackson.core/jackson-databind` |
| `rubygems` | `pkg:gem/{name}` | `pkg:gem/rails` |
| `nuget` | `pkg:nuget/{name}` | `pkg:nuget/Newtonsoft.Json` |
| `composer` | `pkg:composer/{vendor}/{name}` (slash in source) | `pkg:composer/symfony/symfony` |
| `rust` | `pkg:cargo/{name}` | `pkg:cargo/serde` |
| `erlang` | `pkg:hex/{name}` | `pkg:hex/phoenix` |
| `pub` | `pkg:pub/{name}` | `pkg:pub/http` |
| `swift` | `pkg:swift/{name}` | (rarely populated) |
| `actions` | `pkg:github/{owner}/{name}` | `pkg:github/actions/checkout` |

Implement as a `purlFor(ecosystem, packageName)` helper in the ingest script (single lookup table). Unknown ecosystems store `purl = NULL`.

**`last_seen_at` upsert guard** (postgres review — avoids WAL bloat from 25K unchanged-row writes every sync):

```sql
INSERT INTO packages (ecosystem, package_name, purl)
VALUES ($1, $2, $3)
ON CONFLICT (ecosystem, package_name) DO UPDATE
  SET last_seen_at = NOW(),
      purl = COALESCE(EXCLUDED.purl, packages.purl)
  WHERE packages.last_seen_at < NOW() - interval '1 hour'
     OR packages.purl IS DISTINCT FROM EXCLUDED.purl;
```

### `ghsa_advisories`

```sql
CREATE TABLE ghsa_advisories (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ghsa_id text NOT NULL UNIQUE,
  cve_id text,                                 -- nullable; FK when GHSA has CVE alias
  summary text,
  description text,
  severity varchar(20),                        -- CRITICAL | HIGH | MEDIUM | LOW (normalized)
  cvss_score numeric(3,1),
  cvss_vector text,
  cvss_v4_score numeric(3,1),
  cvss_v4_vector text,
  published_at timestamptz NOT NULL,
  upstream_updated_at timestamptz,             -- GHSA's updatedAt — renamed from prior spec to disambiguate
  withdrawn_at timestamptz,
  ghsa_enriched_at timestamptz NOT NULL DEFAULT now(),
  row_created_at timestamptz NOT NULL DEFAULT now(),
  row_updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (cve_id) REFERENCES cve_details(cve_id) ON DELETE SET NULL
);

CREATE INDEX idx_ghsa_adv_cve        ON ghsa_advisories(cve_id) WHERE cve_id IS NOT NULL;
CREATE INDEX idx_ghsa_adv_severity   ON ghsa_advisories(severity);
CREATE INDEX idx_ghsa_adv_cvss       ON ghsa_advisories(cvss_score DESC NULLS LAST);
CREATE INDEX idx_ghsa_adv_published  ON ghsa_advisories(published_at DESC);
CREATE INDEX idx_ghsa_adv_not_withdrawn ON ghsa_advisories(published_at DESC) WHERE withdrawn_at IS NULL;
```

**Naming notes** (postgres review):
- `row_created_at`, `row_updated_at` (our row lifecycle) — **never** `updated_at` alone to avoid collision with `upstream_updated_at`
- `upstream_updated_at` is GHSA's upstream `updatedAt`; clearly distinct

**Partial index flipped** to the hot path (`WHERE withdrawn_at IS NULL`) — default list queries hit it; withdrawn-specific queries go through a seq scan (tolerable at ~1% selectivity).

### `ghsa_weaknesses`

```sql
CREATE TABLE ghsa_weaknesses (
  ghsa_id text NOT NULL REFERENCES ghsa_advisories(ghsa_id) ON DELETE CASCADE,
  cwe_id varchar(20) NOT NULL,
  PRIMARY KEY (ghsa_id, cwe_id)
);

CREATE INDEX idx_ghsa_weaknesses_cwe ON ghsa_weaknesses(cwe_id);
```

Parallel to `cve_weaknesses`. Feeds the technique bridge via the materialized view below.

### `ghsa_packages`

```sql
CREATE TABLE ghsa_packages (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ghsa_id text NOT NULL REFERENCES ghsa_advisories(ghsa_id) ON DELETE CASCADE,
  package_id uuid NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
  vulnerable_range text,                       -- raw GraphQL string; NULL if upstream was empty/null
  -- Stored generated column so UNIQUE + ON CONFLICT work together.
  -- Plain UNIQUE INDEX on an expression is valid DDL, but Postgres
  -- ON CONFLICT cannot target expression indexes; needs a column.
  vulnerable_range_key text GENERATED ALWAYS AS (COALESCE(vulnerable_range, '')) STORED,
  fixed_version text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX uq_ghsa_packages
  ON ghsa_packages (ghsa_id, package_id, vulnerable_range_key);

CREATE INDEX idx_ghsa_packages_pkg  ON ghsa_packages(package_id);
CREATE INDEX idx_ghsa_packages_ghsa ON ghsa_packages(ghsa_id);
```

**Changes from v2:**
- `vulnerable_range_key` now a `GENERATED ALWAYS AS (COALESCE(vulnerable_range, '')) STORED` column — required for `ON CONFLICT (ghsa_id, package_id, vulnerable_range_key)` upserts to work (postgres review HIGH)
- `ON DELETE RESTRICT` → `ON DELETE CASCADE` on `package_id` — simpler cleanup path; packages without advisories will already be skipped by the summary view via its INNER JOIN

### Regular view — `unified_weaknesses`

```sql
-- Unified CWE lookup across CVE and GHSA sources. Regular VIEW, not materialized —
-- this is a trivial UNION ALL with zero aggregation, so materializing would only
-- add staleness (after CVE ingest, GHSA-side rows in a mat view would stay stale
-- until the weekly GHSA sync fires). A regular view is always fresh, and the
-- planner handles it as well as a materialized view for the access patterns below.
CREATE VIEW unified_weaknesses AS
SELECT cve_id  AS entity_id, cwe_id, 'cve'  AS source FROM cve_weaknesses
UNION ALL
SELECT ghsa_id AS entity_id, cwe_id, 'ghsa' AS source FROM ghsa_weaknesses;
```

The planner rewrites lookups by `entity_id` or `cwe_id` through to the underlying tables' indexes (verified existing via `\d`): `cve_weaknesses` has PK on `(cve_id, cwe_id)` + `idx_cve_weaknesses_cwe` on `cwe_id`; `ghsa_weaknesses` gets matching PK on `(ghsa_id, cwe_id)` + `idx_ghsa_weaknesses_cwe` in this spec. No new indexes needed on the view itself.

### Materialized view — `package_summary`

The aggregate is genuinely expensive (~50K ghsa_packages + ~13K advisories + weakness/CAPEC/technique joins with multi-column DISTINCTs). Materializing avoids paying that cost per request.

**Rewritten with CTEs to eliminate the cartesian explosion** (architect v2 HIGH — joining packages × advisories × weaknesses × CAPEC × techniques before aggregating inflates `advisory_count` by a factor of `weaknesses × techniques`):

```sql
CREATE MATERIALIZED VIEW package_summary AS
WITH pkg_adv AS (
  -- Per-package advisory-level aggregates (no weakness/technique joins yet)
  SELECT
    gp.package_id,
    COUNT(DISTINCT gp.ghsa_id)                                           AS advisory_count,
    MAX(g.published_at)                                                  AS latest_published,
    ARRAY_AGG(DISTINCT g.severity) FILTER (WHERE g.severity IS NOT NULL) AS severities
  FROM ghsa_packages gp
  JOIN ghsa_advisories g
    ON g.ghsa_id = gp.ghsa_id AND g.withdrawn_at IS NULL
  GROUP BY gp.package_id
),
pkg_tech AS (
  -- Per-package technique count via CWE → CAPEC bridge, computed separately
  SELECT
    gp.package_id,
    COUNT(DISTINCT cm.technique_id) AS technique_count
  FROM ghsa_packages gp
  JOIN ghsa_advisories g  ON g.ghsa_id = gp.ghsa_id AND g.withdrawn_at IS NULL
  JOIN ghsa_weaknesses w  ON w.ghsa_id = g.ghsa_id
  JOIN capec_mappings cm  ON cm.cwe_id = w.cwe_id AND cm.technique_id IS NOT NULL
  GROUP BY gp.package_id
)
SELECT
  p.id           AS package_id,
  p.ecosystem,
  p.package_name,
  p.purl,
  pa.advisory_count,
  pa.latest_published,
  COALESCE(pa.severities, ARRAY[]::text[]) AS severities,
  COALESCE(pt.technique_count, 0) AS technique_count
FROM packages p
JOIN pkg_adv       pa ON pa.package_id = p.id   -- INNER JOIN: drops packages with zero active advisories
LEFT JOIN pkg_tech pt ON pt.package_id = p.id;  -- LEFT JOIN: keep rows when no CAPEC bridge (technique_count = 0)

CREATE UNIQUE INDEX uq_package_summary          ON package_summary(package_id);
CREATE INDEX idx_package_summary_eco            ON package_summary(ecosystem);
CREATE INDEX idx_package_summary_count          ON package_summary(advisory_count DESC);
CREATE INDEX idx_package_summary_name_trgm      ON package_summary USING gin (package_name gin_trgm_ops);
```

**Refresh strategy:**
- Migration SQL runs `REFRESH MATERIALIZED VIEW package_summary` (non-concurrent) immediately after `CREATE MATERIALIZED VIEW` — `CONCURRENTLY` requires existing rows, so the first refresh must be non-concurrent (postgres + architect v2 HIGH)
- Every subsequent refresh from the sync script uses `REFRESH MATERIALIZED VIEW CONCURRENTLY package_summary`
- **Realistic refresh time:** 30-90 seconds at production scale (25K packages joining 50K ghsa_packages × 13K advisories × ~15K weaknesses × CAPEC). Earlier estimate of "~2s" was wrong (postgres review). Monitor via `pg_stat_activity` during sync; `CONCURRENTLY` takes `ExclusiveLock` but not `AccessExclusiveLock`, so reads continue.
- **Mid-sync failure policy:** if the sync fails partway (rate limit, transient GraphQL error, etc.), the materialized view stays at the last successful refresh state. No refresh-at-start. Operators re-run manually. Staleness is acceptable given weekly cadence.
- **First-sync edge case:** the migration runs `CREATE MATERIALIZED VIEW package_summary` followed by a non-concurrent `REFRESH` — but because no `ghsa_*` data exists yet at migration time, that first refresh produces **zero rows**. `/packages` returns an empty list until the first successful sync run populates the underlying tables and the sync script issues a concurrent refresh at its end. If the very first backfill sync fails partway, `/packages` stays empty (not stale) until a manual re-run completes. Operators must verify a successful first-sync post-deployment; document in `feeds_setup.md` alongside the sync command.

### Column-name correction (propagates throughout)

**Existing `capec_mappings` schema** (verified against codebase):
```
capec_mappings(cwe_id, capec_id, technique_id uuid → techniques.id, ...)
```

No `attack_technique_id` column on `capec_mappings`. The ATT&CK ID is on `techniques.attack_id`. All SQL in v1 that referenced `cm.attack_technique_id` was wrong; v2 uses:
```sql
... cm.technique_id IS NOT NULL
JOIN techniques t ON t.id = cm.technique_id
-- then expose t.attack_id, t.name
```

This pattern matches every existing caller (`cves/route.ts`, `feed/intelligence/`, `frameworks/owasp/`).

## Ingest Script

**File:** `scripts/sync-ghsa.mjs`

**Flow:**
1. Read `TOKEN_GHSA` env var; exit non-zero if missing
2. Open DB connection; run `SELECT 1` warmup to absorb Neon cold-start
3. Paginate GraphQL: 100 advisories per page, cursor-based
4. **Per-page transaction** (not per advisory): `BEGIN` → upsert all 100 advisories + child rows → `COMMIT`
5. For each advisory within the page transaction:
   - Extract CVE alias from `identifiers[]` (`type: 'CVE'`)
   - Normalize severity: `MODERATE` → `MEDIUM`. Reject anything outside `['CRITICAL','HIGH','MEDIUM','LOW']` → log warning, store NULL
   - Normalize ecosystem: lowercase; reject unknown codes → log warning, skip that package row (don't fail advisory)
   - Normalize `vulnerableVersionRange`: empty string → NULL
   - Compute `purl` for each package: `pkg:{ecosystem}/{url-encoded name}`
   - **FK race handling for `cve_id`:** attempt upsert with CVE ID inside a savepoint; on `23503` FK violation, rollback savepoint and re-upsert with `cve_id = NULL` (reconciles on next weekly sync when NVD catches up)
   - Upsert `packages` rows via `ON CONFLICT (ecosystem, package_name) DO UPDATE SET last_seen_at = NOW()`
   - Upsert `ghsa_advisories` via `ON CONFLICT (ghsa_id) DO UPDATE`
   - For `ghsa_weaknesses` and `ghsa_packages`: **diff-based upsert per-advisory**. Explicitly sequenced so we never see zero rows for an advisory mid-transaction (postgres v2 review):
     ```sql
     -- after computing new_cwe_ids[] for this advisory:
     INSERT INTO ghsa_weaknesses (ghsa_id, cwe_id)
     SELECT $1, unnest($2::text[])
     ON CONFLICT (ghsa_id, cwe_id) DO NOTHING;

     DELETE FROM ghsa_weaknesses
     WHERE ghsa_id = $1
       AND cwe_id <> ALL($2::text[]);
     ```
     Both statements issued **per-advisory**, immediately after that advisory's INSERT — not deferred to end-of-page.

     For `ghsa_packages`, the composite `(package_id, vulnerable_range_key)` tuple set requires a row-constructor (Postgres' `<> ALL` doesn't work on tuples in this form):
     ```sql
     -- $2 = array of package_id (uuid[]), $3 = array of vulnerable_range_key (text[])
     -- $2 and $3 are parallel arrays of the same length
     INSERT INTO ghsa_packages (ghsa_id, package_id, vulnerable_range, fixed_version)
     SELECT $1, (u.pkg)::uuid, u.range_raw, u.fixed
     FROM unnest($2::uuid[], $4::text[], $5::text[]) AS u(pkg, range_raw, fixed)
     ON CONFLICT (ghsa_id, package_id, vulnerable_range_key) DO UPDATE
       SET fixed_version = EXCLUDED.fixed_version
       WHERE ghsa_packages.fixed_version IS DISTINCT FROM EXCLUDED.fixed_version;

     DELETE FROM ghsa_packages
     WHERE ghsa_id = $1
       AND (package_id, vulnerable_range_key) NOT IN (
         SELECT u.pkg::uuid, u.rkey
         FROM unnest($2::uuid[], $3::text[]) AS u(pkg, rkey)
       );
     ```
     The DELETE uses the same `(ghsa_id, package_id, vulnerable_range_key)` keyset as the unique index, ensuring orphan rows are reliably identified.
6. After last page: `REFRESH MATERIALIZED VIEW CONCURRENTLY package_summary;`. `unified_weaknesses` is a regular view — no refresh needed.
7. Log summary `{ advisories_inserted, advisories_updated, advisories_withdrawn, packages_inserted, packages_updated, ghsa_weaknesses_added, ghsa_packages_added, ghsa_packages_removed, rate_limit_waits, unknown_ecosystems, unknown_severities, fk_null_fallbacks }`

**Per-page transaction rationale:** 13K advisories ÷ 100 per page = 130 transactions. At 30-50ms Neon pooler RTT, total transaction overhead is ~6 seconds instead of 6-11 minutes with per-advisory transactions.

**Run modes:**
- Manual: `TOKEN_GHSA=... DATABASE_URL=... node scripts/sync-ghsa.mjs`
- Weekly: GitHub Action `sync-ghsa.yml` (Mondays 06:00 UTC)

**Concurrency:** workflow has `concurrency: { group: sync-ghsa, cancel-in-progress: false }` so overlapping manual + scheduled runs queue rather than race.

## API Routes

All follow existing `/api/v1/*` patterns: `handler` + `withCors` + `jsonResponse(data, CACHE_TTL)`.

### `GET /api/v1/ghsa` — paginated list

Filters: `ecosystem`, `severity`, `since`, `q` (full-text on `summary || description`), `has_cve`, `package`, `include_withdrawn`.

Response: `PaginatedResponse<GhsaEntry>`
```ts
interface GhsaEntry {
  ghsaId: string;
  cveId: string | null;
  summary: string | null;
  severity: string | null;           // CRITICAL | HIGH | MEDIUM | LOW | null
  cvssScore: number | null;
  publishedAt: string;               // non-null — column is NOT NULL
  withdrawnAt: string | null;
  packageCount: number;
  ecosystems: string[];
  techniqueCount: number;            // from unified_weaknesses + capec_mappings + techniques
}
```

Default `WHERE withdrawn_at IS NULL`; `?include_withdrawn=1` removes the filter.

### `GET /api/v1/ghsa/:ghsaId` — detail

**Always returns the advisory, even if withdrawn** (so direct links never 404; UI shows a "withdrawn" banner).

```ts
interface GhsaDetail extends GhsaEntry {
  description: string | null;
  cvssVector: string | null;
  cvssV4Score: number | null;
  cvssV4Vector: string | null;
  cwes: string[];
  packages: Array<{
    ecosystem: string;
    packageName: string;
    purl: string | null;
    vulnerableRange: string | null;
    fixedVersion: string | null;
  }>;
  techniques: Array<{ attackId: string; name: string }>;
}
```

### `GET /api/v1/packages` — aggregated list

Reads from `package_summary` materialized view. Filters: `ecosystem`, `q`, `page`, `limit`.

```sql
SELECT
  package_id     AS "packageId",
  ecosystem,
  package_name   AS "packageName",
  purl,
  advisory_count AS "advisoryCount",
  latest_published AS "latestPublished",
  severities,
  technique_count AS "techniqueCount"
FROM package_summary
WHERE ($1::text IS NULL OR ecosystem = $1)
  AND ($2::text IS NULL OR package_name ILIKE '%' || $2 || '%')
ORDER BY advisory_count DESC, latest_published DESC NULLS LAST
LIMIT $3 OFFSET $4;
```

pg_trgm GIN index on `package_name` makes the ILIKE plannable even with leading wildcard.

### `GET /api/v1/packages/:ecosystem/:nameEncoded` — detail

**URL shape change from v1:** single URL-encoded segment for the package name (not catch-all). Avoids Next.js catch-all quirks with Maven `group:artifact` and npm `@scope/name`.

- Client generates URLs via `encodeURIComponent(packageName)`:
  - `/packages/npm/log4js-node`
  - `/packages/npm/%40angular%2Fcore` → decoded `@angular/core`
  - `/packages/maven/com.fasterxml.jackson.core%3Ajackson-databind` → decoded `com.fasterxml.jackson.core:jackson-databind`
- Route handler: `decodeURIComponent(params.nameEncoded)` before querying

```ts
interface PackageDetail {
  ecosystem: string;
  packageName: string;
  purl: string | null;
  advisoryCount: number;
  severityCounts: Record<string, number>;  // { HIGH: 2, MEDIUM: 5 }
  advisories: Array<GhsaEntry & {
    vulnerableRange: string | null;
    fixedVersion: string | null;
  }>;
  linkedTechniques: Array<{ attackId: string; name: string }>;
}
```

Filters withdrawn advisories by default; `?include_withdrawn=1` shows them.

### `GET /api/v1/cves/:cveId/packages` — new route

Returns just the GHSA-derived packages for a given CVE. Purpose: A2A `cve-to-packages` skill, and keeps the main `/cves/:cveId` response lean.

```ts
interface CvePackagesResponse {
  cveId: string;
  ghsaId: string | null;
  packages: Array<{
    ecosystem: string;
    packageName: string;
    purl: string | null;
    vulnerableRange: string | null;
    fixedVersion: string | null;
  }>;
}
```

### Modified: `GET /api/v1/cves/:cveId` — minimal GHSA stub

To preserve endpoint boundaries (architect HIGH), we return a minimal stub, **not** a full embedded GHSA object:

```ts
// Added field on existing CveDetail response
ghsa: { ghsaId: string; summary: string | null } | null
```

Full GHSA detail (description, packages, CVSS v4, etc.) lives at `/api/v1/ghsa/:ghsaId`. UI enrichment card fetches it on demand after seeing `hasGhsa: true`.

### TypeScript types — `src/lib/types.ts`

New interfaces: `GhsaEntry` (list rows), `GhsaDetail` (extends `GhsaEntry`), `PackageDetail`, `CvePackagesResponse`. The package list endpoint reuses an inline extension of `GhsaEntry` with `vulnerableRange` + `fixedVersion` — no separate `PackageListEntry` needed.

Extend existing `CveDetail` with optional `ghsa?: { ghsaId: string; summary: string | null } | null`.

New hooks in `src/hooks/useApi.ts`: `useGhsa(params)`, `useGhsaDetail(ghsaId)`, `usePackages(params)`, `usePackageDetail(ecosystem, nameEncoded)`, `useCvePackages(cveId)`. All follow the existing `useCves` / `useCveDetail` pattern.

## UI Changes

### New pages

- **`/cti/ghsa`** — list, mirrors `/cti/cves` (PageHeader + filter chips + DataTable). Columns: Severity | GHSA ID | CVE alias | Summary | Ecosystems | Packages | CVSS | Published | Techniques
- **`/cti/ghsa/:ghsaId`** — detail. Shows withdrawn banner when applicable. Always rendered regardless of withdrawn status.
- **`/packages`** — list from `package_summary`. Columns: Ecosystem | Package | Advisories | Severities | Latest | Techniques
- **`/packages/:ecosystem/:nameEncoded`** — detail (single encoded segment, not catch-all)

### Sidebar

```ts
// assetsNav
{ path: '/packages', label: 'Packages', tooltip: 'library/dependency packages with GHSA advisories (npm, PyPI, Go, Maven, RubyGems, NuGet, Composer, Rust, Hex, pub, Swift, Actions)' }

// ctiNav
{ path: '/cti/ghsa', label: 'GHSA', tooltip: 'GitHub Security Advisories — library-level vulnerabilities' }
```

Both routes use static App Router files (`app/packages/page.tsx`, `app/cti/ghsa/page.tsx`) at the same level as existing dynamic segments — static beats dynamic, no routing collision.

### "Affected Packages" card on entity pages

Inserted parallel to existing "Affected Applications" blocks on:

1. `src/components/relationships/TechniqueMapView.tsx` (around line 960) — queries packages whose GHSAs bridge (via `unified_weaknesses` + CAPEC) to this technique
2. `src/components/relationships/OwaspMapView.tsx` (around line 269) — filtered by the OWASP category's CWE set
3. `src/views/CveDetail.tsx` — Packages tab alongside existing Applications tab; populated from `/api/v1/cves/:cveId/packages`

**Not in MVP:** `ActorProfileView.tsx` — actors don't link to packages via any data path; deferred explicitly.

### CVE detail enrichment card

Rendered when the main `/cves/:cveId` response has `ghsa: { ghsaId, summary }`. The collapsible card fetches full GHSA details lazily on expand.

**Fetch pattern:** uses `useQuery` via the existing `useGhsaDetail(ghsaId)` hook in `src/hooks/useApi.ts` (to be added). Same TanStack Query pattern as `useCveDetail`. This gives automatic deduplication of concurrent expand events, consistent loading/error states, and shared cache across multiple pages that view the same GHSA (e.g. user expands it on CVE detail then navigates to `/cti/ghsa/:id`). No raw `fetch` in `useEffect`.

Loading state: existing `DiamondLoader`. Error state: inline message with retry button; card otherwise collapses back to the stub.

```
┌─────────────────────────────────────────────────────────────┐
│ GitHub Advisory                                             │
│ [GHSA-jfh8-c2jp-5v3q ↗]  [HIGH]  [CVSS 7.5]                │
│                                                             │
│ Curated summary from GitHub Security Lab...                 │
│                                                             │
│ [Expand for full description + packages →]                 │
└─────────────────────────────────────────────────────────────┘
```

## Technique Bridge

Existing code that used `cve_weaknesses` directly gets migrated to `unified_weaknesses`:

```sql
SELECT uw.entity_id, uw.cwe_id, uw.source
FROM unified_weaknesses uw
WHERE uw.entity_id = $1;
```

**Graceful degradation for pre-migration environments** — resolved with a single mechanism (v2 had redundant try/catch + warmup probe; architect flagged the duplication):

Module-level one-shot capability probe cached for the process lifetime. Check runs once per cold-start, not per request (fullstack v2 review):

```ts
// src/app/api/lib/unifiedWeaknesses.ts
let _unifiedViewExists: boolean | null = null;

export async function hasUnifiedWeaknessesView(): Promise<boolean> {
  if (_unifiedViewExists !== null) return _unifiedViewExists;
  const r = await query<{ exists: boolean }>(
    `SELECT to_regclass('public.unified_weaknesses') IS NOT NULL AS exists`
  );
  _unifiedViewExists = r.rows[0]?.exists ?? false;
  return _unifiedViewExists;
}
```

Callers use the helper to branch:
```ts
const sql = (await hasUnifiedWeaknessesView())
  ? `SELECT entity_id, cwe_id, source FROM unified_weaknesses WHERE entity_id = $1`
  : `SELECT cve_id AS entity_id, cwe_id, 'cve' AS source FROM cve_weaknesses WHERE cve_id = $1`;
```

**Cache scope:** process-lifetime only. On Vercel serverless, each lambda cold-start reruns the check once. Since `to_regclass` is sub-millisecond against a cached system catalog, the overhead is negligible (~0.5ms per cold-start). The cache does not survive a rollback/drop of the view — if a post-deploy migration removes `unified_weaknesses`, warm instances will continue using it until recycled; a redeploy invalidates all caches.

## A2A Agent Skills

Updates **both** places — each uses its own naming convention (fullstack v2 review verified against current codebase):

1. **`public/.well-known/agent-card.json`** — skill descriptors for external agent discovery.
   **Uses kebab-case** to match existing entries (`cve-lookup`, `technique-intelligence`, `application-security`).
2. **`TOOL_DECLARATIONS` array in `app/api/a2a/route.ts`** — function declarations the Gemini model invokes.
   **Uses snake_case** to match existing entries (`search_cves`, `get_cve_detail`, `get_technique_intelligence`).

| Agent-card ID (kebab) | TOOL_DECLARATIONS name (snake) | Purpose | Backing endpoint |
|---|---|---|---|
| `ghsa-lookup` | `get_ghsa_detail` | Lookup GHSA by ID | `/api/v1/ghsa/:ghsaId` |
| `package-vulnerabilities` | `get_package_vulnerabilities` | Vulns affecting a specific package | `/api/v1/packages/:ecosystem/:nameEncoded` |
| `ghsa-search` | `search_ghsa` | List advisories (filters: since, severity, ecosystem) | `/api/v1/ghsa?...` |
| `cve-to-packages` | `cve_to_packages` | Packages for a CVE via GHSA alias | `/api/v1/cves/:cveId/packages` (single server-side join) |

Each tool declaration maps its `name` to the handler that forwards to the backing endpoint. Response format follows existing A2A conventions (plain-text summary + optional `application/json`).

## Connection Between Applications and Packages

**Decision: no automatic linking in MVP** (Option 1 — architect agrees).

- Applications: `(vendor, product)` CPE-derived
- Packages: `(ecosystem, package_name)` GHSA-derived + purl
- No public authoritative mapping exists (NVD doesn't publish CPE-to-npm; GitHub doesn't publish package-to-CPE)

**`purl` stored now for future flexibility.** purl is the industry standard that bridges to CPE/SBOM tooling. Storing it today costs one column; unlocks automatic or semi-automatic linking later without a migration.

Rejected alternatives:
- *Heuristic name matching* — noisy false positives (`log4j` vs `log4js-node`)
- *Manual mapping table* — high maintenance, unclear ROI until user demand surfaces

Organic navigation via CVE pivot is preserved:
- `/applications/:slug` → CVE detail → (if GHSA alias) GHSA detail → packages
- `/packages/:ecosystem/:name` → GHSA detail → (if CVE alias) CVE detail → applications
- CVE detail shows both in adjacent sections

## Feed Status

Three new entries in `src/views/FeedStatus.tsx` `FRAMEWORK_TABLES`:
```ts
{ key: 'ghsa_advisories', label: 'GitHub Security Advisories' },
{ key: 'ghsa_weaknesses', label: 'GHSA CWE Mappings' },
{ key: 'ghsa_packages',   label: 'GHSA Affected Packages' },
```

In `/api/v1/frameworks/status/route.ts`, a **separate** try/catch block for GHSA tables (not merged into existing CSF-enrichment catch). Matches pattern: one block per feature-set — a single missing table doesn't fallback-zero unrelated counts.

## Error Handling

- **GraphQL transport errors:** fail loud, non-zero exit, GitHub Action surfaces failure
- **Rate limit hit mid-sync:** sleep to `X-RateLimit-Reset`, resume
- **Per-advisory savepoint:** one bad advisory rolls back only that advisory; page transaction continues with the rest
- **Missing `TOKEN_GHSA`:** fail immediately with clear message
- **CVE FK violation:** savepoint rollback → retry with `cve_id = NULL`; reconciles next weekly run
- **Unknown ecosystem:** log, skip that package row, advisory still written
- **Unknown severity:** log, store NULL, advisory still written
- **Empty `vulnerableVersionRange`:** normalized to NULL

## Caching

- List endpoints: 5-minute CDN cache
- Detail endpoints: 1-hour CDN cache
- `package_summary` refreshed at end of each sync (weekly) — user-visible staleness up to 1 hour on first detail fetch post-sync, acceptable

## Phased Delivery

Single bundled MVP — all items ship together. Ordering within the bundle:

1. Schema migration SQL (extension, ecosystems, packages, ghsa_*, materialized views, indexes)
2. Seed `ecosystems` table
3. Ingest script `scripts/sync-ghsa.mjs` — manual verification run, spot-check data
4. API routes (5 new, 1 modified)
5. TypeScript type additions in `src/lib/types.ts`
6. New UI pages (`/cti/ghsa`, `/packages` list + details)
7. Sidebar nav additions
8. Entity-page "Affected Packages" cards (Technique 360, OWASP 360, CVE detail)
9. CVE detail enrichment card
10. A2A skill registration (both places)
11. Feed Status entries + separate try/catch
12. GitHub Actions workflow with concurrency guard
13. `docs/feeds_setup.md` update

## Post-Launch Verification (not blocking)

- Run `SELECT COUNT(DISTINCT w.cwe_id) FROM ghsa_weaknesses w LEFT JOIN capec_mappings cm ON cm.cwe_id = w.cwe_id WHERE cm.cwe_id IS NULL` — quantify CAPEC-miss rate; if > 30%, consider CWE→CAPEC coverage work
- Confirm `\d cve_details` referenced-by graph has no unexpected CASCADE that would null-out GHSA rows
- EXPLAIN `WHERE published_at >= $1 ORDER BY published_at DESC` uses existing DESC index

## Dependencies

- `TOKEN_GHSA` GitHub Actions secret (created 2026-04-15)
- `pg_trgm` extension (new — standard Postgres extension, available on Neon)
- No new npm packages
- No breaking changes to existing tables

## Deferred / Rejected

- **`vulnerabilities` supertype view** (architect MED) — premature with only 2 sources; revisit if OSV/NVD-only reporting becomes a UI requirement
- **`last_synced_at` on every API response** (architect LOW) — ops visibility already via feed_status
- **Full CVE→GHSA bidirectional enrichment on CVE list page** — MVP uses the stub only
- **CVSS v4 UI display** — data stored, rendering deferred until > 50% of newer advisories expose it
- **`ghsa_references` URL table** — not in MVP
- **Automatic Applications↔Packages mapping** — explicitly Option 1 (no linking)
- **`ActorProfileView` "Affected Packages" card** — no data path, deferred

## Risks

1. **GraphQL schema evolution** — mitigated by per-advisory savepoints + unknown-value allowlists
2. **Weekly CVE FK reconcile lag** — GHSAs referencing very new CVEs stay orphaned until next run; acceptable given weekly cadence
3. **Package name collisions across ecosystems** — `(ecosystem, package_name)` uniqueness everywhere prevents this
4. **Materialized view refresh contention** — CONCURRENTLY refresh takes an `ExclusiveLock` but not `AccessExclusiveLock`, so readers continue; first sync after view creation must use non-concurrent refresh once to populate
5. **Withdrawn advisory visibility** — default-hidden in lists, always shown on detail page (prevents orphan 404s); banner on the detail view
6. **Neon serverless cold-start** — `SELECT 1` warmup at sync start; detail-endpoint cold-start unchanged (dealt with by platform)
7. **`pg_trgm` extension privilege** — confirm Neon role can `CREATE EXTENSION`; if not, use btree fallback + accept seq scans at current scale

## Open Questions

None — all previously raised questions resolved in v2.

---

## Revision history

**v3 → v3.1 changes (polish pass):**
- `package_summary` top-level `LEFT JOIN pkg_adv` → `INNER JOIN pkg_adv` — drops packages whose only advisories are withdrawn (architect v3 MED; also retires the v2 orphan-packages concern cleanly)
- `ghsa_packages` diff-delete SQL spelled out with row-constructor `(package_id, vulnerable_range_key) NOT IN (...)` pattern — plain `<> ALL` doesn't work on composite tuples (architect v3 INFO)
- Clarified module-level `hasUnifiedWeaknessesView` cache is process-lifetime; resets on serverless cold-start (architect + fullstack v3 LOW) — the earlier "never re-runs" claim was inaccurate on Vercel serverless
- Confirmed `cve_weaknesses(cwe_id)` index exists (`idx_cve_weaknesses_cwe`); spec now notes this inline so readers don't rediscover the question (postgres v3 MED)
- Documented first-sync edge case explicitly: migration creates empty materialized view; `/packages` is **empty (not stale)** until first successful sync completes. Operator checklist item added (fullstack v3 MED)

**v2 → v3 changes:**
- Schema: `ghsa_packages` now uses `vulnerable_range_key` generated column (STORED) for unique index + `ON CONFLICT` support (postgres v2 HIGH — expression unique indexes are syntactically valid but can't target `ON CONFLICT`)
- Schema: `ghsa_packages.package_id` FK changed `ON DELETE RESTRICT` → `ON DELETE CASCADE` (architect v2 LOW)
- `unified_weaknesses` demoted from MATERIALIZED VIEW to regular VIEW — no aggregation justified materialization, regular view is always fresh and equally plannable (architect v2 MED)
- `package_summary` rewritten with CTE-based per-package aggregates to eliminate cartesian explosion from joining weaknesses × CAPEC × techniques before aggregating (architect v2 HIGH)
- Migration SQL must run non-concurrent `REFRESH MATERIALIZED VIEW package_summary` after CREATE; subsequent syncs use `CONCURRENTLY` (postgres + architect v2 HIGH — first concurrent refresh fails on empty view)
- Realistic refresh time estimate corrected to 30-90s (postgres v2 MED — prior "2s" was wrong at scale)
- `packages.last_seen_at` upsert gets a `WHERE` guard to skip unchanged rows (postgres v2 MED — prior unconditional UPDATE caused 25K WAL writes per sync)
- Diff-based upsert for `ghsa_weaknesses` / `ghsa_packages` now specified as **per-advisory SQL** (not deferred to end-of-page), with explicit INSERT ... ON CONFLICT + DELETE ... WHERE cwe_id <> ALL (postgres v2 MED)
- A2A section corrected: `agent-card.json` uses kebab-case skill IDs matching existing entries; `TOOL_DECLARATIONS` uses snake_case matching existing entries (fullstack v2 HIGH — prior spec wrongly used snake_case for both)
- Technique bridge graceful degradation consolidated to single mechanism: module-level cached `to_regclass` probe (not redundant try/catch + warmup; architect + fullstack v2 MED)
- `purl` formatting specified per-ecosystem with lookup table; generic URL-encode was incorrect for Maven `group:artifact` and Go paths (architect v2 LOW)
- CVE detail enrichment card specified to use `useQuery` pattern (new `useGhsaDetail` hook); removed ambiguity about loading/error states (fullstack v2 LOW)
- Removed unused `PackageListEntry` interface; list endpoint reuses inline `GhsaEntry` extension (fullstack v2 LOW)
- Added new hooks list: `useGhsa`, `useGhsaDetail`, `usePackages`, `usePackageDetail`, `useCvePackages`
- Documented mid-sync failure policy: materialized view stays at last-successful state; no refresh-at-start; operators re-run manually (fullstack v2 MED)
- Dropped redundant `idx_unified_weaknesses_entity` (no longer relevant — regular view has no indexes)

**v1 → v2 changes:**
- Schema: added `ecosystems`, `packages` dimension tables; added `purl` column; fixed `UNIQUE ... COALESCE` to `CREATE UNIQUE INDEX`; flipped withdrawn partial index to hot path; renamed `updated_at_upstream` → `upstream_updated_at` and our row timestamps to `row_created_at`/`row_updated_at`
- Added `pg_trgm` extension + GIN index for ILIKE search
- Added two materialized views: `unified_weaknesses`, `package_summary`
- Fixed all SQL column references: `cm.technique_id` + JOIN `techniques`, never `cm.attack_technique_id`
- Changed `/packages/[...slug]` catch-all to `/packages/:ecosystem/:nameEncoded` single encoded segment
- Changed CVE detail to return **minimal GHSA stub** only; added dedicated `/cves/:cveId/packages` endpoint
- Changed ingest: per-page transactions (not per-advisory), savepoint + FK violation retry, diff-based upsert (not delete+reinsert), severity/ecosystem allowlists, empty-string → NULL normalization, `SELECT 1` warmup
- Changed technique bridge: callers use `unified_weaknesses` view with handler-level graceful fallback (not in-SQL UNION)
- Added `TOOL_DECLARATIONS` registration requirement for A2A (not only agent-card.json)
- Added GitHub Action `concurrency:` guard
- Changed feed-status: separate try/catch per feature-set
- Removed `ActorProfileView` from MVP insertion points
- Documented explicit TypeScript type updates for `CveDetail`
