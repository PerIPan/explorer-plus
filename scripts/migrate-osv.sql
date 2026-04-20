-- scripts/migrate-osv.sql
--
-- OSV ingest — NON-GHSA ECOSYSTEMS ONLY.
--
-- Scope decision (2026-04-20): OSV mirrors the reviewed subset of GHSA for
-- npm/PyPI/Maven/Go/NuGet/RubyGems/Packagist/crates.io/Pub/Hex/GitHub Actions.
-- Our `ghsa_advisories` table already has all of those. The unique value in
-- OSV lives in the OS-level & distro ecosystems (Linux, Android, Debian,
-- Alpine, Ubuntu, Rocky, Alma, SUSE, openSUSE, openEuler, Bitnami, OSS-Fuzz,
-- Haskell, GHC, CRAN, SwiftURL, UVI, Wolfi, Chainguard, etc.).
--
-- The ingest script filters ecosystems at fetch time, plus drops any record
-- whose aliases[] intersects an existing ghsa_id. That means we NEVER store
-- a row that overlaps with ghsa_advisories — no dedup matview needed.
--
-- Apply via direct (non-pooler) Neon URL:
--   PGPASSWORD=... psql "$DIRECT_URL" -f scripts/migrate-osv.sql

CREATE TABLE IF NOT EXISTS osv_advisories (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  osv_id         text NOT NULL,                    -- 'LBSEC-2024-0001', 'DSA-5678-1', ...
  ecosystem      text NOT NULL,                    -- 'Linux', 'Debian', 'Alpine', ...
  aliases        text[],                           -- CVE IDs + upstream tracker IDs
  summary        text,
  details        text,
  severity_raw   jsonb,                            -- OSV `severity[]` array verbatim
  cvss_vector    text,                             -- parsed CVSS v3.x vector when present
  cvss_score     numeric(3,1),                     -- computed from vector at ingest
  cvss_severity  text,                             -- LOW / MEDIUM / HIGH / CRITICAL
  published      timestamptz,
  modified       timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  -- Composite key: same advisory can appear in multiple per-ecosystem zips
  -- (rare across non-GHSA ecos, but OSS-Fuzz / cross-distro references do it).
  UNIQUE (osv_id, ecosystem)
);

CREATE INDEX IF NOT EXISTS idx_osv_cvss_score ON osv_advisories(cvss_score DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS idx_osv_ecosystem  ON osv_advisories(ecosystem);
CREATE INDEX IF NOT EXISTS idx_osv_modified   ON osv_advisories(modified DESC NULLS LAST);
-- Common filter on the unified /api/v1/advisories list is `published >= $n`.
-- Without this index a `since` filter seq-scans the whole table.
CREATE INDEX IF NOT EXISTS idx_osv_published   ON osv_advisories(published DESC NULLS LAST);
-- GIN on aliases powers the CVE → related-OSV lookup on CVE detail pages
-- (`WHERE aliases && ARRAY['CVE-...']`).
CREATE INDEX IF NOT EXISTS idx_osv_aliases_gin ON osv_advisories USING GIN (aliases);
-- Standalone idx for direct lookup by OSV ID (ecosystem not always known on detail route)
CREATE INDEX IF NOT EXISTS idx_osv_id ON osv_advisories(osv_id);

CREATE TABLE IF NOT EXISTS osv_affected (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  osv_id             text NOT NULL,
  ecosystem          text NOT NULL,                -- the advisory's ecosystem (for the composite FK)
  package_name       text NOT NULL,
  package_ecosystem  text NOT NULL,                -- the affected package's own ecosystem (usually same as advisory)
  versions           text[],
  ranges             jsonb,
  UNIQUE (osv_id, ecosystem, package_ecosystem, package_name),
  -- Cascade on advisory deletes to prevent orphan accumulation (flagged by
  -- postgres-pro review: deleting a withdrawn advisory would otherwise leave
  -- dangling affected rows forever).
  FOREIGN KEY (osv_id, ecosystem)
    REFERENCES osv_advisories(osv_id, ecosystem) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_osv_affected_pkg ON osv_affected(package_ecosystem, package_name);
CREATE INDEX IF NOT EXISTS idx_osv_affected_osv ON osv_affected(osv_id, ecosystem);
