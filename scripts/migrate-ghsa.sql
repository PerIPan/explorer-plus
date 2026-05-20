-- GHSA + Packages integration schema migration
-- Spec: docs/superpowers/specs/2026-04-15-ghsa-packages-integration-design.md (v3.1)
-- Safe to re-run (idempotent).

-- 1. Extensions
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- 2. Ecosystems reference table
CREATE TABLE IF NOT EXISTS ecosystems (
  code text PRIMARY KEY,
  label text NOT NULL,
  url_template text,
  created_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO ecosystems (code, label, url_template) VALUES
  ('npm',      'npm',            'https://www.npmjs.com/package/{name}'),
  ('pypi',     'PyPI',           'https://pypi.org/project/{name}'),
  ('go',       'Go',             'https://pkg.go.dev/{name}'),
  ('maven',    'Maven',          'https://central.sonatype.com/artifact/{name}'),
  ('rubygems', 'RubyGems',       'https://rubygems.org/gems/{name}'),
  ('nuget',    'NuGet',          'https://www.nuget.org/packages/{name}'),
  ('composer', 'Composer',       'https://packagist.org/packages/{name}'),
  ('rust',     'crates.io',      'https://crates.io/crates/{name}'),
  ('erlang',   'Hex',            'https://hex.pm/packages/{name}'),
  ('pub',      'pub.dev',        'https://pub.dev/packages/{name}'),
  ('swift',    'Swift',          NULL),
  ('actions',  'GitHub Actions', NULL)
ON CONFLICT (code) DO NOTHING;

-- 3. Packages dimension table (library-centric, parallel to applications)
CREATE TABLE IF NOT EXISTS packages (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ecosystem text NOT NULL REFERENCES ecosystems(code),
  package_name text NOT NULL,
  purl text,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (ecosystem, package_name)
);

CREATE INDEX IF NOT EXISTS idx_packages_ecosystem ON packages(ecosystem);
-- /ecosystems/<slug> filters on LOWER(p.ecosystem); plain B-tree on the bare
-- column can't satisfy that predicate — expression index is required.
CREATE INDEX IF NOT EXISTS idx_packages_ecosystem_lower ON packages (LOWER(ecosystem));
CREATE INDEX IF NOT EXISTS idx_packages_name_trgm ON packages USING gin (package_name gin_trgm_ops);

-- 4. GHSA advisories
CREATE TABLE IF NOT EXISTS ghsa_advisories (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ghsa_id text NOT NULL UNIQUE,
  cve_id text,
  summary text,
  description text,
  severity varchar(20),
  cvss_score numeric(3,1),
  cvss_vector text,
  cvss_v4_score numeric(3,1),
  cvss_v4_vector text,
  published_at timestamptz NOT NULL,
  upstream_updated_at timestamptz,
  withdrawn_at timestamptz,
  ghsa_enriched_at timestamptz NOT NULL DEFAULT now(),
  row_created_at timestamptz NOT NULL DEFAULT now(),
  row_updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (cve_id) REFERENCES cve_details(cve_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_ghsa_adv_cve       ON ghsa_advisories(cve_id) WHERE cve_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ghsa_adv_severity  ON ghsa_advisories(severity);
CREATE INDEX IF NOT EXISTS idx_ghsa_adv_cvss      ON ghsa_advisories(cvss_score DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS idx_ghsa_adv_published ON ghsa_advisories(published_at DESC);
CREATE INDEX IF NOT EXISTS idx_ghsa_adv_not_withdrawn ON ghsa_advisories(published_at DESC) WHERE withdrawn_at IS NULL;

-- 5. GHSA weaknesses (CWE links)
CREATE TABLE IF NOT EXISTS ghsa_weaknesses (
  ghsa_id text NOT NULL REFERENCES ghsa_advisories(ghsa_id) ON DELETE CASCADE,
  cwe_id varchar(20) NOT NULL,
  PRIMARY KEY (ghsa_id, cwe_id)
);

CREATE INDEX IF NOT EXISTS idx_ghsa_weaknesses_cwe ON ghsa_weaknesses(cwe_id);

-- 6. GHSA affected packages
CREATE TABLE IF NOT EXISTS ghsa_packages (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ghsa_id text NOT NULL REFERENCES ghsa_advisories(ghsa_id) ON DELETE CASCADE,
  package_id uuid NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
  vulnerable_range text,
  -- Generated column lets UNIQUE INDEX + ON CONFLICT coexist (expression indexes
  -- alone are valid DDL but can't be conflict targets).
  vulnerable_range_key text GENERATED ALWAYS AS (COALESCE(vulnerable_range, '')) STORED,
  fixed_version text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_ghsa_packages
  ON ghsa_packages (ghsa_id, package_id, vulnerable_range_key);
CREATE INDEX IF NOT EXISTS idx_ghsa_packages_pkg  ON ghsa_packages(package_id);
CREATE INDEX IF NOT EXISTS idx_ghsa_packages_ghsa ON ghsa_packages(ghsa_id);

-- 7. Unified weaknesses — regular VIEW (trivial UNION, always fresh)
CREATE OR REPLACE VIEW unified_weaknesses AS
SELECT cve_id  AS entity_id, cwe_id, 'cve'  AS source FROM cve_weaknesses
UNION ALL
SELECT ghsa_id AS entity_id, cwe_id, 'ghsa' AS source FROM ghsa_weaknesses;

-- 8. Package summary — MATERIALIZED VIEW (expensive aggregate)
-- CTE-based per-package aggregates to avoid cartesian explosion across
-- advisory × weakness × CAPEC × technique joins.
DROP MATERIALIZED VIEW IF EXISTS package_summary;

CREATE MATERIALIZED VIEW package_summary AS
WITH pkg_adv AS (
  SELECT
    gp.package_id,
    COUNT(DISTINCT gp.ghsa_id)                                             AS advisory_count,
    MAX(g.published_at)                                                    AS latest_published,
    ARRAY_AGG(DISTINCT g.severity) FILTER (WHERE g.severity IS NOT NULL)   AS severities
  FROM ghsa_packages gp
  JOIN ghsa_advisories g ON g.ghsa_id = gp.ghsa_id AND g.withdrawn_at IS NULL
  GROUP BY gp.package_id
),
pkg_tech AS (
  SELECT
    gp.package_id,
    COUNT(DISTINCT cm.technique_id) AS technique_count
  FROM ghsa_packages gp
  JOIN ghsa_advisories g ON g.ghsa_id = gp.ghsa_id AND g.withdrawn_at IS NULL
  JOIN ghsa_weaknesses w ON w.ghsa_id = g.ghsa_id
  JOIN capec_mappings cm ON cm.cwe_id = w.cwe_id AND cm.technique_id IS NOT NULL
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
  COALESCE(pt.technique_count, 0)          AS technique_count
FROM packages p
JOIN pkg_adv       pa ON pa.package_id = p.id
LEFT JOIN pkg_tech pt ON pt.package_id = p.id;

CREATE UNIQUE INDEX uq_package_summary          ON package_summary(package_id);
CREATE INDEX idx_package_summary_eco            ON package_summary(ecosystem);
CREATE INDEX idx_package_summary_count          ON package_summary(advisory_count DESC);
CREATE INDEX idx_package_summary_name_trgm      ON package_summary USING gin (package_name gin_trgm_ops);

-- Bootstrap non-concurrent refresh — required before any CONCURRENTLY refresh
-- will work (CONCURRENTLY requires existing rows). View will be empty until
-- first sync populates underlying tables; that's intentional.
REFRESH MATERIALIZED VIEW package_summary;
