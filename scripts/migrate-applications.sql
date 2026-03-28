-- Application → CVE → Technique → APT Entity Chain
-- Migration script — run on both local and Neon

-- Enable trigram extension for fuzzy search
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- ── cve_details (authoritative CVE data from CVElistV5) ──────────────────────
CREATE TABLE IF NOT EXISTS cve_details (
  id               UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  cve_id           TEXT          NOT NULL UNIQUE,
  description      TEXT,
  cvss_score       NUMERIC(3,1),
  cvss_severity    VARCHAR(20),
  cvss_vector      TEXT,
  cwe_id           VARCHAR(20),       -- kept for backward compat, primary CWE
  published_at     TIMESTAMPTZ,
  is_kev           BOOLEAN       NOT NULL DEFAULT false,
  created_at       TIMESTAMPTZ   NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ   NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_cve_details_severity ON cve_details(cvss_severity);
CREATE INDEX IF NOT EXISTS idx_cve_details_published ON cve_details(published_at DESC);
CREATE INDEX IF NOT EXISTS idx_cve_details_cvss ON cve_details(cvss_score DESC NULLS LAST);

-- ── cve_weaknesses (multiple CWEs per CVE) ───────────────────────────────────
CREATE TABLE IF NOT EXISTS cve_weaknesses (
  cve_id   TEXT        NOT NULL REFERENCES cve_details(cve_id) ON DELETE CASCADE,
  cwe_id   VARCHAR(20) NOT NULL,
  PRIMARY KEY (cve_id, cwe_id)
);
CREATE INDEX IF NOT EXISTS idx_cve_weaknesses_cwe ON cve_weaknesses(cwe_id);

-- ── applications (canonical vendor+product pairs) ────────────────────────────
CREATE TABLE IF NOT EXISTS applications (
  id            UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  vendor        TEXT          NOT NULL,
  product       TEXT          NOT NULL,
  cpe_prefix    TEXT,
  normalized    TEXT          NOT NULL,
  cve_count     INT           NOT NULL DEFAULT 0,
  created_at    TIMESTAMPTZ   NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ   NOT NULL DEFAULT now(),
  UNIQUE (normalized)
);
CREATE INDEX IF NOT EXISTS idx_applications_vendor_trgm ON applications USING GIN (vendor gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_applications_product_trgm ON applications USING GIN (product gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_applications_cve_count ON applications(cve_count DESC);
CREATE INDEX IF NOT EXISTS idx_applications_cpe ON applications(cpe_prefix) WHERE cpe_prefix IS NOT NULL;

-- ── affected_products (CVE ↔ application with version ranges) ────────────────
CREATE TABLE IF NOT EXISTS affected_products (
  id              UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  cve_id          TEXT          NOT NULL REFERENCES cve_details(cve_id) ON DELETE CASCADE,
  application_id  UUID          NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  version_start   TEXT,
  version_end     TEXT,
  status          VARCHAR(20)   CHECK (status IN ('affected', 'unknown')) DEFAULT 'affected',
  created_at      TIMESTAMPTZ   NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ   NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_affected_products_unique
  ON affected_products (cve_id, application_id, COALESCE(version_start,''), COALESCE(version_end,''));
CREATE INDEX IF NOT EXISTS idx_affected_products_app ON affected_products(application_id);
CREATE INDEX IF NOT EXISTS idx_affected_products_cve ON affected_products(cve_id);

-- ── capec_mappings (CWE → CAPEC → ATT&CK technique) ─────────────────────────
CREATE TABLE IF NOT EXISTS capec_mappings (
  id                  UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  capec_id            VARCHAR(20)   NOT NULL,
  capec_name          TEXT,
  capec_description   TEXT,
  cwe_id              VARCHAR(20)   NOT NULL,
  attack_technique_id VARCHAR(20),
  technique_id        UUID          REFERENCES techniques(id) ON DELETE SET NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_capec_with_technique
  ON capec_mappings (capec_id, cwe_id, attack_technique_id) WHERE attack_technique_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_capec_no_technique
  ON capec_mappings (capec_id, cwe_id) WHERE attack_technique_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_capec_cwe ON capec_mappings(cwe_id);
CREATE INDEX IF NOT EXISTS idx_capec_technique ON capec_mappings(technique_id);

-- ── cve_count trigger ────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION refresh_app_cve_count() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  UPDATE applications SET
    cve_count = (SELECT COUNT(DISTINCT cve_id) FROM affected_products
                 WHERE application_id = COALESCE(NEW.application_id, OLD.application_id)),
    updated_at = now()
  WHERE id = COALESCE(NEW.application_id, OLD.application_id);
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_affected_products_count ON affected_products;
CREATE TRIGGER trg_affected_products_count
  AFTER INSERT OR DELETE ON affected_products
  FOR EACH ROW EXECUTE FUNCTION refresh_app_cve_count();
