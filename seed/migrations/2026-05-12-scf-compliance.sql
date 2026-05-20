-- seed/migrations/2026-05-12-scf-compliance.sql
--
-- SCF (Secure Controls Framework) compliance integration.
-- Spec: docs/superpowers/specs/2026-05-12-scf-compliance-design.md (v3)
--
-- Creates 8 tables backing /compliance/* routes + per-entity compliance shadow.
-- All scf_* names are unambiguous. Per spec Decision 13, scf_framework_refs +
-- the three summary tables + scf_framework_overlap are rebuilt via shadow-table
-- swap at end of each ingest (sync-scf.mjs) — they do NOT take UPSERT traffic.
--
-- Pre-measurement (run before applying — should all be 0):
--   SELECT to_regclass('scf_controls'), to_regclass('scf_attack_mappings'),
--          to_regclass('scf_framework_refs'), to_regclass('scf_frameworks'),
--          to_regclass('scf_framework_aliases'), to_regclass('scf_framework_overlap'),
--          to_regclass('scf_group_compliance_summary'),
--          to_regclass('scf_software_compliance_summary'),
--          to_regclass('scf_sector_compliance_summary');
--
-- Reversible:
--   DROP TABLE IF EXISTS scf_sector_compliance_summary, scf_software_compliance_summary,
--     scf_group_compliance_summary, scf_framework_overlap, scf_framework_aliases,
--     scf_framework_refs, scf_attack_mappings, scf_controls, scf_frameworks CASCADE;

BEGIN;

-- 1. SCF control catalogue (~1500 rows). Stable PK = scf_id ('CFG-02').
CREATE TABLE IF NOT EXISTS scf_controls (
  scf_id                         TEXT PRIMARY KEY,
  domain                         TEXT NOT NULL,
  name                           TEXT NOT NULL,
  description                    TEXT NOT NULL,
  threat_codes                   TEXT[],
  risk_codes                     TEXT[],
  last_validated_attack_version  TEXT,
  unresolved_attack_count        INT NOT NULL DEFAULT 0,
  created_at                     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at                     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scf_controls_domain ON scf_controls(domain);

-- 2. SCF control -> ATT&CK technique (~30K rows).
--    is_unresolved = SCF lists this attack_id but it doesn't exist in techniques.
--    All roll-up queries MUST filter `AND NOT is_unresolved`.
--    attack_id VARCHAR(20) mirrors techniques.attack_id type.
CREATE TABLE IF NOT EXISTS scf_attack_mappings (
  scf_id            TEXT NOT NULL REFERENCES scf_controls(scf_id) ON DELETE CASCADE,
  attack_id         VARCHAR(20) NOT NULL,
  is_unresolved     BOOLEAN NOT NULL DEFAULT false,
  PRIMARY KEY (scf_id, attack_id)
);

-- Covering index — joins use attack_id then immediately need scf_id.
CREATE INDEX IF NOT EXISTS idx_scf_attack_mappings_attack_covering
  ON scf_attack_mappings(attack_id) INCLUDE (scf_id);
-- Partial index for orphan-mapping monitoring.
CREATE INDEX IF NOT EXISTS idx_scf_attack_mappings_unresolved
  ON scf_attack_mappings(attack_id) WHERE is_unresolved;

-- 3. SCF control -> other framework refs (~150-200K rows).
--    No CASCADE — pure derived data, rebuilt via shadow-table swap each ingest.
CREATE TABLE IF NOT EXISTS scf_framework_refs (
  scf_id            TEXT NOT NULL,
  framework_key     TEXT NOT NULL,
  ref_id            TEXT NOT NULL,
  PRIMARY KEY (scf_id, framework_key, ref_id)
);

CREATE INDEX IF NOT EXISTS idx_scf_framework_refs_fw
  ON scf_framework_refs(framework_key);
CREATE INDEX IF NOT EXISTS idx_scf_framework_refs_scf_fw
  ON scf_framework_refs(scf_id, framework_key);

-- 4. Framework catalogue (~255 rows from SCF Authoritative Sources sheet).
CREATE TABLE IF NOT EXISTS scf_frameworks (
  framework_key     TEXT PRIMARY KEY,
  name              TEXT NOT NULL,
  version           TEXT,
  source_org        TEXT NOT NULL,
  upstream_url      TEXT NOT NULL,
  region            TEXT NOT NULL DEFAULT 'global',
  tier              INT  NOT NULL DEFAULT 3,
  license           TEXT,
  short_blurb       TEXT,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scf_frameworks_tier   ON scf_frameworks(tier);
CREATE INDEX IF NOT EXISTS idx_scf_frameworks_region ON scf_frameworks(region);

-- 5. Alias table — decouples /compliance/<framework_key> URLs from
--    volatile SCF column headers ('EU NIS2' vs 'EU NIS 2 Directive').
CREATE TABLE IF NOT EXISTS scf_framework_aliases (
  framework_key     TEXT NOT NULL REFERENCES scf_frameworks(framework_key) ON DELETE CASCADE,
  source_header     TEXT NOT NULL,
  first_seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (framework_key, source_header)
);

-- 6. Cross-framework technique overlap (~31K rows, lower-triangular fw_a < fw_b).
--    Rebuilt via INSERT at end of every ingest.
CREATE TABLE IF NOT EXISTS scf_framework_overlap (
  fw_a              TEXT NOT NULL REFERENCES scf_frameworks(framework_key) ON DELETE CASCADE,
  fw_b              TEXT NOT NULL REFERENCES scf_frameworks(framework_key) ON DELETE CASCADE,
  technique_overlap INT NOT NULL,
  PRIMARY KEY (fw_a, fw_b),
  CHECK (fw_a < fw_b)
);

CREATE INDEX IF NOT EXISTS idx_scf_framework_overlap_b ON scf_framework_overlap(fw_b);

-- 7. Pre-computed compliance shadow counts. Entity pages do PK lookup.
CREATE TABLE IF NOT EXISTS scf_group_compliance_summary (
  group_id          UUID NOT NULL REFERENCES threat_groups(id) ON DELETE CASCADE,
  framework_key     TEXT NOT NULL REFERENCES scf_frameworks(framework_key) ON DELETE CASCADE,
  controls          INTEGER NOT NULL,
  techniques_ref    INTEGER NOT NULL,
  PRIMARY KEY (group_id, framework_key)
);
CREATE INDEX IF NOT EXISTS idx_scf_group_summary_group
  ON scf_group_compliance_summary(group_id);

CREATE TABLE IF NOT EXISTS scf_software_compliance_summary (
  software_id       UUID NOT NULL REFERENCES attack_software(id) ON DELETE CASCADE,
  framework_key     TEXT NOT NULL REFERENCES scf_frameworks(framework_key) ON DELETE CASCADE,
  controls          INTEGER NOT NULL,
  techniques_ref    INTEGER NOT NULL,
  PRIMARY KEY (software_id, framework_key)
);
CREATE INDEX IF NOT EXISTS idx_scf_software_summary
  ON scf_software_compliance_summary(software_id);

CREATE TABLE IF NOT EXISTS scf_sector_compliance_summary (
  sector_id         UUID NOT NULL REFERENCES sectors(id) ON DELETE CASCADE,
  framework_key     TEXT NOT NULL REFERENCES scf_frameworks(framework_key) ON DELETE CASCADE,
  controls          INTEGER NOT NULL,
  techniques_ref    INTEGER NOT NULL,
  PRIMARY KEY (sector_id, framework_key)
);
CREATE INDEX IF NOT EXISTS idx_scf_sector_summary
  ON scf_sector_compliance_summary(sector_id);

-- 10. Per-technique heat signals — drives compliance-page badges.
--     Refreshed at end of each SCF ingest. Cheap (one CTE roll-up).
CREATE TABLE IF NOT EXISTS scf_technique_heat (
  attack_id    VARCHAR(20) PRIMARY KEY,
  cve_count    INTEGER NOT NULL DEFAULT 0,
  has_kev      BOOLEAN NOT NULL DEFAULT false,
  max_epss     NUMERIC(6,5),
  ghsa_count   INTEGER NOT NULL DEFAULT 0,
  group_count  INTEGER NOT NULL DEFAULT 0,
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_scf_technique_heat_kev  ON scf_technique_heat(has_kev) WHERE has_kev;
CREATE INDEX IF NOT EXISTS idx_scf_technique_heat_epss ON scf_technique_heat(max_epss DESC NULLS LAST);

-- 9. Framework coverage summary — feeds /compliance hub. Pre-computed at end
--    of each ingest. PK lookup, <10ms. 250 rows max.
CREATE TABLE IF NOT EXISTS scf_framework_coverage (
  framework_key       TEXT PRIMARY KEY REFERENCES scf_frameworks(framework_key) ON DELETE CASCADE,
  scf_controls        INTEGER NOT NULL DEFAULT 0,
  techniques_total    INTEGER NOT NULL DEFAULT 0,
  techniques_filtered INTEGER NOT NULL DEFAULT 0,
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMIT;
