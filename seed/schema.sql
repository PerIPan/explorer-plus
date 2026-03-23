BEGIN;

-- ---------------------------------------------------------------------------
-- Idempotency: truncate entity and CTI tables (cascade clears relationships)
-- seed_metadata is an audit log and is never truncated
-- Only runs when tables already exist (safe on first run)
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables
             WHERE table_schema = 'public' AND table_name = 'tactics') THEN
    TRUNCATE
      tactics,
      techniques,
      threat_groups,
      attack_software,
      mitigations,
      campaigns,
      data_sources,
      data_components,
      sectors,
      threat_reports,
      ioc_entries,
      sigma_rules,
      atomic_tests,
      defensive_mappings,
      feed_sync_log
    CASCADE;
  END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- seed_metadata  (audit log, never truncated)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS seed_metadata (
  id                SERIAL PRIMARY KEY,
  attack_version    VARCHAR(20)  NOT NULL,
  domain            VARCHAR(50)  NOT NULL,
  stix_bundle_hash  VARCHAR(64),
  source_url        TEXT,
  seeded_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
  entity_counts     JSONB,
  seed_duration_ms  INTEGER,
  seeded_by         VARCHAR(100)
);

-- ---------------------------------------------------------------------------
-- Entity tables
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS tactics (
  id             UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  stix_id        VARCHAR(255) UNIQUE,
  attack_id      VARCHAR(20)  UNIQUE NOT NULL,
  name           VARCHAR(255) NOT NULL,
  description    TEXT,
  url            TEXT,
  sort_order     INTEGER,
  domain         VARCHAR(50),
  stix_created   TIMESTAMPTZ,
  stix_modified  TIMESTAMPTZ,
  created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS techniques (
  id                    UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  stix_id               VARCHAR(255) UNIQUE,
  attack_id             VARCHAR(20)  UNIQUE NOT NULL,
  name                  VARCHAR(255) NOT NULL,
  description           TEXT,
  url                   TEXT,
  platforms             TEXT[],
  is_subtechnique       BOOLEAN      NOT NULL DEFAULT false,
  parent_technique_id   UUID         REFERENCES techniques(id) ON DELETE CASCADE,
  detection             TEXT,
  is_revoked            BOOLEAN      NOT NULL DEFAULT false,
  is_deprecated         BOOLEAN      NOT NULL DEFAULT false,
  revoked_by_stix_id    VARCHAR(100),
  domain                VARCHAR(50),
  stix_created          TIMESTAMPTZ,
  stix_modified         TIMESTAMPTZ,
  created_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
  updated_at            TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS threat_groups (
  id             UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  stix_id        VARCHAR(255) UNIQUE,
  attack_id      VARCHAR(20)  UNIQUE NOT NULL,
  name           VARCHAR(255) NOT NULL,
  description    TEXT,
  url            TEXT,
  aliases        TEXT[],
  is_revoked     BOOLEAN      NOT NULL DEFAULT false,
  is_deprecated  BOOLEAN      NOT NULL DEFAULT false,
  domain         VARCHAR(50),
  stix_created   TIMESTAMPTZ,
  stix_modified  TIMESTAMPTZ,
  created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS attack_software (
  id             UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  stix_id        VARCHAR(255) UNIQUE,
  attack_id      VARCHAR(20)  UNIQUE NOT NULL,
  name           VARCHAR(255) NOT NULL,
  description    TEXT,
  url            TEXT,
  type           VARCHAR(20)  NOT NULL CHECK (type IN ('malware', 'tool')),
  platforms      TEXT[],
  aliases        TEXT[],
  is_revoked     BOOLEAN      NOT NULL DEFAULT false,
  is_deprecated  BOOLEAN      NOT NULL DEFAULT false,
  domain         VARCHAR(50),
  stix_created   TIMESTAMPTZ,
  stix_modified  TIMESTAMPTZ,
  created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS mitigations (
  id             UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  stix_id        VARCHAR(255) UNIQUE,
  attack_id      VARCHAR(20)  UNIQUE NOT NULL,
  name           VARCHAR(255) NOT NULL,
  description    TEXT,
  url            TEXT,
  is_revoked     BOOLEAN      NOT NULL DEFAULT false,
  is_deprecated  BOOLEAN      NOT NULL DEFAULT false,
  domain         VARCHAR(50),
  stix_created   TIMESTAMPTZ,
  stix_modified  TIMESTAMPTZ,
  created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS campaigns (
  id             UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  stix_id        VARCHAR(255) UNIQUE,
  attack_id      VARCHAR(20)  UNIQUE NOT NULL,
  name           VARCHAR(255) NOT NULL,
  description    TEXT,
  url            TEXT,
  aliases        TEXT[],
  first_seen     TIMESTAMPTZ,
  last_seen      TIMESTAMPTZ,
  is_revoked     BOOLEAN      NOT NULL DEFAULT false,
  is_deprecated  BOOLEAN      NOT NULL DEFAULT false,
  domain         VARCHAR(50),
  stix_created   TIMESTAMPTZ,
  stix_modified  TIMESTAMPTZ,
  created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS data_sources (
  id             UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  stix_id        VARCHAR(255) UNIQUE,
  attack_id      VARCHAR(20)  UNIQUE NOT NULL,
  name           VARCHAR(255) NOT NULL,
  description    TEXT,
  url            TEXT,
  is_revoked     BOOLEAN      NOT NULL DEFAULT false,
  is_deprecated  BOOLEAN      NOT NULL DEFAULT false,
  domain         VARCHAR(50),
  stix_created   TIMESTAMPTZ,
  stix_modified  TIMESTAMPTZ,
  created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS data_components (
  id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  stix_id         VARCHAR(255) UNIQUE,
  name            VARCHAR(255) NOT NULL,
  description     TEXT,
  data_source_id  UUID         REFERENCES data_sources(id) ON DELETE CASCADE,
  is_revoked      BOOLEAN      NOT NULL DEFAULT false,
  is_deprecated   BOOLEAN      NOT NULL DEFAULT false,
  domain          VARCHAR(50),
  stix_created    TIMESTAMPTZ,
  stix_modified   TIMESTAMPTZ,
  created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sectors (
  id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  name        VARCHAR(255) NOT NULL,
  slug        VARCHAR(255) UNIQUE,
  created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Relationship tables
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS technique_tactics (
  technique_id  UUID NOT NULL REFERENCES techniques(id) ON DELETE CASCADE,
  tactic_id     UUID NOT NULL REFERENCES tactics(id)    ON DELETE CASCADE,
  PRIMARY KEY (technique_id, tactic_id)
);

CREATE TABLE IF NOT EXISTS group_techniques (
  group_id      UUID NOT NULL REFERENCES threat_groups(id)  ON DELETE CASCADE,
  technique_id  UUID NOT NULL REFERENCES techniques(id)     ON DELETE CASCADE,
  description   TEXT,
  PRIMARY KEY (group_id, technique_id)
);

CREATE TABLE IF NOT EXISTS group_software (
  group_id     UUID NOT NULL REFERENCES threat_groups(id)   ON DELETE CASCADE,
  software_id  UUID NOT NULL REFERENCES attack_software(id) ON DELETE CASCADE,
  description  TEXT,
  PRIMARY KEY (group_id, software_id)
);

CREATE TABLE IF NOT EXISTS software_techniques (
  software_id   UUID NOT NULL REFERENCES attack_software(id) ON DELETE CASCADE,
  technique_id  UUID NOT NULL REFERENCES techniques(id)      ON DELETE CASCADE,
  description   TEXT,
  PRIMARY KEY (software_id, technique_id)
);

CREATE TABLE IF NOT EXISTS mitigation_techniques (
  mitigation_id  UUID NOT NULL REFERENCES mitigations(id) ON DELETE CASCADE,
  technique_id   UUID NOT NULL REFERENCES techniques(id)  ON DELETE CASCADE,
  description    TEXT,
  PRIMARY KEY (mitigation_id, technique_id)
);

CREATE TABLE IF NOT EXISTS technique_data_components (
  technique_id       UUID NOT NULL REFERENCES techniques(id)      ON DELETE CASCADE,
  data_component_id  UUID NOT NULL REFERENCES data_components(id) ON DELETE CASCADE,
  PRIMARY KEY (technique_id, data_component_id)
);

CREATE TABLE IF NOT EXISTS campaign_techniques (
  campaign_id   UUID NOT NULL REFERENCES campaigns(id)  ON DELETE CASCADE,
  technique_id  UUID NOT NULL REFERENCES techniques(id) ON DELETE CASCADE,
  description   TEXT,
  PRIMARY KEY (campaign_id, technique_id)
);

CREATE TABLE IF NOT EXISTS campaign_software (
  campaign_id  UUID NOT NULL REFERENCES campaigns(id)       ON DELETE CASCADE,
  software_id  UUID NOT NULL REFERENCES attack_software(id) ON DELETE CASCADE,
  description  TEXT,
  PRIMARY KEY (campaign_id, software_id)
);

CREATE TABLE IF NOT EXISTS group_campaigns (
  group_id     UUID NOT NULL REFERENCES threat_groups(id) ON DELETE CASCADE,
  campaign_id  UUID NOT NULL REFERENCES campaigns(id)     ON DELETE CASCADE,
  description  TEXT,
  PRIMARY KEY (group_id, campaign_id)
);

CREATE TABLE IF NOT EXISTS group_sectors (
  group_id          UUID        NOT NULL REFERENCES threat_groups(id) ON DELETE CASCADE,
  sector_id         UUID        NOT NULL REFERENCES sectors(id)       ON DELETE CASCADE,
  source            VARCHAR(10) NOT NULL DEFAULT 'auto',
  matched_keywords  TEXT[],
  PRIMARY KEY (group_id, sector_id)
);

-- ---------------------------------------------------------------------------
-- CTI tables
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS threat_reports (
  id                      UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  title                   TEXT         NOT NULL,
  source                  VARCHAR(255),
  url                     TEXT         UNIQUE,
  published_at            TIMESTAMPTZ,
  summary                 TEXT,
  raw_content             TEXT,
  extracted_technique_ids TEXT[],
  otx_pulse_id            VARCHAR(100),
  created_at              TIMESTAMPTZ  NOT NULL DEFAULT now(),
  updated_at              TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ioc_entries (
  id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  type            VARCHAR(50)  NOT NULL,
  value           TEXT         NOT NULL,
  source          VARCHAR(255),
  malware_family  VARCHAR(255),
  confidence      INTEGER,
  first_seen      TIMESTAMPTZ,
  last_seen       TIMESTAMPTZ,
  tags            TEXT[],
  source_ref      TEXT,
  description     TEXT,
  created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
  UNIQUE (type, value, source)
);

CREATE TABLE IF NOT EXISTS sigma_rules (
  id                    UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  sigma_id              VARCHAR(255) UNIQUE,
  title                 TEXT         NOT NULL,
  technique_id          UUID         REFERENCES techniques(id) ON DELETE SET NULL,
  attack_technique_id   VARCHAR(20),
  level                 VARCHAR(20),
  status                VARCHAR(20),
  description           TEXT,
  logsource_category    VARCHAR(100),
  logsource_product     VARCHAR(100),
  yaml_url              TEXT,
  created_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
  updated_at            TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS atomic_tests (
  id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  name                TEXT         NOT NULL,
  technique_id        UUID         REFERENCES techniques(id) ON DELETE SET NULL,
  attack_technique_id VARCHAR(20),
  test_number         INTEGER      NOT NULL,
  description         TEXT,
  platforms           TEXT[],
  executor_type       VARCHAR(50),
  executor_command    TEXT,
  cleanup_command     TEXT,
  source_url          TEXT,
  created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
  UNIQUE (attack_technique_id, test_number)
);

CREATE TABLE IF NOT EXISTS defensive_mappings (
  id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  technique_id        UUID         REFERENCES techniques(id) ON DELETE SET NULL,
  attack_technique_id VARCHAR(20),
  d3fend_id           VARCHAR(50)  NOT NULL,
  d3fend_name         TEXT,
  d3fend_tactic       VARCHAR(100),
  relationship        VARCHAR(100),
  d3fend_url          TEXT,
  created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
  UNIQUE (technique_id, d3fend_id)
);

CREATE TABLE IF NOT EXISTS technique_iocs (
  technique_id  UUID        NOT NULL REFERENCES techniques(id)  ON DELETE CASCADE,
  ioc_id        UUID        NOT NULL REFERENCES ioc_entries(id) ON DELETE CASCADE,
  confidence    VARCHAR(20) NOT NULL DEFAULT 'inferred',
  PRIMARY KEY (technique_id, ioc_id)
);

CREATE TABLE IF NOT EXISTS report_techniques (
  report_id     UUID NOT NULL REFERENCES threat_reports(id) ON DELETE CASCADE,
  technique_id  UUID NOT NULL REFERENCES techniques(id)     ON DELETE CASCADE,
  PRIMARY KEY (report_id, technique_id)
);

CREATE TABLE IF NOT EXISTS feed_sync_log (
  id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  source            VARCHAR(100) NOT NULL,
  started_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
  completed_at      TIMESTAMPTZ,
  status            VARCHAR(20)  NOT NULL DEFAULT 'running',
  records_inserted  INTEGER      NOT NULL DEFAULT 0,
  records_skipped   INTEGER      NOT NULL DEFAULT 0,
  error_message     TEXT,
  metadata          JSONB,
  UNIQUE (source, started_at)
);

-- ---------------------------------------------------------------------------
-- Indexes
-- ---------------------------------------------------------------------------

-- Full-text search on entity tables
CREATE INDEX IF NOT EXISTS idx_techniques_fts
  ON techniques USING GIN (to_tsvector('english',
    COALESCE(name, '') || ' ' || COALESCE(description, '')));

CREATE INDEX IF NOT EXISTS idx_threat_groups_fts
  ON threat_groups USING GIN (to_tsvector('english',
    COALESCE(name, '') || ' ' || COALESCE(description, '')));

CREATE INDEX IF NOT EXISTS idx_attack_software_fts
  ON attack_software USING GIN (to_tsvector('english',
    COALESCE(name, '') || ' ' || COALESCE(description, '')));

CREATE INDEX IF NOT EXISTS idx_mitigations_fts
  ON mitigations USING GIN (to_tsvector('english',
    COALESCE(name, '') || ' ' || COALESCE(description, '')));

CREATE INDEX IF NOT EXISTS idx_campaigns_fts
  ON campaigns USING GIN (to_tsvector('english',
    COALESCE(name, '') || ' ' || COALESCE(description, '')));

CREATE INDEX IF NOT EXISTS idx_data_sources_fts
  ON data_sources USING GIN (to_tsvector('english',
    COALESCE(name, '') || ' ' || COALESCE(description, '')));

-- Full-text on relationship description fields
CREATE INDEX IF NOT EXISTS idx_group_techniques_fts
  ON group_techniques USING GIN (to_tsvector('english',
    COALESCE(description, '')));

CREATE INDEX IF NOT EXISTS idx_software_techniques_fts
  ON software_techniques USING GIN (to_tsvector('english',
    COALESCE(description, '')));

CREATE INDEX IF NOT EXISTS idx_campaign_techniques_fts
  ON campaign_techniques USING GIN (to_tsvector('english',
    COALESCE(description, '')));

-- attack_id lookup indexes
CREATE INDEX IF NOT EXISTS idx_tactics_attack_id          ON tactics(attack_id);
CREATE INDEX IF NOT EXISTS idx_techniques_attack_id       ON techniques(attack_id);
CREATE INDEX IF NOT EXISTS idx_threat_groups_attack_id    ON threat_groups(attack_id);
CREATE INDEX IF NOT EXISTS idx_attack_software_attack_id  ON attack_software(attack_id);
CREATE INDEX IF NOT EXISTS idx_mitigations_attack_id      ON mitigations(attack_id);
CREATE INDEX IF NOT EXISTS idx_campaigns_attack_id        ON campaigns(attack_id);
CREATE INDEX IF NOT EXISTS idx_data_sources_attack_id     ON data_sources(attack_id);

-- GIN on platforms arrays
CREATE INDEX IF NOT EXISTS idx_techniques_platforms      ON techniques USING GIN (platforms);
CREATE INDEX IF NOT EXISTS idx_attack_software_platforms ON attack_software USING GIN (platforms);
CREATE INDEX IF NOT EXISTS idx_atomic_tests_platforms    ON atomic_tests USING GIN (platforms);

-- Parent technique FK index
CREATE INDEX IF NOT EXISTS idx_techniques_parent ON techniques(parent_technique_id);

-- Partial index: parent techniques only
CREATE INDEX IF NOT EXISTS idx_techniques_parent_only
  ON techniques(id) WHERE is_subtechnique = false;

-- Sort index for tactics
CREATE INDEX IF NOT EXISTS idx_tactics_sort_order ON tactics(sort_order);

-- FK indexes on relationship tables
CREATE INDEX IF NOT EXISTS idx_technique_tactics_tactic_id        ON technique_tactics(tactic_id);
CREATE INDEX IF NOT EXISTS idx_technique_tactics_technique_id     ON technique_tactics(technique_id);
CREATE INDEX IF NOT EXISTS idx_group_techniques_group_id          ON group_techniques(group_id);
CREATE INDEX IF NOT EXISTS idx_group_techniques_technique_id      ON group_techniques(technique_id);
CREATE INDEX IF NOT EXISTS idx_group_software_group_id            ON group_software(group_id);
CREATE INDEX IF NOT EXISTS idx_group_software_software_id         ON group_software(software_id);
CREATE INDEX IF NOT EXISTS idx_software_techniques_software_id    ON software_techniques(software_id);
CREATE INDEX IF NOT EXISTS idx_software_techniques_technique_id   ON software_techniques(technique_id);
CREATE INDEX IF NOT EXISTS idx_mitigation_techniques_mitigation_id ON mitigation_techniques(mitigation_id);
CREATE INDEX IF NOT EXISTS idx_mitigation_techniques_technique_id ON mitigation_techniques(technique_id);
CREATE INDEX IF NOT EXISTS idx_technique_data_components_technique_id      ON technique_data_components(technique_id);
CREATE INDEX IF NOT EXISTS idx_technique_data_components_data_component_id ON technique_data_components(data_component_id);
CREATE INDEX IF NOT EXISTS idx_campaign_techniques_campaign_id    ON campaign_techniques(campaign_id);
CREATE INDEX IF NOT EXISTS idx_campaign_techniques_technique_id   ON campaign_techniques(technique_id);
CREATE INDEX IF NOT EXISTS idx_campaign_software_campaign_id      ON campaign_software(campaign_id);
CREATE INDEX IF NOT EXISTS idx_campaign_software_software_id      ON campaign_software(software_id);
CREATE INDEX IF NOT EXISTS idx_group_campaigns_group_id           ON group_campaigns(group_id);
CREATE INDEX IF NOT EXISTS idx_group_campaigns_campaign_id        ON group_campaigns(campaign_id);
CREATE INDEX IF NOT EXISTS idx_group_sectors_group_id             ON group_sectors(group_id);
CREATE INDEX IF NOT EXISTS idx_group_sectors_sector_id            ON group_sectors(sector_id);
CREATE INDEX IF NOT EXISTS idx_data_components_data_source_id     ON data_components(data_source_id);
CREATE INDEX IF NOT EXISTS idx_technique_iocs_technique_id        ON technique_iocs(technique_id);
CREATE INDEX IF NOT EXISTS idx_technique_iocs_ioc_id              ON technique_iocs(ioc_id);
CREATE INDEX IF NOT EXISTS idx_report_techniques_report_id        ON report_techniques(report_id);
CREATE INDEX IF NOT EXISTS idx_report_techniques_technique_id     ON report_techniques(technique_id);

-- CTI: threat_reports
CREATE INDEX IF NOT EXISTS idx_threat_reports_source       ON threat_reports(source);
CREATE INDEX IF NOT EXISTS idx_threat_reports_published_at ON threat_reports(published_at DESC);
CREATE INDEX IF NOT EXISTS idx_threat_reports_fts
  ON threat_reports USING GIN (to_tsvector('english',
    COALESCE(title, '') || ' ' || COALESCE(summary, '')));
CREATE INDEX IF NOT EXISTS idx_threat_reports_techniques_gin
  ON threat_reports USING GIN (extracted_technique_ids);

-- CTI: ioc_entries
CREATE INDEX IF NOT EXISTS idx_ioc_entries_type_value  ON ioc_entries(type, value);
CREATE INDEX IF NOT EXISTS idx_ioc_entries_source      ON ioc_entries(source);
CREATE INDEX IF NOT EXISTS idx_ioc_entries_malware     ON ioc_entries(malware_family);
CREATE INDEX IF NOT EXISTS idx_ioc_entries_first_seen  ON ioc_entries(first_seen);

-- CTI: sigma_rules
CREATE INDEX IF NOT EXISTS idx_sigma_rules_technique_id ON sigma_rules(technique_id);

-- CTI: atomic_tests
CREATE INDEX IF NOT EXISTS idx_atomic_tests_technique_id ON atomic_tests(technique_id);

-- CTI: defensive_mappings
CREATE INDEX IF NOT EXISTS idx_defensive_mappings_technique_id ON defensive_mappings(technique_id);

-- CTI: feed_sync_log
CREATE INDEX IF NOT EXISTS idx_feed_sync_log_source     ON feed_sync_log(source);
CREATE INDEX IF NOT EXISTS idx_feed_sync_log_started_at ON feed_sync_log(started_at DESC);

-- Campaign temporal
CREATE INDEX IF NOT EXISTS idx_campaigns_first_seen ON campaigns(first_seen);
CREATE INDEX IF NOT EXISTS idx_campaigns_last_seen  ON campaigns(last_seen);

-- Sector keywords GIN
CREATE INDEX IF NOT EXISTS idx_group_sectors_matched_keywords
  ON group_sectors USING GIN (matched_keywords);

-- ---------------------------------------------------------------------------
-- Framework integration tables (NIST 800-53, CIS Controls, Engage, RE&CT)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS nist_controls (
  id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  control_id          VARCHAR(20)  NOT NULL,
  control_name        VARCHAR(255),
  control_family      VARCHAR(100),
  technique_id        UUID         REFERENCES techniques(id) ON DELETE CASCADE,
  attack_technique_id VARCHAR(20)  NOT NULL,
  mapping_type        VARCHAR(50),
  status              VARCHAR(50),
  created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
  UNIQUE(control_id, attack_technique_id)
);

CREATE TABLE IF NOT EXISTS cis_controls (
  id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  control_id          VARCHAR(20)  NOT NULL,
  control_name        VARCHAR(255),
  control_group       VARCHAR(100),
  technique_id        UUID         REFERENCES techniques(id) ON DELETE CASCADE,
  attack_technique_id VARCHAR(20)  NOT NULL,
  mapping_type        VARCHAR(50),
  created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
  UNIQUE(control_id, attack_technique_id)
);

CREATE TABLE IF NOT EXISTS engage_mappings (
  id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  engage_id           VARCHAR(20)  NOT NULL,
  engage_name         VARCHAR(255) NOT NULL,
  engage_description  TEXT,
  goal                VARCHAR(100),
  approach            VARCHAR(100),
  technique_id        UUID         REFERENCES techniques(id) ON DELETE CASCADE,
  attack_technique_id VARCHAR(20)  NOT NULL,
  created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
  UNIQUE(engage_id, attack_technique_id)
);

CREATE TABLE IF NOT EXISTS react_actions (
  id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  action_id   VARCHAR(20)  NOT NULL UNIQUE,
  title       VARCHAR(255) NOT NULL,
  description TEXT,
  stage       VARCHAR(50),
  workflow    TEXT,
  created_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_nist_technique    ON nist_controls(technique_id);
CREATE INDEX IF NOT EXISTS idx_nist_control      ON nist_controls(control_id);
CREATE INDEX IF NOT EXISTS idx_nist_attack_id    ON nist_controls(attack_technique_id);
CREATE INDEX IF NOT EXISTS idx_cis_technique     ON cis_controls(technique_id);
CREATE INDEX IF NOT EXISTS idx_cis_attack_id     ON cis_controls(attack_technique_id);
CREATE INDEX IF NOT EXISTS idx_engage_technique  ON engage_mappings(technique_id);
CREATE INDEX IF NOT EXISTS idx_engage_attack_id  ON engage_mappings(attack_technique_id);
CREATE INDEX IF NOT EXISTS idx_react_stage       ON react_actions(stage);

COMMIT;
