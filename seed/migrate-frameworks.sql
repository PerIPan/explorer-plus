-- Framework integration tables: NIST 800-53, CIS Controls, MITRE Engage, RE&CT
-- Run with: psql ... -f seed/migrate-frameworks.sql

-- NIST 800-53 Rev5 control mappings to ATT&CK techniques
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

-- CIS Controls mappings
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

-- MITRE Engage adversary engagement mappings to ATT&CK
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

-- RE&CT incident response actions
CREATE TABLE IF NOT EXISTS react_actions (
  id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  action_id   VARCHAR(20)  NOT NULL UNIQUE,
  title       VARCHAR(255) NOT NULL,
  description TEXT,
  stage       VARCHAR(50),
  workflow    TEXT,
  created_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_nist_technique    ON nist_controls(technique_id);
CREATE INDEX IF NOT EXISTS idx_nist_control      ON nist_controls(control_id);
CREATE INDEX IF NOT EXISTS idx_nist_attack_id    ON nist_controls(attack_technique_id);
CREATE INDEX IF NOT EXISTS idx_cis_technique     ON cis_controls(technique_id);
CREATE INDEX IF NOT EXISTS idx_cis_attack_id     ON cis_controls(attack_technique_id);
CREATE INDEX IF NOT EXISTS idx_engage_technique  ON engage_mappings(technique_id);
CREATE INDEX IF NOT EXISTS idx_engage_attack_id  ON engage_mappings(attack_technique_id);
CREATE INDEX IF NOT EXISTS idx_react_stage       ON react_actions(stage);
