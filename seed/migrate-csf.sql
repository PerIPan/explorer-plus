-- NIST CSF v2 Integration — additive migration
-- Safe to run multiple times (IF NOT EXISTS throughout)

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ─── csf_subcategories: 106 rows, static ────────────────────────────────────
CREATE TABLE IF NOT EXISTS csf_subcategories (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  subcategory_id  TEXT NOT NULL,              -- 'PR.AA-01'
  function        TEXT NOT NULL,              -- 'PR'
  function_name   TEXT NOT NULL,              -- 'Protect'
  category_id     TEXT NOT NULL,              -- 'PR.AA'
  category_name   TEXT NOT NULL,              -- 'Identity Management and Access Control'
  name            TEXT NOT NULL,
  description     TEXT,
  version         TEXT NOT NULL DEFAULT '2.0',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (subcategory_id, version)
);

-- CHECK constraints wrapped for idempotency
DO $$ BEGIN
  ALTER TABLE csf_subcategories
    ADD CONSTRAINT chk_csf_subcategory_id_format
    CHECK (subcategory_id ~ '^(GV|ID|PR|DE|RS|RC)\.[A-Z]{2}-\d{2}(\.\d{2})?$');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE csf_subcategories
    ADD CONSTRAINT chk_csf_function
    CHECK (function IN ('GV','ID','PR','DE','RS','RC'));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE INDEX IF NOT EXISTS idx_csf_sub_function ON csf_subcategories(function);
CREATE INDEX IF NOT EXISTS idx_csf_sub_category ON csf_subcategories(category_id);
CREATE INDEX IF NOT EXISTS idx_csf_sub_subcategory_id ON csf_subcategories(subcategory_id);

-- ─── csf_technique_mappings: CTID direct mappings ───────────────────────────
CREATE TABLE IF NOT EXISTS csf_technique_mappings (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  csf_subcategory_uuid UUID NOT NULL REFERENCES csf_subcategories(id) ON DELETE CASCADE,
  subcategory_id       TEXT NOT NULL,              -- denormalized
  technique_id         UUID REFERENCES techniques(id) ON DELETE CASCADE,
  attack_technique_id  TEXT NOT NULL,              -- denormalized
  mapping_source       TEXT NOT NULL DEFAULT 'ctid',
  is_draft             BOOLEAN NOT NULL DEFAULT FALSE,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (subcategory_id, attack_technique_id)
);

DO $$ BEGIN
  ALTER TABLE csf_technique_mappings
    ADD CONSTRAINT chk_csf_mapping_source
    CHECK (mapping_source IN ('ctid','manual','override'));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE csf_technique_mappings
    ADD CONSTRAINT chk_csf_attack_technique_id_format
    CHECK (attack_technique_id ~ '^T\d{4}(\.\d{3})?$');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE INDEX IF NOT EXISTS idx_csf_tech_attackid  ON csf_technique_mappings(attack_technique_id);
CREATE INDEX IF NOT EXISTS idx_csf_tech_subcat    ON csf_technique_mappings(subcategory_id);
CREATE INDEX IF NOT EXISTS idx_csf_tech_uuid      ON csf_technique_mappings(csf_subcategory_uuid);
CREATE INDEX IF NOT EXISTS idx_csf_tech_techuuid  ON csf_technique_mappings(technique_id);
