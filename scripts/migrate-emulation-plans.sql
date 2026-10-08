-- scripts/migrate-emulation-plans.sql
--
-- CTID Adversary Emulation Library: plans and their steps, each step resolved
-- to an ATT&CK technique. Loaded by scripts/sync-emulation.mjs
-- (.github/workflows/sync-emulation.yml). The plan file -> group link is
-- curation in src/lib/emulation-plans.mjs, not inferred.
--
-- Run:
--   psql "$DATABASE_URL" -f scripts/migrate-emulation-plans.sql
--
-- ON_ERROR_STOP is set in the file (first statement below) for the same reason
-- as scripts/migrate-ics-assets.sql: under plain `psql -f` a failed preflight
-- would otherwise only print and carry on.
--
-- Rollback:
--   DROP TABLE IF EXISTS emulation_plan_steps;
--   DROP TABLE IF EXISTS emulation_plans;
--
-- NOTE FOR MAINTAINERS: emulation_plan_steps references techniques, and
-- seed/schema.sql opens with TRUNCATE techniques ... CASCADE. TRUNCATE ignores
-- ON DELETE and follows every referencing table, so a full `seed.py` run
-- empties emulation_plan_steps. emulation_plans holds no FK to ATT&CK tables
-- and survives, with a step_count that is then stale. Nothing is lost that
-- upstream cannot regenerate: re-run the "Sync Emulation Plans" workflow after
-- any full re-seed. scripts/update-attack.mjs upserts techniques
-- and keeps their UUIDs, so the routine ATT&CK update path is unaffected.
--
-- Design notes (postgres review, 2026-10-08):
--   * No FK from emulation_plans to threat_groups. attack_group_id ('G0016') is
--     the stable key; joining on it avoids SET NULL drift after a re-seed.
--   * steps keep three technique columns on purpose:
--       attack_technique_id  — as written upstream, TEXT because upstream has
--                              junk ('x', '7.A.5') that must not fail the load;
--       resolved_attack_id   — the current ATT&CK id after following any
--                              revocation (display + filters need no join);
--       technique_id         — the FK, for joins. SET NULL if a technique row
--                              is deleted; the ingest re-links from
--                              resolved_attack_id.

\set ON_ERROR_STOP on

BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'techniques'
  ) THEN
    RAISE EXCEPTION
      'migrate-emulation-plans requires the base ATT&CK schema: run seed/schema.sql first (techniques table is missing)';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'threat_groups'
  ) THEN
    RAISE EXCEPTION
      'migrate-emulation-plans requires the base ATT&CK schema: run seed/schema.sql first (threat_groups table is missing)';
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS emulation_plans (
  id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  plan_key          TEXT         NOT NULL UNIQUE,
  name              TEXT         NOT NULL,
  attack_group_id   VARCHAR(20)  NOT NULL,
  upstream_plan_id  TEXT,
  attack_version    TEXT,
  source_path       TEXT         NOT NULL,
  source_commit     TEXT,
  step_count        INT          NOT NULL DEFAULT 0,
  created_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
  CONSTRAINT chk_emu_plan_key  CHECK (plan_key ~ '^[a-z0-9-]+$'),
  CONSTRAINT chk_emu_group_fmt CHECK (attack_group_id ~ '^G[0-9]{4}$')
);

CREATE INDEX IF NOT EXISTS idx_emu_plans_group ON emulation_plans(attack_group_id);

CREATE TABLE IF NOT EXISTS emulation_plan_steps (
  id                   UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  plan_id              UUID         NOT NULL REFERENCES emulation_plans(id) ON DELETE CASCADE,
  step_uid             TEXT         NOT NULL,
  ordinal              INT          NOT NULL,
  procedure_step       TEXT,
  name                 TEXT         NOT NULL,
  description          TEXT,
  tactic_raw           TEXT,
  attack_technique_id  TEXT,
  technique_id         UUID         REFERENCES techniques(id) ON DELETE SET NULL,
  resolved_attack_id   VARCHAR(20),
  resolution           TEXT         NOT NULL,
  platforms            TEXT[]       NOT NULL DEFAULT '{}',
  cti_source           TEXT,
  created_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
  updated_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
  UNIQUE (plan_id, step_uid),
  UNIQUE (plan_id, ordinal),
  CONSTRAINT chk_emu_resolution CHECK (resolution IN ('exact', 'deprecated', 'revoked_replaced', 'unresolved', 'none')),
  -- A linked step may still lose its FK to SET NULL (the ingest re-links
  -- from resolved_attack_id), so only the other direction is enforced.
  CONSTRAINT chk_emu_unres_null CHECK (resolution IN ('exact', 'deprecated', 'revoked_replaced') OR technique_id IS NULL),
  CONSTRAINT chk_emu_resolved_fmt CHECK (resolved_attack_id IS NULL OR resolved_attack_id ~ '^T[0-9]{4}(\.[0-9]{3})?$')
);

CREATE INDEX IF NOT EXISTS idx_emu_steps_tech
  ON emulation_plan_steps(technique_id) WHERE technique_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_emu_steps_resolved
  ON emulation_plan_steps(resolved_attack_id);

COMMENT ON COLUMN emulation_plan_steps.resolution IS
  'exact = upstream id is a current technique; deprecated = it exists but ATT&CK has deprecated it (still linked, flagged in the UI); revoked_replaced = upstream id was revoked and resolved_attack_id is its replacement; unresolved = valid T-number with no current technique; none = no usable technique id upstream (e.g. ''x'').';
COMMENT ON COLUMN emulation_plan_steps.tactic_raw IS
  'Upstream tactic text, trimmed only. Inconsistent upstream (''Commmand and Control'', ''Discovery/Execution''); display uses the resolved technique''s tactics instead.';

COMMIT;
