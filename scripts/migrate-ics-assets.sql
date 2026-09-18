-- scripts/migrate-ics-assets.sql
--
-- ATT&CK ICS Assets (A0001..A0018) + Purdue Model layer.
--
-- Scope is ICS-only. There is deliberately NO Enterprise-technique mapping:
-- the group-mediated derivation was measured and carries zero boundary signal
-- (Jump Host 185 enterprise techniques vs PLC 143 — a boundary asset and a
-- deep-OT asset produce near-identical sets). Everything here is either
-- MITRE-published data or thin, citable curation.
--
-- Run:
--   psql "$DATABASE_URL" -f scripts/migrate-ics-assets.sql
--
-- The file sets ON_ERROR_STOP itself (first line below) rather than relying on
-- the caller passing a flag. docs/feeds_setup.md documents plain `psql -f` for
-- migrations, and without the flag a failed preflight only PRINTS its error —
-- psql carries on, creates half the tables, and exits 0.
--
-- Rollback (reverse dependency order):
--   DROP TABLE IF EXISTS purdue_flow_rules;
--   DROP TABLE IF EXISTS asset_purdue_placement;
--   DROP TABLE IF EXISTS purdue_levels;
--   DROP TABLE IF EXISTS asset_related_assets;
--   DROP TABLE IF EXISTS asset_techniques;
--   DROP TABLE IF EXISTS attack_assets;
--
-- NOTE FOR MAINTAINERS: attack_assets is intentionally NOT in the
-- TRUNCATE ... CASCADE list at the top of seed/schema.sql. TRUNCATE ignores
-- referential actions and pulls in every referencing table regardless, which
-- would silently destroy the hand-written rationale text in
-- asset_purdue_placement — content that cannot be regenerated from upstream.
-- attack_assets is maintained by UPSERT (scripts/backfill-ics-assets.mjs and
-- scripts/update-attack.mjs), which never deletes rows.

\set ON_ERROR_STOP on

BEGIN;

-- Prerequisite: asset_techniques FKs public.techniques. Without this guard the
-- failure is a bare `relation "techniques" does not exist`, which gives no hint
-- that seed/schema.sql must run first.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'techniques'
  ) THEN
    RAISE EXCEPTION
      'migrate-ics-assets requires the base ATT&CK schema: run seed/schema.sql first (techniques table is missing)';
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 1. Assets — 18 rows from ics-attack.json (x-mitre-asset)
-- ---------------------------------------------------------------------------
-- Column contract deliberately mirrors the 7 sibling ATT&CK entity tables
-- (techniques, attack_software, mitigations, ...) so scripts/update-attack.mjs
-- `upsertEntity` works untouched — it builds SQL by interpolating literal
-- column-name lists, so any divergence would require forking that helper.
--
-- sectors/platforms are NULLABLE on purpose: jsonbColumnExpr emits
-- `array_agg(...)` with no COALESCE, which yields NULL (not '{}') for an empty
-- JSON array, and data/ics-attack.json ships 3 assets with empty
-- x_mitre_sectors (A0013, A0018, A0010). A NOT NULL column would make the
-- whole 18-row statement abort with 23502.
CREATE TABLE IF NOT EXISTS attack_assets (
  id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  stix_id       VARCHAR(255) UNIQUE NOT NULL,  -- upsertEntity conflict target
  attack_id     VARCHAR(20)  UNIQUE NOT NULL,  -- A0001..A0018
  name          VARCHAR(255) NOT NULL,
  description   TEXT,
  url           TEXT,
  sectors       TEXT[],                        -- General | Electric | Water and Wastewater
  platforms     TEXT[],                        -- Embedded | Linux | Windows
  is_revoked    BOOLEAN      NOT NULL DEFAULT false,
  is_deprecated BOOLEAN      NOT NULL DEFAULT false,
  domain        VARCHAR(50),                   -- from x_mitre_domains[0]
  stix_created  TIMESTAMPTZ,
  stix_modified TIMESTAMPTZ,
  created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  -- Required so asset_purdue_placement can FK (asset_id, attack_id) as a pair.
  -- Postgres will not accept a composite FK against separate PK + UNIQUE
  -- constraints; this is the minimal way to stop the two identities drifting.
  CONSTRAINT attack_assets_id_attack_id_key UNIQUE (id, attack_id)
);

COMMENT ON COLUMN attack_assets.sectors IS
  'TEXT[]. NULL = never populated by ingest (empty x_mitre_sectors in STIX); non-empty = MITRE-declared sectors. Consumers should COALESCE to [].';
COMMENT ON COLUMN attack_assets.platforms IS
  'TEXT[]. NULL = never populated by ingest; see attack_assets.sectors.';

-- ---------------------------------------------------------------------------
-- 2. Technique -> asset edges — 842 rows (attack-pattern --targets--> asset)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS asset_techniques (
  asset_id     UUID NOT NULL REFERENCES attack_assets(id) ON DELETE CASCADE,
  technique_id UUID NOT NULL REFERENCES techniques(id)    ON DELETE CASCADE,
  PRIMARY KEY (asset_id, technique_id)
);
-- Reverse lookup ("which assets does technique T target?"). The forward
-- direction is served by the PK. No other index is added: at 18 assets /
-- 842 edges / 42 rules every target query plans in well under a millisecond
-- (the /frameworks/purdue rollup measured 0.535 ms, shared hit=8), so an
-- index on primary_level or flow_rules(to_level) would be pure overhead.
CREATE INDEX IF NOT EXISTS idx_asset_techniques_tech ON asset_techniques(technique_id);

-- ---------------------------------------------------------------------------
-- 3. Related assets — free text in STIX, not object refs
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS asset_related_assets (
  asset_id        UUID NOT NULL REFERENCES attack_assets(id) ON DELETE CASCADE,
  related_name    TEXT NOT NULL,
  related_sectors TEXT[],
  description     TEXT,
  PRIMARY KEY (asset_id, related_name)
);

-- ---------------------------------------------------------------------------
-- 4. Purdue levels — 7 reference rows
-- ---------------------------------------------------------------------------
-- level_key is TEXT, not numeric. numeric(3,1) was tried and rejected: node-pg
-- has no parser for OID 1700, so a scalar numeric arrives as a STRING ("3.5")
-- while numeric[] (OID 1231) arrives as NUMBERS ([0,3.5]) — making
-- `spans_levels.includes(primary_level)` silently always false, in exactly the
-- query this feature exists to serve. A text key also gives canonical URLs
-- (/frameworks/purdue/l3_5) matching the framework-slug convention.
CREATE TABLE IF NOT EXISTS purdue_levels (
  level_key   TEXT     PRIMARY KEY CHECK (level_key ~ '^l[0-5](_5)?$'),
  label       TEXT     NOT NULL,
  zone        TEXT     NOT NULL CHECK (zone IN ('ot','dmz','it')),
  description TEXT     NOT NULL,
  sort_order  SMALLINT NOT NULL UNIQUE   -- 0,10,20,30,35,40,50 (int2 -> real JS number)
);

-- ---------------------------------------------------------------------------
-- 5. Curated asset -> level placement — 18 rows, seeded from
--    src/lib/purdue-registry.ts (the scf-framework-registry.ts pattern)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS asset_purdue_placement (
  asset_id      UUID        PRIMARY KEY,
  attack_id     VARCHAR(20) NOT NULL,   -- recorded, not the key; kept honest by the composite FK
  primary_level TEXT        NOT NULL REFERENCES purdue_levels(level_key),
  -- No DEFAULT: '{}' can never satisfy primary_in_spans, so a default would be
  -- dead code that guarantees a constraint violation. Callers must be explicit.
  spans_levels  TEXT[]      NOT NULL,
  -- Generated, so it can never contradict spans_levels. Boundary means
  -- "present in the industrial DMZ" — Jump Host {l3_5} is the archetypal
  -- boundary asset, so a "spans more than one level" definition would be wrong.
  is_boundary   BOOLEAN GENERATED ALWAYS AS ('l3_5' = ANY(spans_levels)) STORED,
  rationale     TEXT        NOT NULL,
  source        TEXT        NOT NULL DEFAULT 'curated:800-82r3+isa-95',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  FOREIGN KEY (asset_id, attack_id)
    REFERENCES attack_assets(id, attack_id) ON DELETE CASCADE,
  CONSTRAINT primary_in_spans CHECK (primary_level = ANY(spans_levels)),
  -- Closed 7-value vocabulary. A FK is impossible from an array; this CHECK is
  -- equivalent in strength for a fixed standard and catches typos (verified: it
  -- rejects both 'l9' and the case error 'L3_5'). The set-level invariant
  -- "every element exists in purdue_levels" is asserted by
  -- scripts/verify-ics-assets.mjs, which also covers the cardinality rules a
  -- CHECK cannot express (subqueries are not permitted in CHECK constraints).
  CONSTRAINT spans_valid
    CHECK (spans_levels <@ ARRAY['l0','l1','l2','l3','l3_5','l4','l5']::text[])
);

-- ---------------------------------------------------------------------------
-- 6. Flow rules — all 42 ordered pairs, explicit, no inference
-- ---------------------------------------------------------------------------
-- direct_allowed means exactly one thing: a DIRECT, SINGLE-HOP network
-- adjacency is permitted. It is not a reachability claim. Where a pair is
-- reachable only by terminating a session at an intermediate level,
-- direct_allowed is false and broker_level names that level — so a consumer
-- can never mistake a brokered pair for an adjacency.
CREATE TABLE IF NOT EXISTS purdue_flow_rules (
  from_level     TEXT    NOT NULL REFERENCES purdue_levels(level_key),
  to_level       TEXT    NOT NULL REFERENCES purdue_levels(level_key),
  direct_allowed BOOLEAN NOT NULL,
  broker_level   TEXT    REFERENCES purdue_levels(level_key),
  note           TEXT,
  PRIMARY KEY (from_level, to_level),
  CONSTRAINT no_self_loop CHECK (from_level <> to_level),
  CONSTRAINT broker_not_endpoint
    CHECK (broker_level IS NULL OR broker_level NOT IN (from_level, to_level)),
  -- A brokered pair is by definition not directly adjacent.
  CONSTRAINT broker_implies_indirect
    CHECK (broker_level IS NULL OR direct_allowed = false)
);

COMMIT;
