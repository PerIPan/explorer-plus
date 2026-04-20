-- scripts/migrate-capec-full.sql
--
-- Full CAPEC taxonomy (patterns, mitigations, relationships) beyond the
-- existing `capec_mappings` bridge table.
--
-- Apply via direct (non-pooler) Neon URL:
--   PGPASSWORD=... psql "$DIRECT_URL" -f scripts/migrate-capec-full.sql

CREATE TABLE IF NOT EXISTS capec_patterns (
  id                  text PRIMARY KEY,         -- 'CAPEC-1', 'CAPEC-66', ...
  name                text NOT NULL,
  description         text,
  abstraction         text,                     -- 'Meta' | 'Standard' | 'Detailed'
  status              text,                     -- 'Draft' | 'Stable' | 'Deprecated'
  likelihood          text,                     -- 'Low' | 'Medium' | 'High'
  severity            text,                     -- 'Very Low' ... 'Very High'
  prerequisites       text[],
  resources_required  text[],
  skills_required     jsonb,                    -- {level: description}
  consequences        jsonb,                    -- {category: [impacts]}
  example_instances   text[],
  cwe_ids             text[],                   -- referenced CWEs
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_capec_patterns_abstraction ON capec_patterns(abstraction);

CREATE TABLE IF NOT EXISTS capec_mitigations (
  id          text PRIMARY KEY,                 -- STIX UUID for the course-of-action object
  name        text,
  description text
);

CREATE TABLE IF NOT EXISTS capec_pattern_mitigations (
  capec_id       text NOT NULL,
  mitigation_id  text NOT NULL,
  UNIQUE (capec_id, mitigation_id)
);
CREATE INDEX IF NOT EXISTS idx_capec_pm_capec ON capec_pattern_mitigations(capec_id);
CREATE INDEX IF NOT EXISTS idx_capec_pm_mit ON capec_pattern_mitigations(mitigation_id);

CREATE TABLE IF NOT EXISTS capec_related (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  capec_id         text NOT NULL,
  related_capec_id text NOT NULL,
  nature           text NOT NULL,               -- 'ChildOf' | 'ParentOf' | 'CanPrecede' | 'CanFollow'
  UNIQUE (capec_id, related_capec_id, nature)
);
CREATE INDEX IF NOT EXISTS idx_capec_related_capec ON capec_related(capec_id);
CREATE INDEX IF NOT EXISTS idx_capec_related_related ON capec_related(related_capec_id);
