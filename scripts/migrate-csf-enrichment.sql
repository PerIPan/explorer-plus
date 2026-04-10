-- CSF v2 enrichment: Implementation Examples, Informative References, category descriptions.
-- Safe to re-run (idempotent) — uses IF NOT EXISTS everywhere.

-- 1. Category description column (denormalized onto existing csf_subcategories)
ALTER TABLE csf_subcategories
  ADD COLUMN IF NOT EXISTS category_description text;

-- 2. Implementation examples
CREATE TABLE IF NOT EXISTS csf_implementation_examples (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  csf_subcategory_uuid uuid NOT NULL REFERENCES csf_subcategories(id) ON DELETE CASCADE,
  subcategory_id text NOT NULL,
  example_id text NOT NULL,
  ordinal smallint NOT NULL,
  text text NOT NULL,
  source text NOT NULL DEFAULT 'nist-csf-v2',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (subcategory_id, example_id)
);

CREATE INDEX IF NOT EXISTS idx_csf_examples_subcat
  ON csf_implementation_examples(subcategory_id);
CREATE INDEX IF NOT EXISTS idx_csf_examples_uuid
  ON csf_implementation_examples(csf_subcategory_uuid);

-- 3. Informative references (NIST 800-53, CIS v8, ISO 27001:2022, 800-221A, 800-207, ...)
CREATE TABLE IF NOT EXISTS csf_informative_references (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  csf_subcategory_uuid uuid NOT NULL REFERENCES csf_subcategories(id) ON DELETE CASCADE,
  subcategory_id text NOT NULL,
  target_framework text NOT NULL,
  target_id text NOT NULL,
  target_text text,
  relationship text,
  source text NOT NULL DEFAULT 'nist-csf-v2',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (subcategory_id, target_framework, target_id)
);

CREATE INDEX IF NOT EXISTS idx_csf_refs_subcat
  ON csf_informative_references(subcategory_id);
CREATE INDEX IF NOT EXISTS idx_csf_refs_target
  ON csf_informative_references(target_framework, target_id);
CREATE INDEX IF NOT EXISTS idx_csf_refs_uuid
  ON csf_informative_references(csf_subcategory_uuid);

-- 4. Framework slug normalization helper (comment-only — actual values come from ingest script)
-- Expected normalized target_framework values:
--   '800-53r5'           NIST SP 800-53 Revision 5
--   'cis-v8'             CIS Controls v8
--   'iso-27001-2022'     ISO/IEC 27001:2022
--   '800-221a'           NIST SP 800-221A (Enterprise Risk Management)
--   '800-207'            NIST SP 800-207 (Zero Trust)
