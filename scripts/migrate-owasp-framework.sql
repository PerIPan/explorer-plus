BEGIN;

ALTER TABLE owasp_top10 ADD COLUMN IF NOT EXISTS framework VARCHAR(50) NOT NULL DEFAULT 'web-2021';
ALTER TABLE owasp_top10 ADD COLUMN IF NOT EXISTS atlas_technique_ids TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE owasp_top10 ADD COLUMN IF NOT EXISTS is_draft BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE owasp_top10 ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

ALTER TABLE owasp_top10 DROP CONSTRAINT IF EXISTS owasp_top10_category_id_key;
DROP INDEX IF EXISTS idx_owasp_top10_category;

CREATE UNIQUE INDEX IF NOT EXISTS idx_owasp_category_framework
  ON owasp_top10(category_id, framework);

DO $$ BEGIN
  ALTER TABLE owasp_top10
    ADD CONSTRAINT chk_owasp_framework
    CHECK (framework IN ('web-2021', 'ml-2023', 'llm-2025'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE INDEX IF NOT EXISTS idx_owasp_cwe_ids_gin ON owasp_top10 USING gin(cwe_ids);
CREATE INDEX IF NOT EXISTS idx_owasp_atlas_ids_gin ON owasp_top10 USING gin(atlas_technique_ids);

CREATE INDEX IF NOT EXISTS idx_owasp_search_gin
  ON owasp_top10 USING gin(to_tsvector('english', name || ' ' || COALESCE(description, '')));

COMMIT;
