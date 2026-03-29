-- MITRE ATLAS integration migration
-- Run on both local and Neon

-- Maturity column for ATLAS techniques
ALTER TABLE techniques ADD COLUMN IF NOT EXISTS maturity VARCHAR(20);

-- Cross-references: ATLAS technique ↔ ATT&CK technique
CREATE TABLE IF NOT EXISTS atlas_xrefs (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  atlas_technique_id    UUID NOT NULL REFERENCES techniques(id) ON DELETE CASCADE,
  attack_technique_id   UUID NOT NULL REFERENCES techniques(id) ON DELETE CASCADE,
  UNIQUE (atlas_technique_id, attack_technique_id)
);
CREATE INDEX IF NOT EXISTS idx_atlas_xrefs_atlas ON atlas_xrefs(atlas_technique_id);
CREATE INDEX IF NOT EXISTS idx_atlas_xrefs_attack ON atlas_xrefs(attack_technique_id);
