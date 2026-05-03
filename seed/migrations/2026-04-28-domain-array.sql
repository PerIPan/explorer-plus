-- seed/migrations/2026-04-28-domain-array.sql
--
-- Preflight A for the attack-update script (docs/mitre_update.md).
-- Convert single-value `domain VARCHAR(50)` columns on the three cross-domain
-- entity tables to `TEXT[]` so APT28-class actors that appear in multiple
-- STIX bundles (Enterprise + ICS) don't silently overwrite each other on
-- multi-domain ingest.
--
-- Pre-measurement (run before applying):
--   SELECT 'threat_groups', COUNT(*), COUNT(DISTINCT domain) FROM threat_groups
--   UNION ALL SELECT 'attack_software', COUNT(*), COUNT(DISTINCT domain) FROM attack_software
--   UNION ALL SELECT 'campaigns', COUNT(*), COUNT(DISTINCT domain) FROM campaigns;
--
-- Post-measurement (run after applying):
--   Same query — row counts must match exactly. data_type for the domain
--   column should now be ARRAY (text[]).
--
-- This migration is reversible:
--   ALTER TABLE threat_groups   ALTER COLUMN domain TYPE TEXT USING domain[1];
--   ALTER TABLE attack_software ALTER COLUMN domain TYPE TEXT USING domain[1];
--   ALTER TABLE campaigns       ALTER COLUMN domain TYPE TEXT USING domain[1];
--   (drops any extra domain memberships acquired since migration — only safe
--    while every row's domain array still has length 1.)

BEGIN;

ALTER TABLE threat_groups
  ALTER COLUMN domain TYPE TEXT[] USING ARRAY[domain]::TEXT[];

ALTER TABLE attack_software
  ALTER COLUMN domain TYPE TEXT[] USING ARRAY[domain]::TEXT[];

ALTER TABLE campaigns
  ALTER COLUMN domain TYPE TEXT[] USING ARRAY[domain]::TEXT[];

CREATE INDEX IF NOT EXISTS idx_threat_groups_domain
  ON threat_groups USING gin(domain);
CREATE INDEX IF NOT EXISTS idx_attack_software_domain
  ON attack_software USING gin(domain);
CREATE INDEX IF NOT EXISTS idx_campaigns_domain
  ON campaigns USING gin(domain);

COMMIT;
