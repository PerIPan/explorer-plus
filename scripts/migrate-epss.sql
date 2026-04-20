-- scripts/migrate-epss.sql
--
-- EPSS (Exploit Prediction Scoring System) enrichment for cve_details.
-- NUMERIC(5,5) = 0 digits before decimal, 5 after → range [0.00000, 0.99999].
-- EPSS scores are probabilities in [0,1]; the theoretical 1.0 is capped
-- at 0.99999 in practice. This type rejects any corrupt input >1.
--
-- Apply idempotently via direct (non-pooler) Neon URL:
--   PGPASSWORD=... psql "$DIRECT_URL" -f scripts/migrate-epss.sql

ALTER TABLE cve_details
  ADD COLUMN IF NOT EXISTS epss_score NUMERIC(5, 5),
  ADD COLUMN IF NOT EXISTS epss_percentile NUMERIC(5, 5),
  ADD COLUMN IF NOT EXISTS epss_updated_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_cve_details_epss_score
  ON cve_details(epss_score DESC NULLS LAST);
