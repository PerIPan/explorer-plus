-- scripts/migrate-epss.sql
--
-- EPSS (Exploit Prediction Scoring System) enrichment for cve_details.
-- NUMERIC(6,5) = 1 digit before decimal + 5 after → range [0.00000, 9.99999].
-- EPSS probabilities are in [0,1] but the percentile field legitimately hits
-- exactly 1.00000 for top-ranked CVEs (100th percentile), so NUMERIC(5,5)
-- (which caps at 0.99999) causes "numeric field overflow" on production data.
-- NUMERIC(6,5) accepts 1.00000; a follow-up CHECK constraint can enforce <=1
-- if we want stricter validation.
--
-- Apply idempotently via direct (non-pooler) Neon URL:
--   PGPASSWORD=... psql "$DIRECT_URL" -f scripts/migrate-epss.sql

ALTER TABLE cve_details
  ADD COLUMN IF NOT EXISTS epss_score NUMERIC(6, 5),
  ADD COLUMN IF NOT EXISTS epss_percentile NUMERIC(6, 5),
  ADD COLUMN IF NOT EXISTS epss_updated_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_cve_details_epss_score
  ON cve_details(epss_score DESC NULLS LAST);
