-- scripts/migrate-ai-rmf-tier.sql
--
-- Bring the two NIST AI rows in scf_frameworks in line with
-- src/lib/scf-framework-registry.ts without waiting for the next SCF ingest:
--   * nist-ai-rmf: version '1.0' (it claimed '1.0 + Generative AI Profile',
--     but its aliases only ever matched the AI RMF column).
--   * nist-600-1-gen-ai-profile: the GenAI Profile, ingested as Tier 3 under
--     its FDI-derived key; promoted to Tier 2 under the SAME key, so its
--     /compliance URL, scf_framework_refs rows and alias history are untouched.
--
-- Every tier filter (app/api/v1/compliance/*, nav-counts, sitemap) is a live
-- join on scf_frameworks and no summary table carries a tier column, so no
-- refresh is needed afterwards. The next sync-scf run writes the same values
-- from the registry, so this file and an ingest agree.
--
-- Idempotent: rows already holding these values are left alone (updated_at
-- moves only for a real change). Aborts, rolling back, unless both keys exist —
-- the 600-1 row only appears after an SCF ingest.
--
-- Run:
--   psql "$DATABASE_URL" -f scripts/migrate-ai-rmf-tier.sql
--
-- Rollback:
--   UPDATE scf_frameworks SET tier = 3, version = NULL, updated_at = now()
--     WHERE framework_key = 'nist-600-1-gen-ai-profile';
--   UPDATE scf_frameworks SET version = '1.0 + Generative AI Profile', updated_at = now()
--     WHERE framework_key = 'nist-ai-rmf';

\set ON_ERROR_STOP on

BEGIN;

DO $$
DECLARE
  n int;
BEGIN
  SELECT count(*) INTO n FROM scf_frameworks
   WHERE framework_key IN ('nist-ai-rmf', 'nist-600-1-gen-ai-profile');
  IF n <> 2 THEN
    RAISE EXCEPTION 'migrate-ai-rmf-tier: expected 2 scf_frameworks rows, found % — run the SCF ingest first', n;
  END IF;
END $$;

UPDATE scf_frameworks f
   SET name         = v.name,
       version      = v.version,
       source_org   = v.source_org,
       upstream_url = v.upstream_url,
       region       = v.region,
       tier         = v.tier,
       license      = v.license,
       short_blurb  = v.short_blurb,
       updated_at   = now()
  FROM (VALUES
    ('nist-ai-rmf',
     'NIST AI RMF 1.0', '1.0', 'NIST',
     'https://www.nist.gov/itl/ai-risk-management-framework', 'global', 2,
     'Public Domain (US Government Work)',
     'Voluntary AI risk-management framework (Govern, Map, Measure, Manage). Its Generative AI Profile, NIST AI 600-1, is listed separately.'),
    ('nist-600-1-gen-ai-profile',
     'NIST AI 600-1 — Generative AI Profile', 'July 2024', 'NIST',
     'https://doi.org/10.6028/NIST.AI.600-1', 'global', 2,
     'Public Domain (US Government Work)',
     'Cross-sectoral AI RMF profile for generative AI: 12 risks unique to or exacerbated by GenAI, with suggested actions per AI RMF function.')
  ) AS v(framework_key, name, version, source_org, upstream_url, region, tier, license, short_blurb)
 WHERE f.framework_key = v.framework_key
   AND (f.name, f.version, f.source_org, f.upstream_url, f.region, f.tier, f.license, f.short_blurb)
       IS DISTINCT FROM
       (v.name, v.version, v.source_org, v.upstream_url, v.region, v.tier, v.license, v.short_blurb);

COMMIT;
