-- Post-backfill repair, in dependency order. Run ONCE, after
-- scripts/backfill-cve-history.mjs reports success.
--
--   psql "$DATABASE_URL" -f scripts/post-backfill.sql
--
-- Not inside a transaction: VACUUM cannot run in one, and each step is
-- independently re-runnable.

\pset pager off
\timing on

-- ---------------------------------------------------------------------------
-- 1. KEV flags for rows that did not exist when the KEV feed last ran.
--
-- Backfilled rows land with is_kev = false (column default) because the KEV
-- cron only ever flags CVEs already present. ioc_entries already holds the
-- authoritative KEV list independently of cve_details, so this is the same
-- assignment ingest-cisa-kev would make on its next run, applied now rather
-- than leaving every KEV-rate display wrong until tomorrow.
-- ---------------------------------------------------------------------------
UPDATE cve_details d
   SET is_kev = true, updated_at = NOW()
 WHERE NOT d.is_kev
   AND EXISTS (SELECT 1 FROM ioc_entries i
                WHERE i.type = 'cve' AND i.source = 'cisa_kev' AND i.value = d.cve_id);

-- ---------------------------------------------------------------------------
-- 2. Statistics and space. autovacuum had NEVER run on cve_details,
-- cve_weaknesses or affected_products (autovacuum_count 0, last_autoanalyze
-- NULL), so without this the planner keeps costing every query against the
-- pre-backfill row counts and picks plans for a table a third of the size.
-- ---------------------------------------------------------------------------
VACUUM ANALYZE cve_details;
VACUUM ANALYZE cve_weaknesses;
VACUUM ANALYZE affected_products;
VACUUM ANALYZE applications;

-- ---------------------------------------------------------------------------
-- 3. Derived objects.
--
-- catchall_cwes FIRST: technique_cve_evidence reads it. It is itself a no-op
-- here — it depends only on capec_mappings, which the backfill never writes —
-- but refreshing it costs 0.2s and removes the question.
--
-- app_technique_groups does NOT read catchall_cwes (it inlines its own
-- HAVING > 10), so it carries no ordering constraint and is listed last purely
-- because it is the expensive one.
--
-- work_mem is raised for this session: at the default 4MB the
-- app_technique_groups DISTINCT spills ~126MB to temp disk, and the spill is
-- what grows with the corpus.
-- ---------------------------------------------------------------------------
SET work_mem = '256MB';

REFRESH MATERIALIZED VIEW CONCURRENTLY catchall_cwes;
REFRESH MATERIALIZED VIEW CONCURRENTLY technique_cve_evidence;
REFRESH MATERIALIZED VIEW CONCURRENTLY app_technique_groups;

RESET work_mem;

-- osv_advisory_rank also reads cve_details.cvss_severity, but it self-heals on
-- its own 13:00 UTC schedule and only ~11,000 of 1.97M OSV advisories carry a
-- CVE alias, so it is deliberately left alone.
