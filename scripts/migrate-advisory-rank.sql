-- osv_advisory_rank — the sort/filter key behind GET /api/v1/advisories.
--
-- Apply with:
--   psql "$DATABASE_URL" -f scripts/migrate-advisory-rank.sql
--
-- Refreshed CONCURRENTLY by app/api/cron/refresh-matviews/route.ts, which is
-- why the UNIQUE index below is mandatory.
--
-- ═══════════════════════════════════════════════════════════════════════════
-- WHY THIS EXISTS
--
-- /api/v1/advisories never returned. Measured: curl gave up after 280 s and the
-- backend query was still `active` in pg_stat_activity 47 minutes later. The
-- data query is a UNION ALL of a 34,836-row GHSA branch and a 1,945,966-row OSV
-- branch, sorted, to return 50 rows — and the OSV branch evaluated, for EVERY
-- row before the sort:
--
--   * a LEFT JOIN LATERAL point lookup into cve_details (to backfill severity),
--   * `(SELECT a FROM unnest(o.aliases) a WHERE a LIKE 'CVE-%' LIMIT 1)`,
--   * `package_count` = one lookup per row into osv_affected
--     (8,718,078 rows / 7273 MB) — 1.9M probes into the largest table we have.
--
-- Indexes alone cannot fix it, because the sort key IS a computed value:
--   ORDER BY CASE severity ... END DESC, published_at DESC, advisory_id DESC
-- where `severity = COALESCE(o.cvss_severity, cve.cvss_severity)`, and 892,866
-- of the 1,945,966 OSV rows have `cvss_severity IS NULL` and so depend on the
-- lateral. There is nothing to index. The sort key has to be materialised.
--
-- ═══════════════════════════════════════════════════════════════════════════
-- WHY IT IS THIS NARROW
--
-- The obvious alternative — a denormalised matview of the whole UNION, payload
-- included — was rejected on refresh cost. It would have to carry
-- `package_count`, which means doing those 1.9M osv_affected probes on every
-- refresh, twice a day, forever. This matview holds ONLY what the WHERE and the
-- ORDER BY need. Everything else (summary, cve_id, ecosystems, package_count,
-- and the live COALESCE'd severity/cvss_score actually returned to the client)
-- is computed by the route's original SELECT lists, unchanged, against the ≤
-- `limit` rows on the requested page. So the refresh never touches osv_affected
-- and never duplicates `summary`.
--
-- ═══════════════════════════════════════════════════════════════════════════
-- WHY THERE IS NO `severity` TEXT COLUMN
--
-- `sev_rank` is the CASE expression from the route's ORDER BY, materialised.
-- The route's `?severity=` filter only accepts CRITICAL / HIGH / MEDIUM / LOW,
-- and the CASE maps exactly those four to 4 / 3 / 2 / 1 and everything else
-- (including cve_details' 'NONE' and NULL) to 0. So `severity = 'HIGH'` is
-- equivalent to `sev_rank = 3`, and the filter becomes an equality on the
-- LEADING column of the ordering index instead of a separate column + index.
--
-- ═══════════════════════════════════════════════════════════════════════════
-- STALENESS THIS INTRODUCES, STATED PLAINLY
--
-- `pagination.total` for the OSV half is now counted from this matview, so it is
-- as of the last refresh rather than live. That is acceptable here specifically
-- because OSV ingest is NOT on a cron — there is no OSV entry in vercel.json;
-- it is a manual monthly full ingest (see the note in the advisories route). A
-- 12-hour-old row count for a table that changes once a month is not a
-- meaningful deviation. If OSV ever goes onto a daily cron, add a
-- `REFRESH MATERIALIZED VIEW CONCURRENTLY osv_advisory_rank` to the tail of that
-- cron.
--
-- The severity a row is SORTED by is likewise as of the last refresh, while the
-- severity RETURNED to the client stays live (the route keeps the original
-- COALESCE). They can disagree for a row whose cve_details severity changed
-- since the refresh — such a row can land on a neighbouring page. Chosen
-- deliberately over the alternative, which was to serve a stale severity VALUE:
-- the response field then would not match what /api/v1/cves says.
-- ═══════════════════════════════════════════════════════════════════════════
\set ON_ERROR_STOP on

BEGIN;

DROP MATERIALIZED VIEW IF EXISTS osv_advisory_rank;

CREATE MATERIALIZED VIEW osv_advisory_rank AS
SELECT
  o.osv_id,
  o.ecosystem,
  o.published,
  -- Mirror of ORDER_CLAUSE in app/api/v1/advisories/route.ts. Keep in sync.
  (CASE COALESCE(o.cvss_severity, cve.cvss_severity)
     WHEN 'CRITICAL' THEN 4
     WHEN 'HIGH'     THEN 3
     WHEN 'MEDIUM'   THEN 2
     WHEN 'LOW'      THEN 1
     ELSE 0
   END)::int AS sev_rank,
  -- Mirror of the route's `?has_cve=` predicate.
  EXISTS (SELECT 1 FROM unnest(o.aliases) a WHERE a LIKE 'CVE-%') AS has_cve
FROM osv_advisories o
LEFT JOIN LATERAL (
  SELECT cd.cvss_severity
  FROM cve_details cd
  WHERE cd.cve_id = ANY(o.aliases)
  LIMIT 1
) cve ON true;

-- Required by REFRESH MATERIALIZED VIEW CONCURRENTLY. Matches the
-- osv_advisories_osv_id_ecosystem_key uniqueness on the source table — note
-- that osv_id ALONE is not unique: 319,917 osv_ids appear under more than one
-- ecosystem.
CREATE UNIQUE INDEX osv_advisory_rank_pk_idx
  ON osv_advisory_rank (osv_id, ecosystem);

-- The route's exact ORDER BY. Serves the unfiltered page, `?severity=`
-- (equality on the leading column), `?since=` (range on the second) and
-- `?has_cve=` (cheap recheck) as a plain forward index scan of `limit + offset`
-- entries.
CREATE INDEX osv_advisory_rank_order_idx
  ON osv_advisory_rank (sev_rank DESC, published DESC NULLS LAST, osv_id DESC);

-- Same, prefixed by ecosystem, for `?ecosystem=` / `?category=`.
CREATE INDEX osv_advisory_rank_eco_order_idx
  ON osv_advisory_rank (ecosystem, sev_rank DESC, published DESC NULLS LAST, osv_id DESC);

COMMIT;

ANALYZE osv_advisory_rank;
