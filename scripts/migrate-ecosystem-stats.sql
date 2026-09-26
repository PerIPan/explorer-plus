-- ecosystem_advisory_stats — the aggregate behind GET /api/v1/ecosystems.
--
-- Apply with:
--   psql "$DATABASE_URL" -f scripts/migrate-ecosystem-stats.sql
--
-- Refreshed CONCURRENTLY by app/api/cron/refresh-matviews/route.ts, which is
-- why the UNIQUE index at the bottom is mandatory.
--
-- ═══════════════════════════════════════════════════════════════════════════
-- WHY THIS EXISTS
--
-- /api/v1/ecosystems recomputed this whole aggregate on every request and took
-- 48,671 ms measured through the production server. The dominant cost is the
-- `osv_pkg_counts` CTE: GROUP BY (ecosystem, package_name) over 8,718,078
-- osv_affected rows (5249 MB heap) with Neon's work_mem = 4MB, so the hash
-- aggregate spills to disk (7,536 kB per worker). 40.9 s of the 48.7 s is that
-- one CTE. Nothing in here depends on the request, and the inputs only change
-- on ingest, so it belongs in a matview.
--
-- ═══════════════════════════════════════════════════════════════════════════
-- WHAT IS DELIBERATELY *NOT* IN HERE: last14d
--
-- The endpoint also returns `last14dCount`, a NOW() - INTERVAL '14 days'
-- window. Materialising it HERE would freeze the window at refresh time, so
-- between the 06:30 and 18:30 refreshes the endpoint would report a 14-day
-- count as of up to 12 hours ago — a response that changes with no ingest
-- behind it. Everything in THIS matview is time-independent. The window is
-- served exactly by the second matview at the bottom of this file
-- (`ecosystem_advisory_days`) plus a sub-day live remainder; read that header
-- for why it is bucketed by day rather than computed live in full.
--
-- ═══════════════════════════════════════════════════════════════════════════
-- WHY THERE IS AN `ord` COLUMN
--
-- The endpoint response is a JSON array and the query it replaced had NO
-- ORDER BY — the array order was the natural output of
-- `ghsa_agg UNION ALL osv_agg` LEFT JOINed to top3: the 12 GHSA ecosystems
-- (alphabetical, from the grouped aggregate) followed by the 33 OSV ones in
-- hash-aggregate order. External callers consume that array, so the order is
-- part of the response.
--
-- Selecting from a matview without ORDER BY would NOT reproduce it:
-- REFRESH MATERIALIZED VIEW CONCURRENTLY diffs into the existing heap with
-- INSERT/UPDATE/DELETE, so physical row order drifts with every refresh.
-- `ord` captures the defining query's own output order at build time via
-- `row_number() OVER ()`, and the route does `ORDER BY ord`. The array order is
-- therefore whatever this query produces, refresh after refresh.
--
-- ═══════════════════════════════════════════════════════════════════════════
-- WHY `src` IS A COLUMN AND WHY THE UNIQUE KEY IS `ord`, NOT `canonical`
--
-- ghsa_agg groups by LOWER(p.ecosystem) and osv_agg by o.ecosystem, and the two
-- are disjoint only by ingest convention (the OSV cron skips GHSA-covered
-- ecosystems). If that ever slipped, `canonical` would collide across the two
-- branches — today the union is 12 + 33 = 45 distinct rows, but nothing
-- enforces it. A UNIQUE index on `canonical` would then fail the CONCURRENTLY
-- refresh, and the live last14d lookup would attribute one branch's count to
-- the other. `ord` is unique by construction, and `src` keys the live last14d
-- join per branch, so a collision degrades to exactly what the old query did:
-- two rows, each with its own numbers.
-- ═══════════════════════════════════════════════════════════════════════════
\set ON_ERROR_STOP on

BEGIN;

DROP MATERIALIZED VIEW IF EXISTS ecosystem_advisory_stats;

CREATE MATERIALIZED VIEW ecosystem_advisory_stats AS
WITH ghsa_pkg_counts AS (
  SELECT LOWER(p.ecosystem) AS eco, p.package_name AS pkg, COUNT(*)::int AS n
  FROM ghsa_advisories g
  JOIN ghsa_packages gp ON gp.ghsa_id = g.ghsa_id
  JOIN packages p ON p.id = gp.package_id
  WHERE g.withdrawn_at IS NULL
  GROUP BY LOWER(p.ecosystem), p.package_name
),
osv_pkg_counts AS (
  SELECT oa.ecosystem AS eco, oa.package_name AS pkg, COUNT(*)::int AS n
  FROM osv_affected oa
  GROUP BY oa.ecosystem, oa.package_name
),
combined_pkg_counts AS (
  SELECT eco, pkg, SUM(n)::int AS n FROM (
    SELECT * FROM ghsa_pkg_counts
    UNION ALL
    SELECT * FROM osv_pkg_counts
  ) u GROUP BY eco, pkg
),
top_pkgs AS (
  SELECT eco, pkg, n,
         ROW_NUMBER() OVER (PARTITION BY eco ORDER BY n DESC, pkg ASC) AS rk
  FROM combined_pkg_counts
),
top3 AS (
  SELECT eco,
         ARRAY_AGG(pkg ORDER BY rk) FILTER (WHERE rk <= 3)  AS top_packages,
         ARRAY_AGG(n   ORDER BY rk) FILTER (WHERE rk <= 3)  AS top_counts
  FROM top_pkgs
  GROUP BY eco
),
ghsa_agg AS (
  SELECT
    'GHSA'::text AS src,
    LOWER(p.ecosystem) AS canonical,
    COUNT(DISTINCT g.ghsa_id)::int AS total,
    COUNT(DISTINCT g.ghsa_id) FILTER (WHERE g.severity = 'CRITICAL')::int AS crit,
    COUNT(DISTINCT g.ghsa_id) FILTER (WHERE g.severity = 'HIGH')::int AS high,
    COUNT(DISTINCT g.ghsa_id) FILTER (WHERE g.severity = 'MEDIUM')::int AS med,
    COUNT(DISTINCT g.ghsa_id) FILTER (WHERE g.severity = 'LOW')::int AS low,
    COUNT(DISTINCT g.ghsa_id) FILTER (WHERE g.severity IS NULL)::int AS unrated
  FROM ghsa_advisories g
  JOIN ghsa_packages gp ON gp.ghsa_id = g.ghsa_id
  JOIN packages p ON p.id = gp.package_id
  WHERE g.withdrawn_at IS NULL
  GROUP BY LOWER(p.ecosystem)
),
osv_agg AS (
  SELECT
    'OSV'::text AS src,
    o.ecosystem AS canonical,
    COUNT(*)::int AS total,
    COUNT(*) FILTER (WHERE COALESCE(o.cvss_severity, cve.cvss_severity) = 'CRITICAL')::int AS crit,
    COUNT(*) FILTER (WHERE COALESCE(o.cvss_severity, cve.cvss_severity) = 'HIGH')::int AS high,
    COUNT(*) FILTER (WHERE COALESCE(o.cvss_severity, cve.cvss_severity) = 'MEDIUM')::int AS med,
    COUNT(*) FILTER (WHERE COALESCE(o.cvss_severity, cve.cvss_severity) = 'LOW')::int AS low,
    COUNT(*) FILTER (WHERE COALESCE(o.cvss_severity, cve.cvss_severity) IS NULL)::int AS unrated
  FROM osv_advisories o
  LEFT JOIN LATERAL (
    SELECT cd.cvss_severity FROM cve_details cd
    WHERE cd.cve_id = ANY(o.aliases) LIMIT 1
  ) cve ON true
  GROUP BY o.ecosystem
),
all_agg AS (
  SELECT * FROM ghsa_agg
  UNION ALL
  SELECT * FROM osv_agg
)
SELECT
  (ROW_NUMBER() OVER ())::int AS ord,
  a.src,
  a.canonical,
  a.total,
  a.crit,
  a.high,
  a.med,
  a.low,
  a.unrated,
  t.top_packages,
  t.top_counts
FROM all_agg a
LEFT JOIN top3 t ON t.eco = a.canonical;

-- Required by REFRESH MATERIALIZED VIEW CONCURRENTLY. See the header for why
-- the key is `ord` rather than `canonical`.
CREATE UNIQUE INDEX ecosystem_advisory_stats_ord_idx
  ON ecosystem_advisory_stats (ord);

COMMIT;

-- Supports the sub-day boundary remainder the route computes live alongside
-- `ecosystem_advisory_days` (see its header below): ~800 rows off the tail of
-- the published ordering, with `ecosystem` in the index so the aggregate does
-- not need a column the heap alone can supply.
CREATE INDEX IF NOT EXISTS idx_osv_published_ecosystem
  ON osv_advisories (published DESC NULLS LAST, ecosystem);

-- ═══════════════════════════════════════════════════════════════════════════
-- ecosystem_advisory_days — the EXACT 14-day window, without the live scan.
--
-- First attempt at `last14dCount` was a live
-- `WHERE published >= NOW() - INTERVAL '14 days' GROUP BY ecosystem` over
-- osv_advisories, backed by the idx_osv_published_ecosystem index above. It
-- measured 32,895 ms / 21,510 ms on a re-run. The index IS used, but it is not
-- an index-only scan in practice:
--
--   Index Only Scan using idx_osv_published_ecosystem  (rows=56311)
--     Heap Fetches: 53880
--     Buffers: shared hit=49920 read=21672
--
-- `pg_class.relallvisible` for osv_advisories is 48,867 of 97,743 pages — 50%.
-- The recent tail is the LEAST visible part of the table (newest writes,
-- not yet autovacuumed), so an index-only scan over the last 14 days will
-- always degrade to ~54k random heap fetches, cache or no cache. Nothing about
-- the index fixes that.
--
-- So: bucket the counts by UTC day, which is time-INDEPENDENT and therefore
-- materialisable, and keep only the sub-day boundary slice live:
--
--   count(published >= B)
--     = count(published >= date_trunc('day', B))       <- from this matview
--     - count(date_trunc('day', B) <= published < B)   <- live, ~800 rows
--
-- Measured, that live remainder is 807 rows / 637 heap fetches / 1,247 ms under
-- the same contention that made the full-window version take 32 s. The answer
-- is arithmetically identical to the old FILTER clause — not an approximation,
-- and not frozen at refresh time.
--
-- `day` is NULL for advisories with a NULL published date. Those rows are kept
-- (they belong in `total`) and `day >= …` excludes them from the window, which
-- is exactly what `published_at >= NOW() - INTERVAL '14 days'` did.
--
-- Summing per-day COUNT(DISTINCT g.ghsa_id) across days is safe: published_at
-- is a single timestamp, so every advisory falls in exactly one bucket. The
-- DISTINCT is there to collapse the ghsa_packages fan-out within a bucket.
-- ═══════════════════════════════════════════════════════════════════════════

BEGIN;

DROP MATERIALIZED VIEW IF EXISTS ecosystem_advisory_days;

CREATE MATERIALIZED VIEW ecosystem_advisory_days AS
SELECT
  'GHSA'::text AS src,
  LOWER(p.ecosystem) AS canonical,
  date_trunc('day', g.published_at, 'UTC') AS day,
  COUNT(DISTINCT g.ghsa_id)::int AS n
FROM ghsa_advisories g
JOIN ghsa_packages gp ON gp.ghsa_id = g.ghsa_id
JOIN packages p ON p.id = gp.package_id
WHERE g.withdrawn_at IS NULL
GROUP BY LOWER(p.ecosystem), date_trunc('day', g.published_at, 'UTC')
UNION ALL
SELECT
  'OSV'::text AS src,
  o.ecosystem AS canonical,
  date_trunc('day', o.published, 'UTC') AS day,
  COUNT(*)::int AS n
FROM osv_advisories o
GROUP BY o.ecosystem, date_trunc('day', o.published, 'UTC');

-- Required by REFRESH MATERIALIZED VIEW CONCURRENTLY. `day` is nullable, and a
-- UNIQUE index treats NULLs as distinct — which would let duplicate NULL-day
-- rows through. There can only ever be one per (src, canonical) by
-- construction, but NULLS NOT DISTINCT makes the index enforce it.
CREATE UNIQUE INDEX ecosystem_advisory_days_key_idx
  ON ecosystem_advisory_days (src, canonical, day) NULLS NOT DISTINCT;

-- The route filters `day >= date_trunc('day', NOW() - INTERVAL '14 days')`.
CREATE INDEX ecosystem_advisory_days_day_idx
  ON ecosystem_advisory_days (day DESC NULLS LAST);

COMMIT;

ANALYZE ecosystem_advisory_days;
