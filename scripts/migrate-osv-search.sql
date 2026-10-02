-- scripts/migrate-osv-search.sql
--
-- Makes `/api/v1/advisories?q=` indexable on osv_advisories.
--
-- ⚠ REVISION 2. Revision 1 OF THIS FILE WOULD HAVE FAILED. Do not run an
--   older copy. What was wrong, confirmed against production:
--     1. `array_to_string(anyarray, text)` is STABLE, not IMMUTABLE
--        (pg_proc.provolatile = 's'). An index expression must be IMMUTABLE,
--        so the aliases statement errored. `concat_ws` is STABLE too, so the
--        obvious rewrite has the same trap. Hence the wrapper below.
--     2. With that statement failing, the other two bought NOTHING: one
--        unindexable arm forces a sequential scan of the whole OR, so the
--        money would have been spent for no speedup.
--     3. `CREATE INDEX ... IF NOT EXISTS` SKIPS a leftover INVALID index and
--        still prints `CREATE INDEX`. It reports success and leaves the arm
--        unindexed. `IF NOT EXISTS` is gone from every statement here.
--     4. The cleanup used a plain `DROP INDEX`, which takes ACCESS EXCLUSIVE
--        on a 774 MB table that has 58s+ readers and a 64s matview refresh.
--        Now CONCURRENTLY.
--
-- ═══════════════════════════════════════════════════════════════════════════
-- TWO DECISIONS TO MAKE BEFORE RUNNING THIS
--
-- (A) THERE IS A BETTER-SHAPED ALTERNATIVE. Putting a single `search_text`
--     column on the osv_advisory_rank matview (osv_id, summary and aliases
--     joined by an unprintable separator) and one GIN on that is better on
--     most axes, because GIN maintenance then sees only real changes:
--
--                            this file          matview search_text
--       new index bytes      185 MB             150-173 MB + ~60 MB heap
--       WAL per delta        +70.7 MB           +20.7 MB (on refresh, not ingest)
--       ingest wall time     +44%               unchanged
--       IMMUTABLE wrapper    required           not needed (stored column)
--       EXISTS recheck       required           not needed
--       buffers, ?q=kernel   43.5k              11.2k
--
--     Its cost: a matview cannot ADD COLUMN, so it is DROP + CREATE. Doing
--     that in one transaction (as scripts/migrate-advisory-rank.sql does)
--     holds ACCESS EXCLUSIVE for the whole build, so the OSV branch STALLS for
--     roughly a minute and then fails at the API pool's 30s client ceiling.
--
--     Note the transaction is what makes this safe rather than dangerous: a
--     reader blocks on the lock and never observes a missing relation, so the
--     route's missing-relation fallback cannot fire and cannot cache a
--     GHSA-only answer. That only becomes a risk if the DROP is ever committed
--     without the CREATE. Build aside and rename if you want zero stall.
--
-- (B) THE osv_id ARM COSTS 141 MB — 76% of the new bytes and 52% of the extra
--     WAL — and earns it only for ID-shaped needles. The existing btree
--     `idx_osv_id` already serves exact and prefix matches; the trigram index
--     buys SUBSTRING matching, which is the current documented behaviour.
--     Dropping that arm means `?q=` no longer finds `ebian` inside
--     `DEBIAN-CVE-…`. Keeping substring semantics is the reason to pay.
--     Measured alternatives, same semantics: GiST trigram 216 MB (worse),
--     one combined GIN 178 MB (no saving), btree text_pattern_ops 69 MB
--     (prefix only — a semantics change).
-- ═══════════════════════════════════════════════════════════════════════════
--
-- WHY ALL THREE ARMS OR NONE
--
-- The route's predicate is a three-way OR. Postgres can combine OR'd arms
-- into a BitmapOr only if EVERY arm has an index; one unindexable arm forces a
-- sequential scan of the whole predicate. Measured per arm before indexing,
-- against production: osv_id ILIKE 5.2s, summary ILIKE 5.1s,
-- unnest(aliases) ILIKE 14.9s, all three OR'd 12.9s.
--
-- SIZES, measured on a loaded copy (NOT the 400-500 MB revision 1 guessed):
--   idx_osv_id_trgm 141 MB · idx_osv_summary_trgm 39 MB · aliases 5.4 MB
--   = 185 MB. Net change on disk is about +41 MB once the dead 144 MB
--   invalid index is dropped. Table today: 774 MB heap, 858 MB indexes.
--
-- Only 267,343 of 1,972,497 rows have a summary (14 MB of text), and `aliases`
-- is empty on 1,945,471 rows (98.6%) — the aliases index is small because its
-- population is small.
--
-- KNOWN LIMIT, NOT FIXED HERE: the keys CTE in the route carries a LIMIT, and
-- for broad terms (`kernel`, `linux`, `CVE-2024`) the planner still prefers an
-- ordered scan of osv_advisory_rank_order_idx with per-row probes over the
-- bitmap path — so those stay slow and the route's 25s budget cancels them.
-- Wrapping the candidate set in a MATERIALIZED CTE forces the bitmap path
-- (measured: kernel 4,536ms -> 570ms, 348.8k -> 43.5k buffers). That is a
-- route change, tracked separately; the indexes are a prerequisite either way.
-- Also note `q >= 3 characters` is NOT sufficient for selectivity: `c++`
-- extracts no usable trigram and scans essentially the whole index.
--
-- ═══════════════════════════════════════════════════════════════════════════
-- RUN ORDER. Direct endpoint (DATABASE_URL_UNPOOLED), autocommit, NO
-- BEGIN and NO --single-transaction: CONCURRENTLY cannot run in a transaction
-- block, and the pooler neither gives a stable session for the build nor
-- accepts `options=-c ...`.
--
-- THE ROUTE IS NOT YET SWITCHED OVER, DELIBERATELY. As shipped it uses
-- `array_to_string(o.aliases, ' ')`, which works but cannot use the index
-- below, because Postgres matches an expression index textually and will not
-- inline an IMMUTABLE wrapper whose body is STABLE. So applying this file
-- alone leaves the aliases arm unindexed, one unindexable arm forces a seq
-- scan of the whole OR, and you will have paid 185 MB for nothing.
--
-- Step 9 below is therefore part of the migration, not an afterthought. The
-- change is a single constant: ALIASES_TEXT_SQL at the top of
-- app/api/v1/advisories/route.ts. Flipping it BEFORE this file runs makes
-- every `?q=` request a 500 — a missing function raises undefined_function,
-- which does not match the route's missing-relation fallback.
-- ═══════════════════════════════════════════════════════════════════════════

-- 1. Preflight. Expect zero rows from both.
SELECT c.relname, i.indisvalid
FROM pg_class c
JOIN pg_index i ON i.indexrelid = c.oid
JOIN pg_class t ON t.oid = i.indrelid
WHERE t.relname = 'osv_advisories' AND NOT i.indisvalid;

SELECT pid, state, left(query, 60) AS query
FROM pg_stat_activity
WHERE query ILIKE '%osv_advisories%' AND pid <> pg_backend_pid();

-- 2. Remove the 144 MB INVALID idx_osv_id_trgm left by a cancelled build.
--    CONCURRENTLY: a plain DROP takes ACCESS EXCLUSIVE and stalls every reader
--    behind the longest running one. Because the index is indisready = false,
--    writes already ignore it, so there is no hurry — it is wasted disk only.
DROP INDEX CONCURRENTLY IF EXISTS idx_osv_id_trgm;

-- 3. Confirm it is gone before creating anything.
SELECT to_regclass('idx_osv_id_trgm') AS should_be_null;

-- 4. The IMMUTABLE wrapper. `array_to_string` is STABLE because in general it
--    depends on type output functions; for text[] joined by a constant it is
--    genuinely immutable, which is what this asserts. search_path is pinned so
--    the body cannot be captured by a shadowing object.
CREATE OR REPLACE FUNCTION osv_aliases_text(text[])
  RETURNS text
  LANGUAGE sql
  IMMUTABLE
  PARALLEL SAFE
  RETURNS NULL ON NULL INPUT
  SET search_path = pg_catalog
AS $$ SELECT array_to_string($1, ' ') $$;

-- 5. The indexes. Cheapest first, so a failure costs least. No IF NOT EXISTS:
--    a leftover must error loudly rather than silently skip. Check indisvalid
--    after each before starting the next.
CREATE INDEX CONCURRENTLY idx_osv_summary_trgm
  ON osv_advisories USING gin (summary gin_trgm_ops);

CREATE INDEX CONCURRENTLY idx_osv_aliases_text_trgm
  ON osv_advisories USING gin (osv_aliases_text(aliases) gin_trgm_ops);

CREATE INDEX CONCURRENTLY idx_osv_id_trgm
  ON osv_advisories USING gin (osv_id gin_trgm_ops);

-- 6. Statistics for the expression index. Without this the planner still picks
--    BitmapOr but estimates badly (1,852 rows against an actual 231).
ANALYZE osv_advisories;

-- 7. Verify all three are valid, and their sizes.
SELECT c.relname, i.indisvalid, pg_size_pretty(pg_relation_size(c.oid)) AS size
FROM pg_class c
JOIN pg_index i ON i.indexrelid = c.oid
JOIN pg_class t ON t.oid = i.indrelid
WHERE t.relname = 'osv_advisories' AND c.relname LIKE '%trgm'
ORDER BY c.relname;

-- 8. Confirm the plan. A selective term should show BitmapOr over all three.
--    EXPLAIN (ANALYZE, BUFFERS) SELECT 1 FROM osv_advisories o
--    WHERE o.osv_id ILIKE '%log4j%' OR o.summary ILIKE '%log4j%'
--       OR (osv_aliases_text(o.aliases) ILIKE '%log4j%'
--           AND EXISTS (SELECT 1 FROM unnest(o.aliases) a WHERE a ILIKE '%log4j%'));
--
-- 8b. OPTIONAL, AND ONLY AFTER THE INDEXES EXIST: fence the keys CTE.
--
--     Even with all three arms indexed, the LIMIT in the route's keys CTE makes
--     the planner prefer an ordered walk of osv_advisory_rank_order_idx with
--     per-row probes over the bitmap path, for BROAD terms (`kernel`, `linux`,
--     `CVE-2024`). Wrapping the candidate set in a MATERIALIZED CTE forces the
--     bitmap path: measured kernel 4,536ms -> 570ms (348.8k -> 43.5k buffers),
--     `a-1` 4,372ms -> 765ms (2.61M -> 93.9k).
--
--     DELIBERATELY NOT SHIPPED YET, because the trade inverts without the
--     indexes. Today the ordered walk can stop as soon as it has limit+offset
--     matches, which is FAST for a common term and slow only for a rare one. A
--     MATERIALIZED fence always materialises every match, so adding it now
--     would make common-term searches worse to make rare ones better. It is a
--     win only once the bitmap path is available to force.
--
-- 9. ONLY NOW switch the route over, and deploy:
--
--      app/api/v1/advisories/route.ts
--      - const ALIASES_TEXT_SQL = "array_to_string(o.aliases, ' ')";
--      + const ALIASES_TEXT_SQL = 'osv_aliases_text(o.aliases)';
--
--    Then re-run the EXPLAIN in step 8 and confirm a BitmapOr over all three
--    arms. Without this step the two preceding indexes are dead weight.

-- DO NOT set fastupdate=off (WAL per delta 140 MB -> 267 MB) and do not raise
-- gin_pending_list_limit (every query scans the pending list; 64 MB costs
-- +13-32ms hot per query). The real lever on ingest cost is not rewriting
-- unchanged rows in scripts/sync-osv.mjs, which is a separate change.
