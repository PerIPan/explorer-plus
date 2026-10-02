-- scripts/migrate-osv-search.sql
--
-- Makes `/api/v1/advisories?q=` indexable.
--
-- THE PROBLEM
--
-- `?q=` is the only filter that forces the OSV branch onto the base table
-- (`osvNeedsBase = true` in app/api/v1/advisories/route.ts), and the predicate
-- it adds was unindexable in all three arms:
--
--   (o.osv_id ILIKE $1 OR o.summary ILIKE $1
--    OR EXISTS (SELECT 1 FROM unnest(o.aliases) a WHERE a ILIKE $1))
--
-- idx_osv_id is a plain btree, which cannot serve `%term%`. idx_osv_aliases_gin
-- is a default array-ops GIN, which cannot serve `unnest(...) ILIKE` at all.
-- osv_advisories is 1,972,497 rows / 1579 MB, so each arm was a full scan.
--
-- Measured 2026-10-02 against production, each arm alone:
--   osv_id ILIKE 5.2s · summary ILIKE 5.1s · unnest(aliases) ILIKE 14.9s
--   all three OR'd 12.9s
--
-- The route evaluates that predicate TWICE per request — once in the COUNT
-- branch and once in the keys CTE — which is why an end-to-end request measured
-- 27s, 31s and >70s on different attempts rather than 13s.
--
-- WHY ALL THREE ARMS NEED AN INDEX
--
-- Postgres can combine OR'd arms into a BitmapOr, but only if EVERY arm is
-- indexable. One unindexable arm forces a sequential scan of the whole OR, so
-- indexing two of the three would have bought nothing.
--
-- WHY A TRIGRAM INDEX AND NOT FULL TEXT
--
-- tsvector/tsquery would be the better tool for prose, but it matches lexemes,
-- not substrings: `?q=log4` would stop finding `log4j`. That is a visible
-- behaviour change to a live search box, so it is not made here. pg_trgm
-- preserves `ILIKE '%term%'` semantics exactly. It is already installed
-- (idx_packages_name_trgm uses it).
--
-- Note `gin_trgm_ops` only helps patterns with a 3-character extractable
-- trigram; the route already requires q >= 3 characters.
--
-- THE ALIASES ARM
--
-- An element-wise `unnest(...) ILIKE` cannot be indexed directly, so the index
-- is on `array_to_string(aliases, ' ')`. That expression is a strict SUPERSET
-- of the element-wise test: if any element contains the needle, so does the
-- joined string. The route therefore uses it as an indexable pre-filter and
-- keeps the exact EXISTS as a recheck, so results are unchanged — the join
-- could otherwise match a needle straddling two elements.
--
-- ═══════════════════════════════════════════════════════════════════════════
-- RUN THIS ON THE DIRECT ENDPOINT, NOT THE POOLER
--
-- Use DATABASE_URL_UNPOOLED (no `-pooler` in the host). Two reasons, both
-- learned the hard way on 2026-10-02:
--
-- 1. CONCURRENTLY needs a stable session for the whole build. PgBouncer's
--    transaction pooling does not guarantee one.
-- 2. A bare `SET statement_timeout` from ANY client persists on the pooled
--    server connection and is inherited by whoever gets that connection next.
--    A 25s value set by an unrelated script seconds earlier killed the
--    idx_osv_id_trgm build at exactly 25s and left a 144 MB INVALID index
--    behind. This is also the most likely explanation for the intermittent
--    ~15s cancels that pushed osv_advisory_rank off its Vercel cron slot
--    (see scripts/refresh-matview.mjs) — circumstantial, not proven.
--
-- CLEAN UP FIRST. The interrupted build left this behind; it is 144 MB of dead
-- disk and `IF NOT EXISTS` will NOT replace it, so the create below would
-- silently skip and leave the arm unindexed:

DROP INDEX IF EXISTS idx_osv_id_trgm;

-- Verify nothing invalid remains before and after:
--   SELECT c.relname, i.indisvalid FROM pg_class c
--   JOIN pg_index i ON i.indexrelid = c.oid JOIN pg_class t ON t.oid = i.indrelid
--   WHERE t.relname = 'osv_advisories' AND NOT i.indisvalid;
--
-- CONCURRENTLY: each statement must run outside a transaction block, so this
-- file deliberately has no BEGIN/COMMIT. If one is interrupted it leaves an
-- INVALID index; drop it and re-run that statement.
--
-- COST: measured 144 MB for a PARTIAL idx_osv_id_trgm build, so budget roughly
-- 400-500 MB of new index across the three on a 1579 MB table. If that is not
-- worth it, the summary index alone is the cheap majority of the value (only
-- 267,343 of 1,972,497 rows have a summary — 14 MB of text) but will NOT fix
-- the 14.9s aliases arm, and leaving any one arm unindexed forces a seq scan
-- of the whole OR.
-- ═══════════════════════════════════════════════════════════════════════════

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_osv_summary_trgm
  ON osv_advisories USING gin (summary gin_trgm_ops);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_osv_id_trgm
  ON osv_advisories USING gin (osv_id gin_trgm_ops);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_osv_aliases_text_trgm
  ON osv_advisories USING gin (array_to_string(aliases, ' ') gin_trgm_ops);
