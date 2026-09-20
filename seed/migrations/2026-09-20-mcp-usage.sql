-- MCP tool usage counters — one row per (tool, day, client).
--
-- Why a separate table from api_usage:
--   * MCP identifies work by TOOL NAME (search_cves), not URL endpoint. The two
--     namespaces don't overlap and shouldn't share a column.
--   * MCP tool calls reach data through callInternalApi(), which fetches the
--     PUBLIC /api/v1 URL — so on a CDN miss they ALSO increment api_usage under
--     the underlying endpoint. Without this table, agent traffic is invisible as
--     agent traffic and silently inflates the browse-endpoint numbers.
--
-- Why aggregate rows instead of per-request rows (cf. a2a_requests):
--   The MCP endpoint is anonymous AND unrate-limited, so there is no quota to
--   enforce and therefore no reason to retain any client identity — no IP, not
--   even a salted hash. Counters answer the questions actually worth asking
--   (which tools get used, how fast, how often they fail) at a fraction of the
--   write cost and with no PII.
--
-- CARDINALITY IS THE HAZARD HERE. `client` derives from the MCP client's
-- self-reported clientInfo.name, which is attacker-controlled free text on an
-- unauthenticated, unlimited endpoint. Left raw, one caller could mint millions
-- of rows. The writer therefore normalizes it against a known-client allowlist
-- and collapses everything else to 'other' — the same bounded-cardinality trick
-- middleware.ts uses when it folds unknown path segments into ':id'. The CHECK
-- below is defence in depth, not the primary control.
--
-- Query examples:
--   -- most-used tools this week
--   SELECT tool, SUM(count) AS calls, SUM(error_count) AS errors,
--          (SUM(total_latency_ms) / NULLIF(SUM(count), 0)) AS avg_ms
--     FROM mcp_usage WHERE day >= CURRENT_DATE - 7
--    GROUP BY tool ORDER BY calls DESC;
--   -- which agents are calling
--   SELECT client, SUM(count) AS calls FROM mcp_usage
--    WHERE day >= CURRENT_DATE - 30 GROUP BY client ORDER BY calls DESC;
--   -- tools that fail most
--   SELECT tool, SUM(error_count)::float / NULLIF(SUM(count), 0) AS error_rate
--     FROM mcp_usage GROUP BY tool HAVING SUM(count) > 20 ORDER BY error_rate DESC;

\set ON_ERROR_STOP on

BEGIN;

CREATE TABLE IF NOT EXISTS mcp_usage (
  tool             text        NOT NULL,
  day              date        NOT NULL DEFAULT (now() AT TIME ZONE 'utc')::date,
  -- Normalized in the writer to a bounded allowlist; 'other' is the catch-all.
  client           text        NOT NULL DEFAULT 'unknown',
  count            bigint      NOT NULL DEFAULT 0,
  error_count      bigint      NOT NULL DEFAULT 0,
  -- Summed, not averaged, so the mean survives concurrent upserts:
  -- avg = total_latency_ms / count.
  total_latency_ms bigint      NOT NULL DEFAULT 0,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tool, day, client),
  CONSTRAINT mcp_usage_tool_len   CHECK (char_length(tool) BETWEEN 1 AND 64),
  CONSTRAINT mcp_usage_client_len CHECK (char_length(client) BETWEEN 1 AND 32),
  CONSTRAINT mcp_usage_counts_sane CHECK (error_count <= count)
);

-- Fast "last N days" scans (the PK leads with tool, so a day-only index is needed).
CREATE INDEX IF NOT EXISTS idx_mcp_usage_day ON mcp_usage (day);

-- Hot-row hygiene: a popular tool updates the same physical tuple all day.
-- fillfactor leaves page space so those updates stay HOT (no index bloat); the
-- lower autovacuum thresholds react to per-row churn rather than table growth.
-- Mirrors api_usage exactly.
ALTER TABLE mcp_usage SET (
  fillfactor = 90,
  autovacuum_vacuum_scale_factor = 0.05,
  autovacuum_analyze_scale_factor = 0.05
);

COMMIT;
