-- API usage counters — one row per normalized endpoint per (UTC) day.
-- Written at the origin in jsonResponse() (app/api/lib/handler.ts) via Next
-- after(), so only cache MISSES are counted (CDN hits never reach origin).
-- middleware.ts just tags the request with the normalized x-usage-endpoint.
-- Query examples:
--   SELECT endpoint, SUM(count) AS hits FROM api_usage
--     WHERE day >= CURRENT_DATE - 7 GROUP BY endpoint ORDER BY hits DESC;
--   SELECT day, SUM(count) FROM api_usage GROUP BY day ORDER BY day DESC LIMIT 30;
CREATE TABLE IF NOT EXISTS api_usage (
  endpoint   text        NOT NULL,
  day        date        NOT NULL DEFAULT (now() AT TIME ZONE 'utc')::date,
  count      bigint      NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (endpoint, day)
);

-- created_at added idempotently for pre-existing installs (repo convention).
ALTER TABLE api_usage ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now();

-- Fast "last N days" scans (PK leads with endpoint, so a day-only index is needed).
CREATE INDEX IF NOT EXISTS idx_api_usage_day ON api_usage (day);

-- Hot-row hygiene: a popular endpoint updates the same physical tuple all day.
-- fillfactor leaves page space so those updates stay HOT (no index bloat); the
-- lower autovacuum thresholds react to per-row churn rather than table growth.
ALTER TABLE api_usage SET (
  fillfactor = 90,
  autovacuum_vacuum_scale_factor = 0.05,
  autovacuum_analyze_scale_factor = 0.05
);
