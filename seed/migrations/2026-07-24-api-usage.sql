-- API usage counters — one row per normalized endpoint per day.
-- Written by edge middleware (see middleware.ts) via a non-blocking daily UPSERT.
-- Query examples:
--   SELECT endpoint, SUM(count) AS hits FROM api_usage
--     WHERE day >= CURRENT_DATE - 7 GROUP BY endpoint ORDER BY hits DESC;
--   SELECT day, SUM(count) FROM api_usage GROUP BY day ORDER BY day DESC LIMIT 30;
CREATE TABLE IF NOT EXISTS api_usage (
  endpoint   text        NOT NULL,
  day        date        NOT NULL DEFAULT CURRENT_DATE,
  count      bigint      NOT NULL DEFAULT 0,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (endpoint, day)
);

-- Fast "last N days" scans.
CREATE INDEX IF NOT EXISTS idx_api_usage_day ON api_usage (day);
