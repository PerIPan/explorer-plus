-- Threat Profile telemetry. Anonymous by construction: date not timestamp,
-- no raw IP, no UA, no referrer, no cookie, no session.
CREATE TABLE IF NOT EXISTS profile_submissions (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  day            date   NOT NULL DEFAULT CURRENT_DATE,
  variant        text   NOT NULL CHECK (variant IN ('v1-4q','v1-6q-ot')),
  action         text   NOT NULL CHECK (action IN ('apply','dismiss','auto_close')),
  sectors        text[] NOT NULL DEFAULT '{}',
  platforms      text[] NOT NULL DEFAULT '{}',
  roles          text[] NOT NULL DEFAULT '{}',
  frameworks     text[] NOT NULL DEFAULT '{}',
  assets         text[] NOT NULL DEFAULT '{}',
  purdue_levels  text[] NOT NULL DEFAULT '{}',
  visitor_day    text,
  ip_day         text,
  created_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (day, visitor_day, action, variant)
);

-- Every sibling telemetry table (api_usage, mcp_usage, a2a_requests) has one;
-- the dismissal-rate query is day-scoped.
CREATE INDEX IF NOT EXISTS idx_profile_submissions_day
  ON profile_submissions (day, action);

-- Fix round 1 (Critical): visitor_day folds in User-Agent, which is fully
-- attacker-controlled, and was wrongly used to gate the per-visitor rate cap
-- -- trivially bypassed by varying User-Agent per request from one IP (proved
-- live: 15 requests, 1 IP, 15 distinct UAs -> 15 distinct visitor_day values,
-- cap never fired). ip_day is IP-only (sha256(hmac(PROFILE_IP_SALT, utc_date)
-- || ip), no UA) and is what the rate limiter must query against. visitor_day
-- is kept, UA-inclusive, for storage grouping and the UNIQUE dedup only -- it
-- must never again be load-bearing for abuse resistance. Additive and safe to
-- re-run against the already-applied table (ADD COLUMN IF NOT EXISTS).
ALTER TABLE profile_submissions ADD COLUMN IF NOT EXISTS ip_day text;
CREATE INDEX IF NOT EXISTS idx_profile_submissions_ip_day
  ON profile_submissions (day, ip_day);
