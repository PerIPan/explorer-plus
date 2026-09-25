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
  created_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (day, visitor_day, action, variant)
);

-- Every sibling telemetry table (api_usage, mcp_usage, a2a_requests) has one;
-- the dismissal-rate query is day-scoped.
CREATE INDEX IF NOT EXISTS idx_profile_submissions_day
  ON profile_submissions (day, action);
