-- Threat Profile telemetry. Anonymous by construction: date not timestamp,
-- no raw IP, no UA, no referrer, no cookie, no session.
--
-- Apply with:
--   psql "$DATABASE_URL" -f scripts/migrate-profile-submissions.sql
CREATE TABLE IF NOT EXISTS profile_submissions (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  -- HARD UTC, never CURRENT_DATE. Three things must agree on what "today"
  -- is: this default, the per-IP cap query (app/api/v1/profile/submit/
  -- route.ts `underDailyCap`) and the `ip_day` HMAC day key (same file,
  -- `computeVisitorHashes`, which keys on `new Date().toISOString()`).
  -- The latter two are hard UTC. `CURRENT_DATE` is SESSION-TIMEZONE, so it
  -- only agreed with them because Neon's TimeZone happens to be GMT today.
  -- Move the session TZ off UTC (a role setting, PGTZ, a pooler default) and
  -- between local midnight and UTC midnight an INSERT stamps day = D+1 while
  -- the cap counts day = D: the per-IP cap silently resets, mid-day, and
  -- abuse walks through it invisibly. All three date sources are now UTC by
  -- construction rather than by coincidence.
  day            date   NOT NULL DEFAULT (now() AT TIME ZONE 'utc')::date,
  variant        text   NOT NULL CHECK (variant IN ('v1-4q','v1-6q-ot')),
  action         text   NOT NULL CHECK (action IN ('apply','dismiss','auto_close')),
  sectors        text[] NOT NULL DEFAULT '{}',
  platforms      text[] NOT NULL DEFAULT '{}',
  roles          text[] NOT NULL DEFAULT '{}',
  frameworks     text[] NOT NULL DEFAULT '{}',
  assets         text[] NOT NULL DEFAULT '{}',
  purdue_levels  text[] NOT NULL DEFAULT '{}',
  -- NOT NULL is load-bearing, not hygiene: the UNIQUE below is NULLS
  -- DISTINCT (the Postgres default), so a single NULL visitor_day row would
  -- not conflict with anything -- including another NULL row -- and the
  -- apply/dismiss dedup would be defeated entirely for it. The route always
  -- computes a digest (it has no code path that emits NULL), so NOT NULL
  -- costs nothing and makes that unrepresentable. Chosen over
  -- `UNIQUE NULLS NOT DISTINCT` because it removes the NULL case rather than
  -- defining a comparison rule for a value that should never exist.
  visitor_day    text   NOT NULL,
  ip_day         text,
  created_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (day, visitor_day, action, variant)
);

-- Every sibling telemetry table (api_usage, mcp_usage, a2a_requests) has one;
-- the dismissal-rate query is day-scoped. Deliberately NOT extended with
-- visitor_day: `idx_profile_submissions_ip_day` below is the index the
-- per-IP cap needs, and this one exists for sibling-table consistency and
-- the day-scoped rollup, which is a small scan either way.
CREATE INDEX IF NOT EXISTS idx_profile_submissions_day
  ON profile_submissions (day, action);

-- The metric this feature is judged on. COUNT DISTINCT VISITOR_DAY, never
-- count(*): one visitor-day may legitimately produce BOTH an apply and a
-- dismiss (peek dismissed, panel reopened from the diamond later and
-- applied), and both rows survive the UNIQUE because `action` is part of it.
-- Counting rows therefore double-counts that visitor on both sides of the
-- ratio and moves it; counting visitors answers the question actually being
-- asked ("what share of the people who saw it took it").
--
--   SELECT day,
--          count(DISTINCT visitor_day) FILTER (WHERE action = 'apply')      AS applied,
--          count(DISTINCT visitor_day) FILTER (WHERE action = 'dismiss')    AS dismissed,
--          count(DISTINCT visitor_day) FILTER (WHERE action = 'auto_close') AS auto_closed,
--          count(DISTINCT visitor_day)                                      AS visitors
--   FROM profile_submissions
--   WHERE day >= (now() AT TIME ZONE 'utc')::date - 30
--   GROUP BY day
--   ORDER BY day DESC;

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

-- Fix round 2. Both of these are re-runnable and are the ALTER form of the
-- column definitions above, for the already-applied production table.
--
-- P1: `day` was `DEFAULT CURRENT_DATE` -- session-timezone -- while the cap
-- query and the ip_day HMAC are both hard UTC. See the column comment.
ALTER TABLE profile_submissions
  ALTER COLUMN day SET DEFAULT (now() AT TIME ZONE 'utc')::date;

-- P8: visitor_day was nullable under a NULLS DISTINCT UNIQUE, which any NULL
-- row would defeat. Verified zero NULLs in production before setting this.
ALTER TABLE profile_submissions
  ALTER COLUMN visitor_day SET NOT NULL;
