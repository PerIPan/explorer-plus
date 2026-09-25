-- Threat Profile ranking matviews. Apply with:
--   psql "$DATABASE_URL" -f scripts/migrate-profile-matviews.sql
-- Both are refreshed CONCURRENTLY by app/api/cron/refresh-matviews/route.ts,
-- which requires the unique indexes below.

-- Lift = how much more a sector's groups use a technique than all groups do.
-- Both numerator and denominator count only groups with >=1 group_techniques
-- row, live only. The alternative (all attributed groups) shifts the displayed
-- multiplier by up to ~7% but provably cannot re-rank within a sector.
DROP MATERIALIZED VIEW IF EXISTS sector_technique_lift;
CREATE MATERIALIZED VIEW sector_technique_lift AS
WITH live_groups AS (
  SELECT DISTINCT gt.group_id
  FROM group_techniques gt
  JOIN threat_groups tg ON tg.id = gt.group_id
  WHERE tg.is_revoked = false AND tg.is_deprecated = false
),
all_n AS (SELECT count(*)::numeric AS n FROM live_groups),
glob AS (
  SELECT gt.technique_id, count(DISTINCT gt.group_id)::numeric AS c
  FROM group_techniques gt
  JOIN live_groups lg ON lg.group_id = gt.group_id
  GROUP BY 1
),
sector_n AS (
  SELECT s.slug, count(DISTINCT gs.group_id)::numeric AS n
  FROM group_sectors gs
  JOIN sectors s ON s.id = gs.sector_id
  JOIN live_groups lg ON lg.group_id = gs.group_id
  GROUP BY 1
),
sect AS (
  SELECT s.slug, gt.technique_id, count(DISTINCT gt.group_id)::numeric AS c
  FROM group_sectors gs
  JOIN sectors s ON s.id = gs.sector_id
  JOIN live_groups lg ON lg.group_id = gs.group_id
  JOIN group_techniques gt ON gt.group_id = gs.group_id
  GROUP BY 1, 2
)
SELECT sect.slug AS sector_slug,
       sect.technique_id,
       sect.c::int AS group_count,
       round((sect.c / sn.n) / (g.c / (SELECT n FROM all_n)), 3) AS lift
FROM sect
JOIN glob g ON g.technique_id = sect.technique_id
JOIN sector_n sn ON sn.slug = sect.slug;

CREATE UNIQUE INDEX sector_technique_lift_pk
  ON sector_technique_lift (sector_slug, technique_id);
