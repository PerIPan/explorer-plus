import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from './_lib/db.js';
import { withHandler } from './_lib/middleware.js';

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const [
    statsResult,
    topGroupsResult,
    tacticDistResult,
    sectorResult,
    versionResult,
  ] = await Promise.all([
    // Entity counts
    query<{
      techniqueCount: string; groupCount: string; softwareCount: string;
      mitigationCount: string; campaignCount: string; dataSourceCount: string;
    }>(
      `SELECT
         (SELECT count(*) FROM techniques    WHERE is_revoked = false AND is_deprecated = false) AS "techniqueCount",
         (SELECT count(*) FROM threat_groups WHERE is_revoked = false AND is_deprecated = false) AS "groupCount",
         (SELECT count(*) FROM attack_software WHERE is_revoked = false AND is_deprecated = false) AS "softwareCount",
         (SELECT count(*) FROM mitigations   WHERE is_revoked = false AND is_deprecated = false) AS "mitigationCount",
         (SELECT count(*) FROM campaigns     WHERE is_revoked = false AND is_deprecated = false) AS "campaignCount",
         (SELECT count(*) FROM data_sources  WHERE is_revoked = false AND is_deprecated = false) AS "dataSourceCount"`,
    ),
    // Top 10 groups by technique count
    query<{ attackId: string; name: string; techniqueCount: string }>(
      `SELECT
         tg.attack_id    AS "attackId",
         tg.name,
         COUNT(gt.technique_id) AS "techniqueCount"
       FROM threat_groups tg
       JOIN group_techniques gt ON gt.group_id = tg.id
       WHERE tg.is_revoked = false AND tg.is_deprecated = false
       GROUP BY tg.id, tg.attack_id, tg.name
       ORDER BY "techniqueCount" DESC
       LIMIT 10`,
    ),
    // Tactic distribution
    query<{ tacticName: string; count: string }>(
      `SELECT
         ta.name AS "tacticName",
         COUNT(DISTINCT tt.technique_id) AS count
       FROM tactics ta
       JOIN technique_tactics tt ON tt.tactic_id = ta.id
       JOIN techniques t ON t.id = tt.technique_id
         AND t.is_revoked = false AND t.is_deprecated = false
       GROUP BY ta.id, ta.name, ta.sort_order
       ORDER BY ta.sort_order ASC NULLS LAST`,
    ),
    // Sector breakdown
    query<{ sectorName: string; groupCount: string }>(
      `SELECT
         s.name AS "sectorName",
         COUNT(DISTINCT gs.group_id) AS "groupCount"
       FROM sectors s
       JOIN group_sectors gs ON gs.sector_id = s.id
       JOIN threat_groups tg ON tg.id = gs.group_id
         AND tg.is_revoked = false AND tg.is_deprecated = false
       GROUP BY s.id, s.name
       ORDER BY "groupCount" DESC`,
    ),
    // ATT&CK version
    query<{ attackVersion: string; domain: string; seededAt: string }>(
      `SELECT attack_version AS "attackVersion", domain, seeded_at AS "seededAt"
       FROM seed_metadata ORDER BY id DESC LIMIT 1`,
    ),
  ]);

  const raw = statsResult.rows[0];
  res.status(200).json({
    stats: {
      techniqueCount: parseInt(raw.techniqueCount, 10),
      groupCount: parseInt(raw.groupCount, 10),
      softwareCount: parseInt(raw.softwareCount, 10),
      mitigationCount: parseInt(raw.mitigationCount, 10),
      campaignCount: parseInt(raw.campaignCount, 10),
      dataSourceCount: parseInt(raw.dataSourceCount, 10),
    },
    topGroups: topGroupsResult.rows.map((r) => ({
      attackId: r.attackId,
      name: r.name,
      techniqueCount: parseInt(r.techniqueCount, 10),
    })),
    tacticDistribution: tacticDistResult.rows.map((r) => ({
      tacticName: r.tacticName,
      count: parseInt(r.count, 10),
    })),
    sectorBreakdown: sectorResult.rows.map((r) => ({
      sectorName: r.sectorName,
      groupCount: parseInt(r.groupCount, 10),
    })),
    attackVersion: versionResult.rows[0] ?? null,
  });
}

export default withHandler(handler, { cacheTtl: 1800 });
