import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from './lib/db.js';
import { withHandler } from './lib/middleware.js';
import { z } from 'zod';

const querySchema = z.object({
  sector: z.string().max(50).optional(),
});

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const parsed = querySchema.safeParse(req.query);
  const sector = parsed.success ? parsed.data.sector ?? null : null;

  const [
    statsResult,
    topGroupsResult,
    tacticDistResult,
    sectorResult,
    versionResult,
  ] = await Promise.all([
    // Entity counts — sector-filtered when active
    sector
      ? query<{
          techniqueCount: string; groupCount: string; softwareCount: string;
          mitigationCount: string; campaignCount: string; dataSourceCount: string;
        }>(
          `SELECT
             (SELECT count(DISTINCT gt.technique_id) FROM group_techniques gt
              JOIN group_sectors gs ON gs.group_id = gt.group_id
              JOIN sectors s ON s.id = gs.sector_id WHERE s.slug = $1) AS "techniqueCount",
             (SELECT count(DISTINCT gs.group_id) FROM group_sectors gs
              JOIN sectors s ON s.id = gs.sector_id
              JOIN threat_groups tg ON tg.id = gs.group_id AND tg.is_revoked = false AND tg.is_deprecated = false
              WHERE s.slug = $1) AS "groupCount",
             (SELECT count(DISTINCT gsw.software_id) FROM group_software gsw
              JOIN attack_software sw ON sw.id = gsw.software_id AND sw.is_revoked = false AND sw.is_deprecated = false
              JOIN group_sectors gs ON gs.group_id = gsw.group_id
              JOIN sectors s ON s.id = gs.sector_id WHERE s.slug = $1) AS "softwareCount",
             (SELECT count(*) FROM mitigations WHERE is_revoked = false AND is_deprecated = false) AS "mitigationCount",
             (SELECT count(DISTINCT gc.campaign_id) FROM group_campaigns gc
              JOIN group_sectors gs ON gs.group_id = gc.group_id
              JOIN sectors s ON s.id = gs.sector_id WHERE s.slug = $1) AS "campaignCount",
             (SELECT count(*) FROM data_sources WHERE is_revoked = false) AS "dataSourceCount"`,
          [sector],
        )
      : query<{
          techniqueCount: string; groupCount: string; softwareCount: string;
          mitigationCount: string; campaignCount: string; dataSourceCount: string;
        }>(
          `SELECT
             (SELECT count(*) FROM techniques    WHERE is_revoked = false AND is_deprecated = false) AS "techniqueCount",
             (SELECT count(*) FROM threat_groups WHERE is_revoked = false AND is_deprecated = false) AS "groupCount",
             (SELECT count(*) FROM attack_software WHERE is_revoked = false AND is_deprecated = false) AS "softwareCount",
             (SELECT count(*) FROM mitigations   WHERE is_revoked = false AND is_deprecated = false) AS "mitigationCount",
             (SELECT count(*) FROM campaigns     WHERE is_revoked = false AND is_deprecated = false) AS "campaignCount",
             (SELECT count(*) FROM data_sources  WHERE is_revoked = false) AS "dataSourceCount"`,
        ),

    // Top 10 groups by technique count
    sector
      ? query<{ attackId: string; name: string; techniqueCount: string }>(
          `SELECT tg.attack_id AS "attackId", tg.name, COUNT(gt.technique_id) AS "techniqueCount"
           FROM threat_groups tg
           JOIN group_techniques gt ON gt.group_id = tg.id
           JOIN group_sectors gs ON gs.group_id = tg.id
           JOIN sectors s ON s.id = gs.sector_id
           WHERE tg.is_revoked = false AND tg.is_deprecated = false AND s.slug = $1
           GROUP BY tg.id, tg.attack_id, tg.name
           ORDER BY "techniqueCount" DESC LIMIT 10`,
          [sector],
        )
      : query<{ attackId: string; name: string; techniqueCount: string }>(
          `SELECT tg.attack_id AS "attackId", tg.name, COUNT(gt.technique_id) AS "techniqueCount"
           FROM threat_groups tg
           JOIN group_techniques gt ON gt.group_id = tg.id
           WHERE tg.is_revoked = false AND tg.is_deprecated = false
           GROUP BY tg.id, tg.attack_id, tg.name
           ORDER BY "techniqueCount" DESC LIMIT 10`,
        ),

    // Tactic distribution
    sector
      ? query<{ tacticName: string; tacticId: string; count: string }>(
          `SELECT ta.name AS "tacticName", ta.attack_id AS "tacticId",
                  COUNT(DISTINCT tt.technique_id) AS count
           FROM tactics ta
           JOIN technique_tactics tt ON tt.tactic_id = ta.id
           JOIN techniques t ON t.id = tt.technique_id AND t.is_revoked = false AND t.is_deprecated = false
           JOIN group_techniques gt ON gt.technique_id = t.id
           JOIN group_sectors gs ON gs.group_id = gt.group_id
           JOIN sectors s ON s.id = gs.sector_id
           WHERE s.slug = $1
           GROUP BY ta.id, ta.name, ta.attack_id, ta.sort_order
           ORDER BY ta.sort_order ASC NULLS LAST`,
          [sector],
        )
      : query<{ tacticName: string; tacticId: string; count: string }>(
          `SELECT ta.name AS "tacticName", ta.attack_id AS "tacticId",
                  COUNT(DISTINCT tt.technique_id) AS count
           FROM tactics ta
           JOIN technique_tactics tt ON tt.tactic_id = ta.id
           JOIN techniques t ON t.id = tt.technique_id AND t.is_revoked = false AND t.is_deprecated = false
           GROUP BY ta.id, ta.name, ta.attack_id, ta.sort_order
           ORDER BY ta.sort_order ASC NULLS LAST`,
        ),

    // Sector breakdown — always global
    query<{ sectorName: string; groupCount: string }>(
      `SELECT s.name AS "sectorName", COUNT(DISTINCT gs.group_id) AS "groupCount"
       FROM sectors s
       JOIN group_sectors gs ON gs.sector_id = s.id
       JOIN threat_groups tg ON tg.id = gs.group_id AND tg.is_revoked = false AND tg.is_deprecated = false
       GROUP BY s.id, s.name ORDER BY "groupCount" DESC`,
    ),

    // ATT&CK version — always global
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
      tacticId: r.tacticId,
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
