import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from './lib/db.js';
import { withHandler } from './lib/middleware.js';
import { domainSchema } from './lib/validate.js';
import { z } from 'zod';

const querySchema = z.object({
  sector: z.string().max(50).optional(),
  domain: domainSchema,
});

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const parsed = querySchema.safeParse(req.query);
  const sector = parsed.success ? parsed.data.sector ?? null : null;
  const domain = parsed.success ? parsed.data.domain ?? null : null;

  // Build reusable domain filter snippets (parameterised index depends on call site)
  // Each query helper below receives its own params array and builds conditions in order.

  const [
    statsResult,
    topGroupsResult,
    tacticDistResult,
    sectorResult,
    topTechniquesResult,
    versionResult,
  ] = await Promise.all([
    // ── Entity counts ──────────────────────────────────────────────────────────
    (() => {
      if (sector && domain) {
        return query<{
          techniqueCount: string; groupCount: string; softwareCount: string;
          mitigationCount: string; campaignCount: string; dataSourceCount: string;
        }>(
          `SELECT
             (SELECT count(DISTINCT gt.technique_id)
              FROM group_techniques gt
              JOIN techniques tq ON tq.id = gt.technique_id AND tq.domain = $2
              JOIN group_sectors gs ON gs.group_id = gt.group_id
              JOIN sectors s ON s.id = gs.sector_id WHERE s.slug = $1) AS "techniqueCount",
             (SELECT count(DISTINCT gs.group_id)
              FROM group_sectors gs
              JOIN sectors s ON s.id = gs.sector_id
              JOIN threat_groups tg ON tg.id = gs.group_id
                AND tg.is_revoked = false AND tg.is_deprecated = false
              WHERE s.slug = $1) AS "groupCount",
             (SELECT count(DISTINCT gsw.software_id)
              FROM group_software gsw
              JOIN attack_software sw ON sw.id = gsw.software_id
                AND sw.is_revoked = false AND sw.is_deprecated = false AND sw.domain = $2
              JOIN group_sectors gs ON gs.group_id = gsw.group_id
              JOIN sectors s ON s.id = gs.sector_id WHERE s.slug = $1) AS "softwareCount",
             (SELECT count(*) FROM mitigations
              WHERE is_revoked = false AND is_deprecated = false AND domain = $2) AS "mitigationCount",
             (SELECT count(DISTINCT gc.campaign_id)
              FROM group_campaigns gc
              JOIN campaigns cp ON cp.id = gc.campaign_id AND cp.domain = $2
              JOIN group_sectors gs ON gs.group_id = gc.group_id
              JOIN sectors s ON s.id = gs.sector_id WHERE s.slug = $1) AS "campaignCount",
             (SELECT count(*) FROM data_sources
              WHERE is_revoked = false AND domain = $2) AS "dataSourceCount"`,
          [sector, domain],
        );
      }
      if (sector) {
        return query<{
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
        );
      }
      if (domain) {
        return query<{
          techniqueCount: string; groupCount: string; softwareCount: string;
          mitigationCount: string; campaignCount: string; dataSourceCount: string;
        }>(
          `SELECT
             (SELECT count(*) FROM techniques
              WHERE is_revoked = false AND is_deprecated = false AND domain = $1) AS "techniqueCount",
             (SELECT count(DISTINCT tg.id) FROM threat_groups tg
              WHERE tg.is_revoked = false AND tg.is_deprecated = false
              AND tg.id IN (
                SELECT gt.group_id FROM group_techniques gt
                JOIN techniques t ON t.id = gt.technique_id AND t.domain = $1
                UNION
                SELECT gt2.group_id FROM atlas_xrefs ax
                JOIN techniques at2 ON at2.id = ax.atlas_technique_id AND at2.domain = $1
                JOIN group_techniques gt2 ON gt2.technique_id = ax.attack_technique_id
              )) AS "groupCount",
             (SELECT count(*) FROM attack_software
              WHERE is_revoked = false AND is_deprecated = false AND domain = $1) AS "softwareCount",
             (SELECT count(*) FROM mitigations
              WHERE is_revoked = false AND is_deprecated = false AND domain = $1) AS "mitigationCount",
             (SELECT count(DISTINCT c.id) FROM campaigns c
              JOIN campaign_techniques ct ON ct.campaign_id = c.id
              JOIN techniques t ON t.id = ct.technique_id AND t.domain = $1
              WHERE c.is_revoked = false AND c.is_deprecated = false) AS "campaignCount",
             (SELECT count(*) FROM data_sources
              WHERE is_revoked = false AND domain = $1) AS "dataSourceCount"`,
          [domain],
        );
      }
      return query<{
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
      );
    })(),

    // ── Top 10 groups by technique count ──────────────────────────────────────
    (() => {
      if (sector && domain) {
        return query<{ attackId: string; name: string; techniqueCount: string }>(
          `SELECT tg.attack_id AS "attackId", tg.name, COUNT(gt.technique_id) AS "techniqueCount"
           FROM threat_groups tg
           JOIN group_techniques gt ON gt.group_id = tg.id
           JOIN techniques tq ON tq.id = gt.technique_id AND tq.domain = $2
           JOIN group_sectors gs ON gs.group_id = tg.id
           JOIN sectors s ON s.id = gs.sector_id
           WHERE tg.is_revoked = false AND tg.is_deprecated = false AND s.slug = $1
           GROUP BY tg.id, tg.attack_id, tg.name
           ORDER BY "techniqueCount" DESC LIMIT 10`,
          [sector, domain],
        );
      }
      if (sector) {
        return query<{ attackId: string; name: string; techniqueCount: string }>(
          `SELECT tg.attack_id AS "attackId", tg.name, COUNT(gt.technique_id) AS "techniqueCount"
           FROM threat_groups tg
           JOIN group_techniques gt ON gt.group_id = tg.id
           JOIN group_sectors gs ON gs.group_id = tg.id
           JOIN sectors s ON s.id = gs.sector_id
           WHERE tg.is_revoked = false AND tg.is_deprecated = false AND s.slug = $1
           GROUP BY tg.id, tg.attack_id, tg.name
           ORDER BY "techniqueCount" DESC LIMIT 10`,
          [sector],
        );
      }
      if (domain) {
        // 1st order: groups with techniques in this domain
        // + 2nd order for ATLAS: groups via atlas_xrefs → ATT&CK techniques
        return query<{ attackId: string; name: string; techniqueCount: string }>(
          `SELECT tg.attack_id AS "attackId", tg.name, COUNT(DISTINCT gt.technique_id) AS "techniqueCount"
           FROM threat_groups tg
           JOIN group_techniques gt ON gt.group_id = tg.id
           WHERE tg.is_revoked = false AND tg.is_deprecated = false
             AND gt.technique_id IN (
               SELECT id FROM techniques WHERE domain = $1
               UNION
               SELECT ax.attack_technique_id FROM atlas_xrefs ax
               JOIN techniques at2 ON at2.id = ax.atlas_technique_id AND at2.domain = $1
             )
           GROUP BY tg.id, tg.attack_id, tg.name
           ORDER BY "techniqueCount" DESC LIMIT 10`,
          [domain],
        );
      }
      return query<{ attackId: string; name: string; techniqueCount: string }>(
        `SELECT tg.attack_id AS "attackId", tg.name, COUNT(gt.technique_id) AS "techniqueCount"
         FROM threat_groups tg
         JOIN group_techniques gt ON gt.group_id = tg.id
         WHERE tg.is_revoked = false AND tg.is_deprecated = false
         GROUP BY tg.id, tg.attack_id, tg.name
         ORDER BY "techniqueCount" DESC LIMIT 10`,
      );
    })(),

    // ── Tactic distribution ───────────────────────────────────────────────────
    (() => {
      if (sector && domain) {
        return query<{ tacticName: string; tacticId: string; count: string; domain: string | null }>(
          `SELECT ta.name AS "tacticName", ta.attack_id AS "tacticId", ta.domain,
                  COUNT(DISTINCT tt.technique_id) AS count
           FROM tactics ta
           JOIN technique_tactics tt ON tt.tactic_id = ta.id
           JOIN techniques t ON t.id = tt.technique_id
             AND t.is_revoked = false AND t.is_deprecated = false AND t.domain = $2
           JOIN group_techniques gt ON gt.technique_id = t.id
           JOIN group_sectors gs ON gs.group_id = gt.group_id
           JOIN sectors s ON s.id = gs.sector_id
           WHERE s.slug = $1
           GROUP BY ta.id, ta.name, ta.attack_id, ta.domain, ta.sort_order
           ORDER BY ta.sort_order ASC NULLS LAST`,
          [sector, domain],
        );
      }
      if (sector) {
        return query<{ tacticName: string; tacticId: string; count: string; domain: string | null }>(
          `SELECT ta.name AS "tacticName", ta.attack_id AS "tacticId", ta.domain,
                  COUNT(DISTINCT tt.technique_id) AS count
           FROM tactics ta
           JOIN technique_tactics tt ON tt.tactic_id = ta.id
           JOIN techniques t ON t.id = tt.technique_id AND t.is_revoked = false AND t.is_deprecated = false
           JOIN group_techniques gt ON gt.technique_id = t.id
           JOIN group_sectors gs ON gs.group_id = gt.group_id
           JOIN sectors s ON s.id = gs.sector_id
           WHERE s.slug = $1
           GROUP BY ta.id, ta.name, ta.attack_id, ta.domain, ta.sort_order
           ORDER BY ta.sort_order ASC NULLS LAST`,
          [sector],
        );
      }
      if (domain) {
        return query<{ tacticName: string; tacticId: string; count: string; domain: string | null }>(
          `SELECT ta.name AS "tacticName", ta.attack_id AS "tacticId", ta.domain,
                  COUNT(DISTINCT tt.technique_id) AS count
           FROM tactics ta
           JOIN technique_tactics tt ON tt.tactic_id = ta.id
           JOIN techniques t ON t.id = tt.technique_id
             AND t.is_revoked = false AND t.is_deprecated = false AND t.domain = $1
           GROUP BY ta.id, ta.name, ta.attack_id, ta.domain, ta.sort_order
           ORDER BY ta.sort_order ASC NULLS LAST`,
          [domain],
        );
      }
      return query<{ tacticName: string; tacticId: string; count: string; domain: string | null }>(
        `SELECT ta.name AS "tacticName", ta.attack_id AS "tacticId", ta.domain,
                COUNT(DISTINCT tt.technique_id) AS count
         FROM tactics ta
         JOIN technique_tactics tt ON tt.tactic_id = ta.id
         JOIN techniques t ON t.id = tt.technique_id AND t.is_revoked = false AND t.is_deprecated = false
         GROUP BY ta.id, ta.name, ta.attack_id, ta.domain, ta.sort_order
         ORDER BY ta.sort_order ASC NULLS LAST`,
      );
    })(),

    // ── Sector breakdown — always global ──────────────────────────────────────
    query<{ sectorName: string; groupCount: string }>(
      `SELECT s.name AS "sectorName", COUNT(DISTINCT gs.group_id) AS "groupCount"
       FROM sectors s
       JOIN group_sectors gs ON gs.sector_id = s.id
       JOIN threat_groups tg ON tg.id = gs.group_id AND tg.is_revoked = false AND tg.is_deprecated = false
       GROUP BY s.id, s.name ORDER BY "groupCount" DESC`,
    ),

    // ── Top 10 most targeted techniques ───────────────────────────────────────
    (() => {
      if (sector && domain) {
        return query<{ attackId: string; name: string; groupCount: string }>(
          `SELECT t.attack_id AS "attackId", t.name, COUNT(DISTINCT gt.group_id) AS "groupCount"
           FROM techniques t
           JOIN group_techniques gt ON gt.technique_id = t.id
           JOIN group_sectors gs ON gs.group_id = gt.group_id
           JOIN sectors s ON s.id = gs.sector_id
           WHERE t.is_revoked = false AND t.is_deprecated = false
             AND t.is_subtechnique = false AND t.domain = $2 AND s.slug = $1
           GROUP BY t.id, t.attack_id, t.name
           ORDER BY "groupCount" DESC LIMIT 10`,
          [sector, domain],
        );
      }
      if (sector) {
        return query<{ attackId: string; name: string; groupCount: string }>(
          `SELECT t.attack_id AS "attackId", t.name, COUNT(DISTINCT gt.group_id) AS "groupCount"
           FROM techniques t
           JOIN group_techniques gt ON gt.technique_id = t.id
           JOIN group_sectors gs ON gs.group_id = gt.group_id
           JOIN sectors s ON s.id = gs.sector_id
           WHERE t.is_revoked = false AND t.is_deprecated = false AND t.is_subtechnique = false AND s.slug = $1
           GROUP BY t.id, t.attack_id, t.name
           ORDER BY "groupCount" DESC LIMIT 10`,
          [sector],
        );
      }
      if (domain) {
        // 1st order: techniques in this domain used by groups
        // + 2nd order for ATLAS: ATLAS techniques whose ATT&CK xrefs are used by groups
        return query<{ attackId: string; name: string; groupCount: string }>(
          `SELECT t.attack_id AS "attackId", t.name, COUNT(DISTINCT g.group_id) AS "groupCount"
           FROM techniques t
           JOIN (
             SELECT gt.technique_id, gt.group_id FROM group_techniques gt
             WHERE gt.technique_id IN (SELECT id FROM techniques WHERE domain = $1)
             UNION
             SELECT ax.atlas_technique_id AS technique_id, gt2.group_id
             FROM atlas_xrefs ax
             JOIN group_techniques gt2 ON gt2.technique_id = ax.attack_technique_id
             JOIN techniques at2 ON at2.id = ax.atlas_technique_id AND at2.domain = $1
           ) g ON g.technique_id = t.id
           WHERE t.is_revoked = false AND t.is_deprecated = false AND t.is_subtechnique = false
           GROUP BY t.id, t.attack_id, t.name
           ORDER BY "groupCount" DESC LIMIT 10`,
          [domain],
        );
      }
      return query<{ attackId: string; name: string; groupCount: string }>(
        `SELECT t.attack_id AS "attackId", t.name, COUNT(DISTINCT gt.group_id) AS "groupCount"
         FROM techniques t
         JOIN group_techniques gt ON gt.technique_id = t.id
         WHERE t.is_revoked = false AND t.is_deprecated = false AND t.is_subtechnique = false
         GROUP BY t.id, t.attack_id, t.name
         ORDER BY "groupCount" DESC LIMIT 10`,
      );
    })(),

    // ── ATT&CK version — filtered by domain when provided ──────────────────────
    domain
      ? query<{ attackVersion: string; domain: string; seededAt: string }>(
          `SELECT attack_version AS "attackVersion", domain, seeded_at AS "seededAt"
           FROM seed_metadata WHERE domain = $1 ORDER BY id DESC LIMIT 1`,
          [domain],
        )
      : query<{ attackVersion: string; domain: string; seededAt: string }>(
          `SELECT attack_version AS "attackVersion", domain, seeded_at AS "seededAt"
           FROM seed_metadata ORDER BY id DESC LIMIT 1`,
        ),
  ]);

  const raw = statsResult.rows[0];
  if (!raw) {
    res.status(500).json({ error: 'Failed to load stats', code: 'INTERNAL_ERROR' });
    return;
  }
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
      domain: r.domain ?? null,
    })),
    sectorBreakdown: sectorResult.rows.map((r) => ({
      sectorName: r.sectorName,
      groupCount: parseInt(r.groupCount, 10),
    })),
    topTechniques: topTechniquesResult.rows.map((r) => ({
      attackId: r.attackId,
      name: r.name,
      groupCount: parseInt(r.groupCount, 10),
    })),
    attackVersion: versionResult.rows[0] ?? null,
  });
}

export default withHandler(handler, { cacheTtl: 1800 });
