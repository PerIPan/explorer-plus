import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../../lib/db.js';
import { withHandler } from '../../lib/middleware.js';
import { slugSchema } from '../../lib/validate.js';

/**
 * Sector 360 View — returns groups, campaigns, software, techniques, and CVEs
 * linked to a sector via group_sectors → group → relationships.
 */
async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const parsed = slugSchema.safeParse(req.query.slug);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid slug format', code: 'VALIDATION_ERROR' });
    return;
  }
  const slug = parsed.data;

  const sectorResult = await query<{ id: string; name: string; slug: string | null }>(
    `SELECT id, name, slug FROM sectors WHERE slug = $1`,
    [slug],
  );

  if (sectorResult.rows.length === 0) {
    res.status(404).json({ error: 'Sector not found', code: 'NOT_FOUND' });
    return;
  }

  const sector = sectorResult.rows[0];
  const sectorId = sector.id;

  const [groups, campaigns, software, techniques, cves, apps] = await Promise.all([
    // Groups targeting this sector
    query<{ attackId: string; name: string; aliases: string[] | null; source: string }>(
      `SELECT
         tg.attack_id AS "attackId", tg.name, tg.aliases, gs.source
       FROM group_sectors gs
       JOIN threat_groups tg ON tg.id = gs.group_id
       WHERE gs.sector_id = $1 AND tg.is_revoked = false AND tg.is_deprecated = false
       ORDER BY tg.name ASC`,
      [sectorId],
    ),

    // Campaigns by groups in this sector
    query<{ attackId: string; name: string; firstSeen: string | null; lastSeen: string | null }>(
      `SELECT DISTINCT
         c.attack_id AS "attackId", c.name,
         c.first_seen AS "firstSeen", c.last_seen AS "lastSeen"
       FROM group_sectors gs
       JOIN group_campaigns gc ON gc.group_id = gs.group_id
       JOIN campaigns c ON c.id = gc.campaign_id
       WHERE gs.sector_id = $1 AND c.is_revoked = false AND c.is_deprecated = false
       ORDER BY c.name ASC`,
      [sectorId],
    ),

    // Software used by groups in this sector
    query<{ attackId: string; name: string; type: string | null }>(
      `SELECT DISTINCT
         sw.attack_id AS "attackId", sw.name, sw.type
       FROM group_sectors gs
       JOIN group_software gsw ON gsw.group_id = gs.group_id
       JOIN attack_software sw ON sw.id = gsw.software_id
       WHERE gs.sector_id = $1 AND sw.is_revoked = false AND sw.is_deprecated = false
       ORDER BY sw.name ASC`,
      [sectorId],
    ),

    // Top techniques used by groups in this sector (via group_techniques)
    query<{ attackId: string; name: string; groupCount: string }>(
      `SELECT
         t.attack_id AS "attackId", t.name,
         COUNT(DISTINCT gt.group_id)::text AS "groupCount"
       FROM group_sectors gs
       JOIN group_techniques gt ON gt.group_id = gs.group_id
       JOIN techniques t ON t.id = gt.technique_id
       WHERE gs.sector_id = $1 AND t.is_revoked = false AND t.is_deprecated = false
         AND t.is_subtechnique = false
       GROUP BY t.attack_id, t.name
       ORDER BY COUNT(DISTINCT gt.group_id) DESC, t.name ASC
       LIMIT 50`,
      [sectorId],
    ),

    // CVEs linked to techniques used by groups in this sector
    query<{ cveId: string; description: string | null; cvssSeverity: string | null; publishedAt: string | null }>(
      `SELECT DISTINCT
         cd.cve_id AS "cveId", cd.description,
         cd.cvss_severity AS "cvssSeverity", cd.published_at AS "publishedAt"
       FROM group_sectors gs
       JOIN group_techniques gt ON gt.group_id = gs.group_id
       JOIN technique_iocs ti ON ti.technique_id = gt.technique_id
       JOIN ioc_entries ie ON ie.id = ti.ioc_id AND ie.type = 'cve'
       JOIN cve_details cd ON cd.cve_id = ie.value
       WHERE gs.sector_id = $1
       ORDER BY cd.published_at DESC NULLS LAST
       LIMIT 20`,
      [sectorId],
    ),

    // Vulnerable applications (via groups → techniques → CAPEC → CVE → apps)
    query<{ normalized: string; vendor: string; product: string; cveCount: string }>(
      `SELECT DISTINCT a.normalized, a.vendor, a.product, a.cve_count::text AS "cveCount"
       FROM group_sectors gs
       JOIN app_technique_groups atg ON atg.group_attack_id = (
         SELECT attack_id FROM threat_groups WHERE id = gs.group_id
       )
       JOIN applications a ON a.id = atg.application_id
       WHERE gs.sector_id = $1
       ORDER BY a.cve_count DESC
       LIMIT 20`,
      [sectorId],
    ),
  ]);

  res.status(200).json({
    ...sector,
    groups: groups.rows,
    campaigns: campaigns.rows,
    software: software.rows,
    techniques: techniques.rows.map((r) => ({
      ...r,
      groupCount: parseInt(r.groupCount, 10),
    })),
    cves: cves.rows,
    vulnerableApps: apps.rows.map((r) => ({ ...r, cveCount: parseInt(r.cveCount, 10) })),
  });
}

export default withHandler(handler, { cacheTtl: 3600 });
