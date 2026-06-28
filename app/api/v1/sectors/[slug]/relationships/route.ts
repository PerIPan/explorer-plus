import { NextRequest } from 'next/server';
import { query } from '../../../lib/db';
import { jsonResponse, errorResponse } from '../../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../../lib/cors';
import { slugSchema } from '../../../lib/validate';

export { OPTIONS };

/**
 * Sector 360 View — returns groups, campaigns, software, techniques, and CVEs
 * linked to a sector via group_sectors -> group -> relationships.
 */
export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ slug: string }> }
) {
  const { slug: rawSlug } = await params;
  const parsed = slugSchema.safeParse(rawSlug);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Invalid slug format', 'VALIDATION_ERROR'));
  }
  const slug = parsed.data;

  const sectorResult = await query<{ id: string; name: string; slug: string | null }>(
    `SELECT id, name, slug FROM sectors WHERE slug = $1`,
    [slug],
  );

  if (sectorResult.rows.length === 0) {
    return withCors(errorResponse(404, 'Sector not found', 'NOT_FOUND'));
  }

  const sector = sectorResult.rows[0];
  const sectorId = sector.id;

  const [groups, campaigns, software, techniques, cves, apps] = await Promise.all([
    query<{ attackId: string; name: string; aliases: string[] | null; source: string }>(
      `SELECT
         tg.attack_id AS "attackId", tg.name, tg.aliases, gs.source
       FROM group_sectors gs
       JOIN threat_groups tg ON tg.id = gs.group_id
       WHERE gs.sector_id = $1 AND tg.is_revoked = false AND tg.is_deprecated = false
       ORDER BY tg.name ASC`,
      [sectorId],
    ),

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

    query<{ cveId: string; description: string | null; cvssSeverity: string | null; publishedAt: string | null; isKev: boolean }>(
      `SELECT DISTINCT cd.cve_id AS "cveId", cd.description,
         cd.cvss_severity AS "cvssSeverity", cd.published_at AS "publishedAt",
         COALESCE(cd.is_kev, false) AS "isKev"
       FROM cve_details cd
       WHERE cd.cve_id IN (
         (SELECT ie.value FROM group_sectors gs
          JOIN group_techniques gt ON gt.group_id = gs.group_id
          JOIN technique_iocs ti ON ti.technique_id = gt.technique_id
          JOIN ioc_entries ie ON ie.id = ti.ioc_id AND ie.type = 'cve'
          WHERE gs.sector_id = $1 LIMIT 200)
         UNION
         -- Grounded CVE path: real CVEs affecting the applications already
         -- linked to this sector's groups via the (catch-all-guarded)
         -- app_technique_groups matview — the same basis as the apps list
         -- below. Replaces a prior reverse CWE fan-out (technique→CWE→every
         -- CVE sharing that CWE) that linked sectors to unrelated CVEs.
         (SELECT ap.cve_id FROM group_sectors gs
          JOIN threat_groups tg ON tg.id = gs.group_id
          JOIN app_technique_groups atg ON atg.group_attack_id = tg.attack_id
          JOIN affected_products ap ON ap.application_id = atg.application_id
          WHERE gs.sector_id = $1 LIMIT 200)
       )
       ORDER BY cd.published_at DESC NULLS LAST
       LIMIT 4`,
      [sectorId],
    ),

    query<{ normalized: string; vendor: string; product: string; cveCount: string }>(
      `SELECT normalized, vendor, product, "cveCount" FROM (
         SELECT DISTINCT a.normalized, a.vendor, a.product, a.cve_count::text AS "cveCount", a.cve_count
         FROM group_sectors gs
         JOIN threat_groups tg ON tg.id = gs.group_id
         JOIN app_technique_groups atg ON atg.group_attack_id = tg.attack_id
         JOIN applications a ON a.id = atg.application_id
         WHERE gs.sector_id = $1
       ) sub
       ORDER BY cve_count DESC
       LIMIT 100`,
      [sectorId],
    ),
  ]);

  return withCors(jsonResponse({
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
  }, 3600));
}
