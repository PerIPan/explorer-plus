import { NextRequest } from 'next/server';
import { query } from '../../lib/db';
import { jsonResponse, errorResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';
import { attackIdSchema, domainSchema } from '../../lib/validate';

export { OPTIONS };

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ attackId: string }> }
) {
  const { attackId: rawAttackId } = await params;
  const parsed = attackIdSchema.safeParse(rawAttackId);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Invalid attack_id format', 'VALIDATION_ERROR'));
  }
  const attackId = parsed.data;
  const domainParsed = domainSchema.safeParse(req.nextUrl.searchParams.get('domain') ?? undefined);
  const domain = domainParsed.success ? domainParsed.data ?? null : null;

  const groupResult = await query<{
    id: string; attackId: string; stixId: string | null; name: string;
    description: string | null; url: string | null; aliases: string[] | null;
    isRevoked: boolean; isDeprecated: boolean; domain: string | null;
    stixCreated: string | null; stixModified: string | null;
  }>(
    `SELECT
       id, attack_id AS "attackId", stix_id AS "stixId", name, description, url,
       aliases, is_revoked AS "isRevoked", is_deprecated AS "isDeprecated",
       domain, stix_created AS "stixCreated", stix_modified AS "stixModified"
     FROM threat_groups WHERE attack_id = $1`,
    [attackId],
  );

  if (groupResult.rows.length === 0) {
    return withCors(errorResponse(404, 'Group not found', 'NOT_FOUND'));
  }

  const group = groupResult.rows[0];
  const groupId = group.id;

  const [techniquesResult, softwareResult, campaignsResult, sectorsResult, appsResult] = await Promise.all([
    query<{ attackId: string; name: string; procedure: string | null; platforms: string[] | null }>(
      domain
        ? `SELECT t.attack_id AS "attackId", t.name, gt.description AS procedure, t.platforms
           FROM group_techniques gt
           JOIN techniques t ON t.id = gt.technique_id
           WHERE gt.group_id = $1 AND t.domain = $2
           ORDER BY t.name ASC`
        : `SELECT t.attack_id AS "attackId", t.name, gt.description AS procedure, t.platforms
           FROM group_techniques gt
           JOIN techniques t ON t.id = gt.technique_id
           WHERE gt.group_id = $1
           ORDER BY t.name ASC`,
      domain ? [groupId, domain] : [groupId],
    ),
    query<{ attackId: string; name: string; type: string; description: string | null }>(
      domain
        ? `SELECT sw.attack_id AS "attackId", sw.name, sw.type, gs.description
           FROM group_software gs
           JOIN attack_software sw ON sw.id = gs.software_id
           WHERE gs.group_id = $1 AND $2 = ANY(sw.domain)
           ORDER BY sw.name ASC`
        : `SELECT sw.attack_id AS "attackId", sw.name, sw.type, gs.description
           FROM group_software gs
           JOIN attack_software sw ON sw.id = gs.software_id
           WHERE gs.group_id = $1
           ORDER BY sw.name ASC`,
      domain ? [groupId, domain] : [groupId],
    ),
    query<{ attackId: string; name: string; description: string | null; firstSeen: string | null; lastSeen: string | null }>(
      domain
        ? `SELECT c.attack_id AS "attackId", c.name, gc.description,
                c.first_seen AS "firstSeen", c.last_seen AS "lastSeen"
           FROM group_campaigns gc
           JOIN campaigns c ON c.id = gc.campaign_id
           WHERE gc.group_id = $1 AND $2 = ANY(c.domain)
           ORDER BY c.name ASC`
        : `SELECT c.attack_id AS "attackId", c.name, gc.description,
                c.first_seen AS "firstSeen", c.last_seen AS "lastSeen"
           FROM group_campaigns gc
           JOIN campaigns c ON c.id = gc.campaign_id
           WHERE gc.group_id = $1
           ORDER BY c.name ASC`,
      domain ? [groupId, domain] : [groupId],
    ),
    query<{ name: string; slug: string | null }>(
      `SELECT s.name, s.slug
       FROM group_sectors gs
       JOIN sectors s ON s.id = gs.sector_id
       WHERE gs.group_id = $1
       ORDER BY s.name ASC`,
      [groupId],
    ),
    query<{ normalized: string; vendor: string; product: string; cveCount: string }>(
      `SELECT a.normalized, a.vendor, a.product, a.cve_count::text AS "cveCount"
       FROM applications a
       WHERE a.id IN (
         SELECT DISTINCT atg.application_id FROM app_technique_groups atg
         WHERE atg.group_attack_id = $1
       )
       ORDER BY a.cve_count DESC
       LIMIT 100`,
      [group.attackId],
    ),
  ]);

  return withCors(jsonResponse({
    ...group,
    techniques: techniquesResult.rows,
    software: softwareResult.rows,
    campaigns: campaignsResult.rows,
    sectors: sectorsResult.rows,
    targetedApps: appsResult.rows.map((r) => ({ ...r, cveCount: parseInt(r.cveCount, 10) })),
  }, 3600));
}
