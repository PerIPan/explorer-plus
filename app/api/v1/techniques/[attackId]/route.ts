import { NextRequest } from 'next/server';
import { query } from '../../lib/db';
import { jsonResponse, errorResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';
import { attackIdSchema, domainSchema } from '../../lib/validate';
import { z } from 'zod';

export { OPTIONS };

const optionalSector = z.string().max(50).optional();

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
  const sectorParsed = optionalSector.safeParse(req.nextUrl.searchParams.get('sector') ?? undefined);
  const sector = sectorParsed.success ? sectorParsed.data ?? null : null;
  const domainParsed = domainSchema.safeParse(req.nextUrl.searchParams.get('domain') ?? undefined);
  const domain = domainParsed.success ? domainParsed.data ?? null : null;

  // Fetch main technique (optionally scoped by domain)
  const techParams: unknown[] = [attackId];
  const domainFilter = domain ? (() => { techParams.push(domain); return `AND domain = $${techParams.length}`; })() : '';

  const techResult = await query<{
    id: string; attackId: string; stixId: string | null; name: string;
    description: string | null; url: string | null; platforms: string[] | null;
    isSubtechnique: boolean; detection: string | null; isRevoked: boolean;
    isDeprecated: boolean; domain: string | null; stixCreated: string | null;
    stixModified: string | null; maturity: string | null;
  }>(
    `SELECT
       id, attack_id AS "attackId", stix_id AS "stixId", name, description, url,
       platforms, is_subtechnique AS "isSubtechnique", detection,
       is_revoked AS "isRevoked", is_deprecated AS "isDeprecated", domain,
       stix_created AS "stixCreated", stix_modified AS "stixModified", maturity
     FROM techniques WHERE attack_id = $1 ${domainFilter}`,
    techParams,
  );

  if (techResult.rows.length === 0) {
    return withCors(errorResponse(404, 'Technique not found', 'NOT_FOUND'));
  }

  const tech = techResult.rows[0];
  const techId = tech.id;

  // Run all relationship queries in parallel
  const [groupsResult, softwareResult, mitigationsResult, dataComponentsResult, subTechResult, campaignsResult, tacticsResult, xrefsResult] =
    await Promise.all([
      query<{ attackId: string; name: string; procedure: string | null }>(
        `SELECT DISTINCT ON (tg.name) tg.attack_id AS "attackId", tg.name, gt.description AS procedure
         FROM group_techniques gt
         JOIN threat_groups tg ON tg.id = gt.group_id
         WHERE (gt.technique_id = $1
            OR gt.technique_id IN (SELECT id FROM techniques WHERE parent_technique_id = $1))
         ${sector ? `AND tg.id IN (SELECT gs.group_id FROM group_sectors gs JOIN sectors s ON s.id = gs.sector_id WHERE s.slug = $2)` : ''}
         ORDER BY tg.name ASC`,
        sector ? [techId, sector] : [techId],
      ),
      query<{ attackId: string; name: string; type: string; description: string | null }>(
        `SELECT sw.attack_id AS "attackId", sw.name, sw.type, st.description
         FROM software_techniques st
         JOIN attack_software sw ON sw.id = st.software_id
         WHERE st.technique_id = $1
         ${sector ? `AND sw.id IN (SELECT gsw.software_id FROM group_software gsw JOIN group_sectors gs ON gs.group_id = gsw.group_id JOIN sectors s ON s.id = gs.sector_id WHERE s.slug = $2)` : ''}
         ORDER BY sw.name ASC`,
        sector ? [techId, sector] : [techId],
      ),
      query<{ attackId: string; name: string; description: string | null }>(
        `SELECT m.attack_id AS "attackId", m.name, mt.description
         FROM mitigation_techniques mt
         JOIN mitigations m ON m.id = mt.mitigation_id
         WHERE mt.technique_id = $1
         ORDER BY m.name ASC`,
        [techId],
      ),
      query<{ componentName: string; description: string | null; dataSourceName: string; dataSourceAttackId: string }>(
        `SELECT dc.name AS "componentName", dc.description,
                ds.name AS "dataSourceName", ds.attack_id AS "dataSourceAttackId"
         FROM technique_data_components tdc
         JOIN data_components dc ON dc.id = tdc.data_component_id
         JOIN data_sources ds ON ds.id = dc.data_source_id
         WHERE tdc.technique_id = $1
         ORDER BY ds.name ASC, dc.name ASC`,
        [techId],
      ),
      query<{ attackId: string; name: string; description: string | null; detection: string | null }>(
        `SELECT attack_id AS "attackId", name, description, detection
         FROM techniques
         WHERE parent_technique_id = $1
           AND is_revoked = false AND is_deprecated = false
         ORDER BY attack_id ASC`,
        [techId],
      ),
      query<{ attackId: string; name: string; description: string | null }>(
        `SELECT c.attack_id AS "attackId", c.name, ct.description
         FROM campaign_techniques ct
         JOIN campaigns c ON c.id = ct.campaign_id
         WHERE ct.technique_id = $1
         ${sector ? `AND c.id IN (SELECT gc.campaign_id FROM group_campaigns gc JOIN group_sectors gs ON gs.group_id = gc.group_id JOIN sectors s ON s.id = gs.sector_id WHERE s.slug = $2)` : ''}
         ORDER BY c.name ASC`,
        sector ? [techId, sector] : [techId],
      ),
      query<{ attackId: string; name: string }>(
        `SELECT ta.attack_id AS "attackId", ta.name
         FROM technique_tactics tt
         JOIN tactics ta ON ta.id = tt.tactic_id
         WHERE tt.technique_id = $1
         ORDER BY ta.sort_order ASC`,
        [techId],
      ),
      query<{ attackId: string; name: string; domain: string | null }>(
        `SELECT t.attack_id AS "attackId", t.name, t.domain
         FROM atlas_xrefs ax
         JOIN techniques t ON t.id = ax.attack_technique_id
         WHERE ax.atlas_technique_id = $1
         UNION
         SELECT t.attack_id AS "attackId", t.name, t.domain
         FROM atlas_xrefs ax
         JOIN techniques t ON t.id = ax.atlas_technique_id
         WHERE ax.attack_technique_id = $1`,
        [techId],
      ),
    ]);

  return withCors(jsonResponse({
    ...tech,
    tactics: tacticsResult.rows.map((t) => t.name),
    groups: groupsResult.rows,
    software: softwareResult.rows,
    mitigations: mitigationsResult.rows,
    dataComponents: dataComponentsResult.rows,
    sub_techniques: subTechResult.rows,
    campaigns: campaignsResult.rows,
    atlasXrefs: xrefsResult.rows,
  }, 3600));
}
