import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../lib/db.js';
import { withHandler } from '../lib/middleware.js';
import { attackIdSchema } from '../lib/validate.js';
import { z } from 'zod';

const optionalSector = z.string().max(50).optional();
const optionalDomain = z.enum(['enterprise-attack', 'mobile-attack', 'ics-attack']).optional();

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const parsed = attackIdSchema.safeParse(req.query.attackId);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid attack_id format', code: 'VALIDATION_ERROR' });
    return;
  }
  const attackId = parsed.data;
  const sectorParsed = optionalSector.safeParse(req.query.sector);
  const sector = sectorParsed.success ? sectorParsed.data ?? null : null;
  const domainParsed = optionalDomain.safeParse(req.query.domain);
  const domain = domainParsed.success ? domainParsed.data ?? null : null;

  // Fetch main technique (optionally scoped by domain)
  const techParams: unknown[] = [attackId];
  const domainFilter = domain ? (() => { techParams.push(domain); return `AND domain = $${techParams.length}`; })() : '';

  const techResult = await query<{
    id: string; attackId: string; stixId: string | null; name: string;
    description: string | null; url: string | null; platforms: string[] | null;
    isSubtechnique: boolean; detection: string | null; isRevoked: boolean;
    isDeprecated: boolean; domain: string | null; stixCreated: string | null;
    stixModified: string | null;
  }>(
    `SELECT
       id, attack_id AS "attackId", stix_id AS "stixId", name, description, url,
       platforms, is_subtechnique AS "isSubtechnique", detection,
       is_revoked AS "isRevoked", is_deprecated AS "isDeprecated", domain,
       stix_created AS "stixCreated", stix_modified AS "stixModified"
     FROM techniques WHERE attack_id = $1 ${domainFilter}`,
    techParams,
  );

  if (techResult.rows.length === 0) {
    res.status(404).json({ error: 'Technique not found', code: 'NOT_FOUND' });
    return;
  }

  const tech = techResult.rows[0];
  const techId = tech.id;

  // Run all relationship queries in parallel
  const [groupsResult, softwareResult, mitigationsResult, dataComponentsResult, subTechResult, campaignsResult, tacticsResult] =
    await Promise.all([
      // Related groups — includes groups using this technique OR any of its sub-techniques
      query<{ attackId: string; name: string; procedure: string | null }>(
        `SELECT DISTINCT ON (tg.name) tg.attack_id AS "attackId", tg.name, gt.description AS procedure
         FROM group_techniques gt
         JOIN threat_groups tg ON tg.id = gt.group_id
         WHERE (gt.technique_id = $1
            OR gt.technique_id IN (SELECT id FROM techniques WHERE parent_technique_id = $1))
         ${sector ? `AND tg.id IN (SELECT gs.group_id FROM group_sectors gs JOIN sectors s ON s.id = gs.sector_id WHERE s.slug = $2)` : ''}
         ORDER BY tg.name ASC, (gt.technique_id = $1) DESC`,
        sector ? [techId, sector] : [techId],
      ),
      // Related software
      query<{ attackId: string; name: string; type: string; description: string | null }>(
        `SELECT sw.attack_id AS "attackId", sw.name, sw.type, st.description
         FROM software_techniques st
         JOIN attack_software sw ON sw.id = st.software_id
         WHERE st.technique_id = $1
         ${sector ? `AND sw.id IN (SELECT gsw.software_id FROM group_software gsw JOIN group_sectors gs ON gs.group_id = gsw.group_id JOIN sectors s ON s.id = gs.sector_id WHERE s.slug = $2)` : ''}
         ORDER BY sw.name ASC`,
        sector ? [techId, sector] : [techId],
      ),
      // Related mitigations
      query<{ attackId: string; name: string; description: string | null }>(
        `SELECT m.attack_id AS "attackId", m.name, mt.description
         FROM mitigation_techniques mt
         JOIN mitigations m ON m.id = mt.mitigation_id
         WHERE mt.technique_id = $1
         ORDER BY m.name ASC`,
        [techId],
      ),
      // Data components with data source name
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
      // Sub-techniques (if parent)
      query<{ attackId: string; name: string; description: string | null; detection: string | null }>(
        `SELECT attack_id AS "attackId", name, description, detection
         FROM techniques
         WHERE parent_technique_id = $1
           AND is_revoked = false AND is_deprecated = false
         ORDER BY attack_id ASC`,
        [techId],
      ),
      // Related campaigns
      query<{ attackId: string; name: string; description: string | null }>(
        `SELECT c.attack_id AS "attackId", c.name, ct.description
         FROM campaign_techniques ct
         JOIN campaigns c ON c.id = ct.campaign_id
         WHERE ct.technique_id = $1
         ${sector ? `AND c.id IN (SELECT gc.campaign_id FROM group_campaigns gc JOIN group_sectors gs ON gs.group_id = gc.group_id JOIN sectors s ON s.id = gs.sector_id WHERE s.slug = $2)` : ''}
         ORDER BY c.name ASC`,
        sector ? [techId, sector] : [techId],
      ),
      // Tactics
      query<{ attackId: string; name: string }>(
        `SELECT ta.attack_id AS "attackId", ta.name
         FROM technique_tactics tt
         JOIN tactics ta ON ta.id = tt.tactic_id
         WHERE tt.technique_id = $1
         ORDER BY ta.sort_order ASC`,
        [techId],
      ),
    ]);

  res.status(200).json({
    ...tech,
    tactics: tacticsResult.rows.map((t: any) => t.name),
    groups: groupsResult.rows,
    software: softwareResult.rows,
    mitigations: mitigationsResult.rows,
    dataComponents: dataComponentsResult.rows,
    sub_techniques: subTechResult.rows,
    campaigns: campaignsResult.rows,
  });
}

export default withHandler(handler, { cacheTtl: 3600 });
