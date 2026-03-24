import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../lib/db.js';
import { withHandler } from '../lib/middleware.js';
import { attackIdSchema } from '../lib/validate.js';
import { z } from 'zod';

const optionalDomain = z.enum(['enterprise-attack', 'mobile-attack', 'ics-attack']).optional();

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const parsed = attackIdSchema.safeParse(req.query.attackId);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid attack_id format', code: 'VALIDATION_ERROR' });
    return;
  }
  const attackId = parsed.data;
  const domainParsed = optionalDomain.safeParse(req.query.domain);
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
    res.status(404).json({ error: 'Group not found', code: 'NOT_FOUND' });
    return;
  }

  const group = groupResult.rows[0];
  const groupId = group.id;

  const [techniquesResult, softwareResult, campaignsResult, sectorsResult] = await Promise.all([
    // Techniques with procedures (optionally filtered by domain)
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
    // Software (optionally filtered by domain)
    query<{ attackId: string; name: string; type: string; description: string | null }>(
      domain
        ? `SELECT sw.attack_id AS "attackId", sw.name, sw.type, gs.description
           FROM group_software gs
           JOIN attack_software sw ON sw.id = gs.software_id
           WHERE gs.group_id = $1 AND sw.domain = $2
           ORDER BY sw.name ASC`
        : `SELECT sw.attack_id AS "attackId", sw.name, sw.type, gs.description
           FROM group_software gs
           JOIN attack_software sw ON sw.id = gs.software_id
           WHERE gs.group_id = $1
           ORDER BY sw.name ASC`,
      domain ? [groupId, domain] : [groupId],
    ),
    // Campaigns
    query<{ attackId: string; name: string; description: string | null; firstSeen: string | null; lastSeen: string | null }>(
      `SELECT c.attack_id AS "attackId", c.name, gc.description,
              c.first_seen AS "firstSeen", c.last_seen AS "lastSeen"
       FROM group_campaigns gc
       JOIN campaigns c ON c.id = gc.campaign_id
       WHERE gc.group_id = $1
       ORDER BY c.name ASC`,
      [groupId],
    ),
    // Sectors
    query<{ name: string; slug: string | null }>(
      `SELECT s.name, s.slug
       FROM group_sectors gs
       JOIN sectors s ON s.id = gs.sector_id
       WHERE gs.group_id = $1
       ORDER BY s.name ASC`,
      [groupId],
    ),
  ]);

  res.status(200).json({
    ...group,
    techniques: techniquesResult.rows,
    software: softwareResult.rows,
    campaigns: campaignsResult.rows,
    sectors: sectorsResult.rows,
  });
}

export default withHandler(handler, { cacheTtl: 3600 });
