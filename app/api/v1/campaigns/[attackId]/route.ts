import { NextRequest } from 'next/server';
import { query } from '../../lib/db.js';
import { jsonResponse, errorResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';
import { attackIdSchema } from '../../lib/validate.js';

export { OPTIONS };

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ attackId: string }> }
) {
  const { attackId: rawAttackId } = await params;
  const parsed = attackIdSchema.safeParse(rawAttackId);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Invalid attack_id format', 'VALIDATION_ERROR'));
  }
  const attackId = parsed.data;

  const campaignResult = await query<{
    id: string; attackId: string; stixId: string | null; name: string;
    description: string | null; url: string | null; aliases: string[] | null;
    firstSeen: string | null; lastSeen: string | null; isRevoked: boolean;
    isDeprecated: boolean; domain: string | null; stixCreated: string | null;
    stixModified: string | null;
  }>(
    `SELECT
       id, attack_id AS "attackId", stix_id AS "stixId", name, description, url,
       aliases, first_seen AS "firstSeen", last_seen AS "lastSeen",
       is_revoked AS "isRevoked", is_deprecated AS "isDeprecated",
       domain, stix_created AS "stixCreated", stix_modified AS "stixModified"
     FROM campaigns WHERE attack_id = $1`,
    [attackId],
  );

  if (campaignResult.rows.length === 0) {
    return withCors(errorResponse(404, 'Campaign not found', 'NOT_FOUND'));
  }

  const campaign = campaignResult.rows[0];
  const campaignId = campaign.id;

  const [techniquesResult, softwareResult, groupsResult] = await Promise.all([
    query<{ attackId: string; name: string; description: string | null; platforms: string[] | null }>(
      `SELECT t.attack_id AS "attackId", t.name, ct.description, t.platforms
       FROM campaign_techniques ct
       JOIN techniques t ON t.id = ct.technique_id
       WHERE ct.campaign_id = $1
       ORDER BY t.name ASC`,
      [campaignId],
    ),
    query<{ attackId: string; name: string; type: string; description: string | null }>(
      `SELECT sw.attack_id AS "attackId", sw.name, sw.type, cs.description
       FROM campaign_software cs
       JOIN attack_software sw ON sw.id = cs.software_id
       WHERE cs.campaign_id = $1
       ORDER BY sw.name ASC`,
      [campaignId],
    ),
    query<{ attackId: string; name: string; description: string | null }>(
      `SELECT tg.attack_id AS "attackId", tg.name, gc.description
       FROM group_campaigns gc
       JOIN threat_groups tg ON tg.id = gc.group_id
       WHERE gc.campaign_id = $1
       ORDER BY tg.name ASC`,
      [campaignId],
    ),
  ]);

  return withCors(jsonResponse({
    ...campaign,
    techniques: techniquesResult.rows,
    software: softwareResult.rows,
    groups: groupsResult.rows,
  }, 3600));
}
