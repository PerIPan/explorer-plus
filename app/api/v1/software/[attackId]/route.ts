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

  const softwareResult = await query<{
    id: string; attackId: string; stixId: string | null; name: string;
    description: string | null; url: string | null; type: string;
    platforms: string[] | null; aliases: string[] | null; isRevoked: boolean;
    isDeprecated: boolean; domain: string | null; stixCreated: string | null;
    stixModified: string | null;
  }>(
    `SELECT
       id, attack_id AS "attackId", stix_id AS "stixId", name, description, url,
       type, platforms, aliases, is_revoked AS "isRevoked",
       is_deprecated AS "isDeprecated", domain,
       stix_created AS "stixCreated", stix_modified AS "stixModified"
     FROM attack_software WHERE attack_id = $1`,
    [attackId],
  );

  if (softwareResult.rows.length === 0) {
    return withCors(errorResponse(404, 'Software not found', 'NOT_FOUND'));
  }

  const software = softwareResult.rows[0];
  const softwareId = software.id;

  const [techniquesResult, groupsResult, campaignsResult] = await Promise.all([
    query<{ attackId: string; name: string; procedure: string | null; platforms: string[] | null }>(
      `SELECT t.attack_id AS "attackId", t.name, st.description AS procedure, t.platforms
       FROM software_techniques st
       JOIN techniques t ON t.id = st.technique_id
       WHERE st.software_id = $1
       ORDER BY t.name ASC`,
      [softwareId],
    ),
    query<{ attackId: string; name: string; description: string | null }>(
      `SELECT tg.attack_id AS "attackId", tg.name, gs.description
       FROM group_software gs
       JOIN threat_groups tg ON tg.id = gs.group_id
       WHERE gs.software_id = $1
       ORDER BY tg.name ASC`,
      [softwareId],
    ),
    query<{ attackId: string; name: string; description: string | null }>(
      `SELECT c.attack_id AS "attackId", c.name, cs.description
       FROM campaign_software cs
       JOIN campaigns c ON c.id = cs.campaign_id
       WHERE cs.software_id = $1
       ORDER BY c.name ASC`,
      [softwareId],
    ),
  ]);

  return withCors(jsonResponse({
    ...software,
    techniques: techniquesResult.rows,
    groups: groupsResult.rows,
    campaigns: campaignsResult.rows,
  }, 3600));
}
