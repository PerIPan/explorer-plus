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

  const mitResult = await query<{
    id: string; attackId: string; stixId: string | null; name: string;
    description: string | null; url: string | null; isRevoked: boolean;
    isDeprecated: boolean; domain: string | null; stixCreated: string | null;
    stixModified: string | null;
  }>(
    `SELECT
       id, attack_id AS "attackId", stix_id AS "stixId", name, description, url,
       is_revoked AS "isRevoked", is_deprecated AS "isDeprecated", domain,
       stix_created AS "stixCreated", stix_modified AS "stixModified"
     FROM mitigations WHERE attack_id = $1`,
    [attackId],
  );

  if (mitResult.rows.length === 0) {
    return withCors(errorResponse(404, 'Mitigation not found', 'NOT_FOUND'));
  }

  const mitigation = mitResult.rows[0];
  const mitId = mitigation.id;

  const techniquesResult = await query<{
    attackId: string; name: string; description: string | null; platforms: string[] | null;
  }>(
    `SELECT t.attack_id AS "attackId", t.name, mt.description, t.platforms
     FROM mitigation_techniques mt
     JOIN techniques t ON t.id = mt.technique_id
     WHERE mt.mitigation_id = $1
       AND t.is_revoked = false AND t.is_deprecated = false
     ORDER BY t.name ASC`,
    [mitId],
  );

  return withCors(jsonResponse({
    ...mitigation,
    techniques: techniquesResult.rows,
  }, 3600));
}
