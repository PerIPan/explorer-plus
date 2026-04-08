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

  const tacticResult = await query<{
    id: string; attackId: string; stixId: string | null; name: string;
    description: string | null; url: string | null; sortOrder: number | null;
    domain: string | null; stixCreated: string | null; stixModified: string | null;
  }>(
    `SELECT
       id, attack_id AS "attackId", stix_id AS "stixId", name, description, url,
       sort_order AS "sortOrder", domain,
       stix_created AS "stixCreated", stix_modified AS "stixModified"
     FROM tactics WHERE attack_id = $1`,
    [attackId],
  );

  if (tacticResult.rows.length === 0) {
    return withCors(errorResponse(404, 'Tactic not found', 'NOT_FOUND'));
  }

  const tactic = tacticResult.rows[0];
  const tacticId = tactic.id;

  const techniquesResult = await query<{
    attackId: string; name: string; description: string | null;
    platforms: string[] | null; isSubtechnique: boolean;
  }>(
    `SELECT
       t.attack_id      AS "attackId",
       t.name,
       t.description,
       t.platforms,
       t.is_subtechnique AS "isSubtechnique"
     FROM technique_tactics tt
     JOIN techniques t ON t.id = tt.technique_id
     WHERE tt.tactic_id = $1
       AND t.is_revoked = false AND t.is_deprecated = false
     ORDER BY t.attack_id ASC`,
    [tacticId],
  );

  return withCors(jsonResponse({
    ...tactic,
    techniques: techniquesResult.rows,
  }, 3600));
}
