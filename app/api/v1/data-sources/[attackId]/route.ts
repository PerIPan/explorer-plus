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

  const dsResult = await query<{
    id: string; attackId: string; stixId: string | null; name: string;
    description: string | null; url: string | null; isRevoked: boolean;
    isDeprecated: boolean; domain: string | null; stixCreated: string | null;
    stixModified: string | null;
  }>(
    `SELECT
       id, attack_id AS "attackId", stix_id AS "stixId", name, description, url,
       is_revoked AS "isRevoked", is_deprecated AS "isDeprecated", domain,
       stix_created AS "stixCreated", stix_modified AS "stixModified"
     FROM data_sources WHERE attack_id = $1`,
    [attackId],
  );

  if (dsResult.rows.length === 0) {
    return withCors(errorResponse(404, 'Data source not found', 'NOT_FOUND'));
  }

  const ds = dsResult.rows[0];
  const dsId = ds.id;

  const componentsResult = await query<{
    componentId: string; componentName: string; componentDescription: string | null;
  }>(
    `SELECT
       dc.id          AS "componentId",
       dc.name        AS "componentName",
       dc.description AS "componentDescription"
     FROM data_components dc
     WHERE dc.data_source_id = $1
     ORDER BY dc.name ASC`,
    [dsId],
  );

  const techniquesResult = await query<{
    attackId: string; name: string; componentName: string;
  }>(
    `SELECT DISTINCT
       t.attack_id  AS "attackId",
       t.name,
       dc.name      AS "componentName"
     FROM technique_data_components tdc
     JOIN techniques t  ON t.id  = tdc.technique_id
     JOIN data_components dc ON dc.id = tdc.data_component_id
     WHERE dc.data_source_id = $1
       AND t.is_revoked = false AND t.is_deprecated = false
     ORDER BY t.name ASC`,
    [dsId],
  );

  return withCors(jsonResponse({
    ...ds,
    components: componentsResult.rows,
    techniques: techniquesResult.rows,
  }, 3600));
}
