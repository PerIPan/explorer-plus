import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../_lib/db';
import { withHandler } from '../_lib/middleware';
import { attackIdSchema } from '../_lib/validate';

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const parsed = attackIdSchema.safeParse(req.query.attackId);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid attack_id format', code: 'VALIDATION_ERROR' });
    return;
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
    res.status(404).json({ error: 'Data source not found', code: 'NOT_FOUND' });
    return;
  }

  const ds = dsResult.rows[0];
  const dsId = ds.id;

  // Components with their linked techniques
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

  // Techniques linked through data components
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

  res.status(200).json({
    ...ds,
    components: componentsResult.rows,
    techniques: techniquesResult.rows,
  });
}

export default withHandler(handler, { cacheTtl: 3600 });
