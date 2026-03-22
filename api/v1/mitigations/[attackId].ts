import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../lib/db.js';
import { withHandler } from '../lib/middleware.js';
import { attackIdSchema } from '../lib/validate.js';

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const parsed = attackIdSchema.safeParse(req.query.attackId);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid attack_id format', code: 'VALIDATION_ERROR' });
    return;
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
    res.status(404).json({ error: 'Mitigation not found', code: 'NOT_FOUND' });
    return;
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

  res.status(200).json({
    ...mitigation,
    techniques: techniquesResult.rows,
  });
}

export default withHandler(handler, { cacheTtl: 3600 });
