import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../_lib/db.js';
import { withHandler } from '../_lib/middleware.js';
import { attackIdSchema } from '../_lib/validate.js';

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const parsed = attackIdSchema.safeParse(req.query.attackId);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid attack_id format', code: 'VALIDATION_ERROR' });
    return;
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
    res.status(404).json({ error: 'Tactic not found', code: 'NOT_FOUND' });
    return;
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

  res.status(200).json({
    ...tactic,
    techniques: techniquesResult.rows,
  });
}

export default withHandler(handler, { cacheTtl: 3600 });
