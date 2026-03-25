import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../../lib/db.js';
import { withHandler } from '../../lib/middleware.js';
import { attackIdSchema } from '../../lib/validate.js';

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const parsed = attackIdSchema.safeParse(req.query.attackId);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid attack_id format', code: 'VALIDATION_ERROR' });
    return;
  }
  const attackId = parsed.data;

  const [nistResult, engageResult, verisResult, cloudResult] = await Promise.all([
    query<{
      controlId: string;
      controlName: string | null;
      controlFamily: string | null;
      attackTechniqueId: string;
      mappingType: string | null;
    }>(
      `SELECT
         control_id          AS "controlId",
         control_name        AS "controlName",
         control_family      AS "controlFamily",
         attack_technique_id AS "attackTechniqueId",
         mapping_type        AS "mappingType"
       FROM nist_controls
       WHERE attack_technique_id = $1
       ORDER BY control_id ASC`,
      [attackId],
    ),
    query<{
      engageId: string;
      engageName: string;
      engageDescription: string | null;
      goal: string | null;
      approach: string | null;
      attackTechniqueId: string;
    }>(
      `SELECT
         engage_id           AS "engageId",
         engage_name         AS "engageName",
         engage_description  AS "engageDescription",
         goal,
         approach,
         attack_technique_id AS "attackTechniqueId"
       FROM engage_mappings
       WHERE attack_technique_id = $1
       ORDER BY engage_id ASC`,
      [attackId],
    ),
    query<{ verisId: string }>(
      `SELECT veris_id AS "verisId"
       FROM veris_mappings
       WHERE attack_technique_id = $1
       ORDER BY veris_id ASC`,
      [attackId],
    ),
    query<{
      provider: string;
      controlId: string;
      controlName: string;
      controlDescription: string | null;
      mappingType: string | null;
    }>(
      `SELECT
         provider,
         control_id          AS "controlId",
         control_name        AS "controlName",
         control_description AS "controlDescription",
         mapping_type        AS "mappingType"
       FROM cloud_control_mappings
       WHERE attack_technique_id = $1
       ORDER BY provider ASC, control_id ASC`,
      [attackId],
    ),
  ]);

  res.status(200).json({
    attackId,
    nist: nistResult.rows,
    engage: engageResult.rows,
    verisCategories: verisResult.rows,
    cloudControls: cloudResult.rows,
  });
}

export default withHandler(handler, { cacheTtl: 3600 });
