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

  const [nistResult, engageResult, verisResult, cloudResult, owaspCweResult, owaspAtlasResult] = await Promise.all([
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
    // OWASP categories via CWE overlap (for ATT&CK techniques)
    query<{ categoryId: string; name: string; framework: string }>(
      `SELECT DISTINCT o.category_id AS "categoryId", o.name, o.framework
       FROM owasp_top10 o
       JOIN capec_mappings cm ON cm.cwe_id = ANY(o.cwe_ids)
       WHERE cm.attack_technique_id = $1 AND cm.technique_id IS NOT NULL
       ORDER BY o.framework, o.category_id`,
      [attackId],
    ),
    // OWASP categories via ATLAS (for ATLAS techniques)
    query<{ categoryId: string; name: string; framework: string }>(
      `SELECT category_id AS "categoryId", name, framework
       FROM owasp_top10
       WHERE $1 = ANY(atlas_technique_ids)
       ORDER BY framework, category_id`,
      [attackId],
    ),
  ]);

  const owaspRows = [...owaspCweResult.rows, ...owaspAtlasResult.rows];
  const owaspMap = new Map(owaspRows.map(r => [`${r.categoryId}-${r.framework}`, r]));
  const owasp = [...owaspMap.values()];

  res.status(200).json({
    attackId,
    nist: nistResult.rows,
    engage: engageResult.rows,
    verisCategories: verisResult.rows,
    cloudControls: cloudResult.rows,
    owasp,
  });
}

export default withHandler(handler, { cacheTtl: 3600 });
