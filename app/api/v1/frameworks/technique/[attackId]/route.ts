import { NextRequest } from 'next/server';
import { query } from '../../../lib/db';
import { jsonResponse, errorResponse } from '../../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../../lib/cors';
import { attackIdSchema } from '../../../lib/validate';

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

  const [nistResult, engageResult, verisResult, cloudResult, owaspCweResult, owaspAtlasResult, csfResult] = await Promise.all([
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
    // NIST CSF v2 subcategories that cover this technique
    query<{ subcategoryId: string; name: string; function: string; functionName: string; categoryId: string; categoryName: string }>(
      `SELECT DISTINCT
         m.subcategory_id  AS "subcategoryId",
         s.name,
         s.function,
         s.function_name   AS "functionName",
         s.category_id     AS "categoryId",
         s.category_name   AS "categoryName"
       FROM csf_technique_mappings m
       JOIN csf_subcategories s ON s.subcategory_id = m.subcategory_id AND s.version = '2.0'
       WHERE m.attack_technique_id = $1 AND m.is_draft = FALSE
       ORDER BY m.subcategory_id`,
      [attackId],
    ),
  ]);

  const owaspRows = [...owaspCweResult.rows, ...owaspAtlasResult.rows];
  const owaspMap = new Map(owaspRows.map(r => [`${r.categoryId}-${r.framework}`, r]));
  const owasp = [...owaspMap.values()];

  return withCors(jsonResponse({
    attackId,
    nist: nistResult.rows,
    engage: engageResult.rows,
    verisCategories: verisResult.rows,
    cloudControls: cloudResult.rows,
    owasp,
    csf: csfResult.rows,
  }, 3600));
}
