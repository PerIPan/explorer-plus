import { NextRequest } from 'next/server';
import { query } from '../../../../lib/db';
import { jsonResponse, errorResponse } from '../../../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../../../lib/cors';

export { OPTIONS };

const CSF_ID_RE = /^(GV|ID|PR|DE|RS|RC)\.[A-Z]{2}-\d{2}$/;

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ subcategoryId: string }> },
) {
  const { subcategoryId: raw } = await params;
  const subcategoryId = raw.toUpperCase();

  if (!CSF_ID_RE.test(subcategoryId)) {
    return withCors(errorResponse(400, 'Invalid subcategory ID', 'VALIDATION_ERROR'));
  }

  const result = await query<{ attackId: string }>(
    `SELECT DISTINCT attack_technique_id AS "attackId"
     FROM csf_technique_mappings
     WHERE subcategory_id = $1 AND is_draft = FALSE
     ORDER BY attack_technique_id`,
    [subcategoryId],
  );

  return withCors(jsonResponse({ techniques: result.rows }, 3600));
}
