import { NextRequest } from 'next/server';
import { query } from '../../../../lib/db.js';
import { jsonResponse, errorResponse } from '../../../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../../../lib/cors';
import { z } from 'zod';

export { OPTIONS };

const uuidSchema = z.string().uuid();

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ reportId: string }> }
) {
  const { reportId: raw } = await params;
  const parsed = uuidSchema.safeParse(raw);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Invalid reportId', 'VALIDATION_ERROR'));
  }
  const reportId = parsed.data;

  const result = await query<{ attackId: string; name: string }>(
    `SELECT t.attack_id AS "attackId", t.name
     FROM report_techniques rt
     JOIN techniques t ON t.id = rt.technique_id
     WHERE rt.report_id = $1
     ORDER BY t.attack_id ASC`,
    [reportId],
  );

  return withCors(jsonResponse({ data: result.rows }, 3600));
}
