import { NextRequest } from 'next/server';
import { query } from '../../../../lib/db.js';
import { jsonResponse, errorResponse } from '../../../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../../../lib/cors';
import { z } from 'zod';

export { OPTIONS };

const controlIdSchema = z.string().regex(/^[A-Z]{2}-\d{1,3}$/);

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ controlId: string }> }
) {
  const { controlId: raw } = await params;
  const parsed = controlIdSchema.safeParse(raw);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Invalid controlId', 'VALIDATION_ERROR'));
  }
  const controlId = parsed.data;

  const result = await query<{ attackId: string; name: string }>(
    `SELECT t.attack_id AS "attackId", t.name
     FROM nist_controls nc
     JOIN techniques t ON t.id = nc.technique_id
     WHERE nc.control_id = $1
     ORDER BY t.attack_id ASC`,
    [controlId],
  );

  return withCors(jsonResponse({ data: result.rows }, 3600));
}
