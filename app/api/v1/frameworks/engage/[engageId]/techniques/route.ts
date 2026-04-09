import { NextRequest } from 'next/server';
import { query } from '../../../../lib/db';
import { jsonResponse, errorResponse } from '../../../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../../../lib/cors';
import { z } from 'zod';

export { OPTIONS };

const engageIdSchema = z.string().regex(/^EA[CV]\d{4}$/);

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ engageId: string }> }
) {
  const { engageId: raw } = await params;
  const parsed = engageIdSchema.safeParse(raw);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Invalid engageId', 'VALIDATION_ERROR'));
  }
  const engageId = parsed.data;

  const result = await query<{ attackId: string; name: string }>(
    `SELECT t.attack_id AS "attackId", t.name
     FROM engage_mappings em
     JOIN techniques t ON t.id = em.technique_id
     WHERE em.engage_id = $1
     ORDER BY t.attack_id ASC`,
    [engageId],
  );

  return withCors(jsonResponse({ data: result.rows }, 3600));
}
