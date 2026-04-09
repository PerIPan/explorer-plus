import { NextRequest } from 'next/server';
import { query } from '../../../../lib/db';
import { jsonResponse, errorResponse } from '../../../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../../../lib/cors';
import { z } from 'zod';

export { OPTIONS };

const uuidSchema = z.string().uuid();

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ iocId: string }> }
) {
  const { iocId: raw } = await params;
  const parsed = uuidSchema.safeParse(raw);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Invalid iocId', 'VALIDATION_ERROR'));
  }
  const iocId = parsed.data;

  const result = await query<{ attackId: string; name: string }>(
    `SELECT t.attack_id AS "attackId", t.name
     FROM technique_iocs ti
     JOIN techniques t ON t.id = ti.technique_id
     WHERE ti.ioc_id = $1
     ORDER BY t.attack_id ASC`,
    [iocId],
  );

  return withCors(jsonResponse({ data: result.rows }, 3600));
}
