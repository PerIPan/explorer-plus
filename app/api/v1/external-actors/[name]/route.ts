import { NextRequest } from 'next/server';
import { query } from '../../lib/db';
import { jsonResponse, errorResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';

export { OPTIONS };

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ name: string }> }
) {
  const { name: rawName } = await params;
  if (!rawName) {
    return withCors(errorResponse(400, 'Name parameter required', 'VALIDATION_ERROR'));
  }

  const name = decodeURIComponent(rawName);

  const result = await query<{
    id: string;
    name: string;
    description: string | null;
    source: string;
    country: string | null;
    category: string | null;
    synonyms: string[] | null;
    refs: string[] | null;
    mitreGroupId: string | null;
    mitreGroupName: string | null;
    motivation: string | null;
    firstSeen: string | null;
    suspectedVictims: string[] | null;
    targetCategories: string[] | null;
    suspectedStateSponsor: string | null;
    attributionConfidence: string | null;
  }>(
    `SELECT
       ea.id,
       ea.name,
       ea.description,
       ea.source,
       ea.country,
       ea.category,
       ea.synonyms,
       ea.refs,
       ea.mitre_group_id AS "mitreGroupId",
       tg.name           AS "mitreGroupName",
       ea.motivation,
       ea.first_seen AS "firstSeen",
       ea.suspected_victims AS "suspectedVictims",
       ea.target_categories AS "targetCategories",
       ea.suspected_state_sponsor AS "suspectedStateSponsor",
       ea.attribution_confidence AS "attributionConfidence"
     FROM external_actors ea
     LEFT JOIN threat_groups tg ON tg.attack_id = ea.mitre_group_id
     WHERE LOWER(ea.name) = LOWER($1)
     LIMIT 1`,
    [name],
  );

  if (result.rows.length === 0) {
    return withCors(errorResponse(404, 'Actor not found', 'NOT_FOUND'));
  }

  return withCors(jsonResponse(result.rows[0], 3600));
}
