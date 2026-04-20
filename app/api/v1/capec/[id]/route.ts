import { NextRequest } from 'next/server';
import { query } from '../../lib/db';
import { jsonResponse, errorResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';

export { OPTIONS };

const CAPEC_ID_RE = /^CAPEC-\d+$/;

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id: raw } = await params;
  const capecId = raw.toUpperCase();

  if (!CAPEC_ID_RE.test(capecId)) {
    return withCors(errorResponse(400, 'Invalid CAPEC ID', 'VALIDATION_ERROR'));
  }

  const patternResult = await query<{
    id: string;
    name: string;
    description: string | null;
    abstraction: string | null;
    status: string | null;
    likelihood: string | null;
    severity: string | null;
    prerequisites: string[] | null;
    resourcesRequired: string[] | null;
    skillsRequired: Record<string, string>;
    consequences: Record<string, string[]>;
    exampleInstances: string[] | null;
    cweIds: string[] | null;
  }>(
    `SELECT id, name, description, abstraction, status, likelihood, severity,
            prerequisites,
            resources_required   AS "resourcesRequired",
            skills_required      AS "skillsRequired",
            consequences,
            example_instances    AS "exampleInstances",
            cwe_ids              AS "cweIds"
     FROM capec_patterns WHERE id = $1 LIMIT 1`,
    [capecId],
  );

  if (patternResult.rows.length === 0) {
    return withCors(errorResponse(404, 'CAPEC pattern not found', 'NOT_FOUND'));
  }

  const pattern = patternResult.rows[0];

  const [mitigations, related, techniques] = await Promise.all([
    query<{ name: string | null; description: string | null }>(
      `SELECT m.name, m.description
       FROM capec_pattern_mitigations pm
       JOIN capec_mitigations m ON m.id = pm.mitigation_id
       WHERE pm.capec_id = $1
       ORDER BY m.name NULLS LAST`,
      [capecId],
    ),
    query<{ relatedCapecId: string; nature: string; name: string | null }>(
      `SELECT r.related_capec_id AS "relatedCapecId", r.nature, p.name
       FROM capec_related r
       LEFT JOIN capec_patterns p ON p.id = r.related_capec_id
       WHERE r.capec_id = $1
       ORDER BY r.nature, r.related_capec_id`,
      [capecId],
    ),
    // Linked ATT&CK techniques via existing capec_mappings bridge
    query<{ attackId: string; name: string }>(
      `SELECT DISTINCT t.attack_id AS "attackId", t.name
       FROM capec_mappings cm
       JOIN techniques t ON t.id = cm.technique_id
       WHERE cm.capec_id = $1
       ORDER BY t.attack_id`,
      [capecId],
    ),
  ]);

  return withCors(
    jsonResponse(
      {
        ...pattern,
        mitigations: mitigations.rows,
        related: related.rows,
        techniques: techniques.rows,
      },
      3600,
    ),
  );
}
