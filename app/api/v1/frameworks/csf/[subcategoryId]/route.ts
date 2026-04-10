import { NextRequest } from 'next/server';
import { query } from '../../../lib/db';
import { jsonResponse, errorResponse } from '../../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../../lib/cors';

export { OPTIONS };

const CACHE_TTL = 3600;
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

  const subResult = await query<{
    subcategoryId: string;
    function: string;
    functionName: string;
    categoryId: string;
    categoryName: string;
    categoryDescription: string | null;
    name: string;
    description: string | null;
  }>(
    `SELECT
       subcategory_id       AS "subcategoryId",
       function,
       function_name        AS "functionName",
       category_id          AS "categoryId",
       category_name        AS "categoryName",
       category_description AS "categoryDescription",
       name,
       description
     FROM csf_subcategories
     WHERE subcategory_id = $1 AND version = '2.0'
     LIMIT 1`,
    [subcategoryId],
  );

  if (subResult.rows.length === 0) {
    return withCors(errorResponse(404, 'Subcategory not found', 'NOT_FOUND'));
  }

  const sub = subResult.rows[0];

  // Core queries (must succeed)
  const [techniquesResult, relatedResult] = await Promise.all([
    query<{ attackId: string; name: string | null; tacticName: string | null }>(
      `SELECT
         m.attack_technique_id AS "attackId",
         MAX(t.name)           AS "name",
         MIN(tac.name)         AS "tacticName"
       FROM csf_technique_mappings m
       LEFT JOIN techniques t ON t.id = m.technique_id
       LEFT JOIN technique_tactics tt ON tt.technique_id = t.id
       LEFT JOIN tactics tac ON tac.id = tt.tactic_id
       WHERE m.subcategory_id = $1 AND m.is_draft = FALSE
       GROUP BY m.attack_technique_id
       ORDER BY m.attack_technique_id`,
      [subcategoryId],
    ),

    query<{ subcategoryId: string; name: string; function: string; sharedCount: string }>(
      `SELECT
         s.subcategory_id   AS "subcategoryId",
         s.name,
         s.function,
         COUNT(*)           AS "sharedCount"
       FROM csf_technique_mappings m2
       JOIN csf_subcategories s ON s.subcategory_id = m2.subcategory_id AND s.version = '2.0'
       WHERE m2.attack_technique_id IN (
         SELECT attack_technique_id FROM csf_technique_mappings
         WHERE subcategory_id = $1 AND is_draft = FALSE
       )
       AND m2.subcategory_id <> $1
       AND m2.is_draft = FALSE
       GROUP BY s.subcategory_id, s.name, s.function
       HAVING COUNT(*) >= 2
       ORDER BY COUNT(*) DESC, s.subcategory_id
       LIMIT 10`,
      [subcategoryId],
    ),
  ]);

  // Enrichment queries (Implementation Examples + Informative References).
  // Tables may not exist yet on environments where migrate-csf-enrichment.sql
  // hasn't been applied — degrade gracefully to empty arrays instead of 500.
  const [examplesResult, refsResult] = await Promise.all([
    query<{ exampleId: string; ordinal: number; text: string }>(
      `SELECT example_id AS "exampleId", ordinal, text
       FROM csf_implementation_examples
       WHERE subcategory_id = $1
       ORDER BY ordinal`,
      [subcategoryId],
    ).catch(() => ({ rows: [] as Array<{ exampleId: string; ordinal: number; text: string }> })),

    query<{ framework: string; id: string; text: string | null; relationship: string | null }>(
      `SELECT target_framework AS "framework", target_id AS "id",
              target_text AS "text", relationship
       FROM csf_informative_references
       WHERE subcategory_id = $1
       ORDER BY target_framework, target_id`,
      [subcategoryId],
    ).catch(() => ({ rows: [] as Array<{ framework: string; id: string; text: string | null; relationship: string | null }> })),
  ]);

  return withCors(
    jsonResponse(
      {
        ...sub,
        techniques: techniquesResult.rows,
        relatedSubcategories: relatedResult.rows.map((r) => ({
          ...r,
          sharedCount: parseInt(r.sharedCount, 10),
        })),
        implementationExamples: examplesResult.rows,
        informativeReferences: refsResult.rows,
      },
      CACHE_TTL,
    ),
  );
}
