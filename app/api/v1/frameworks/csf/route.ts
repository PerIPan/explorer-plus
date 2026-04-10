import { NextRequest } from 'next/server';
import { query } from '../../lib/db';
import { jsonResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';

export { OPTIONS };

const CACHE_TTL = 3600;

interface CsfSubcategoryRow {
  function: string;
  functionName: string;
  subcategoryId: string;
  categoryId: string;
  categoryName: string;
  name: string;
  description: string | null;
  techniqueCount: string;
}

interface CsfSubcategoryItem {
  subcategoryId: string;
  categoryId: string;
  categoryName: string;
  name: string;
  description: string | null;
  techniqueCount: number;
}

interface CsfFunctionGroup {
  function: string;
  functionName: string;
  subcategories: CsfSubcategoryItem[];
}

/**
 * GET /api/v1/frameworks/csf
 * Returns all CSF v2 subcategories grouped by function (GV/ID/PR/DE/RS/RC),
 * each with its technique count.
 */
export async function GET(_req: NextRequest) {
  const result = await query<CsfSubcategoryRow>(
    `SELECT
       s.function,
       s.function_name       AS "functionName",
       s.subcategory_id      AS "subcategoryId",
       s.category_id         AS "categoryId",
       s.category_name       AS "categoryName",
       s.name,
       s.description,
       COUNT(m.id)           AS "techniqueCount"
     FROM csf_subcategories s
     LEFT JOIN csf_technique_mappings m
       ON m.subcategory_id = s.subcategory_id AND m.is_draft = FALSE
     WHERE s.version = '2.0'
     GROUP BY s.id, s.function, s.function_name, s.subcategory_id, s.category_id, s.category_name, s.name, s.description
     ORDER BY s.function, s.subcategory_id`,
  );

  const groups: Record<string, CsfFunctionGroup> = {};
  for (const r of result.rows) {
    if (!groups[r.function]) {
      groups[r.function] = { function: r.function, functionName: r.functionName, subcategories: [] };
    }
    groups[r.function].subcategories.push({
      subcategoryId: r.subcategoryId,
      categoryId: r.categoryId,
      categoryName: r.categoryName,
      name: r.name,
      description: r.description,
      techniqueCount: parseInt(r.techniqueCount, 10),
    });
  }

  const data = ['GV', 'ID', 'PR', 'DE', 'RS', 'RC']
    .map((fn) => groups[fn])
    .filter((g): g is CsfFunctionGroup => Boolean(g));

  return withCors(jsonResponse({ data, total: result.rows.length }, CACHE_TTL));
}
