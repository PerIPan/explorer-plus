import { NextRequest } from 'next/server';
import { query } from '../../lib/db';
import { jsonResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';
import { notCatchallCwe, liveTechnique } from '../../lib/inference';

export { OPTIONS };

const VALID_FRAMEWORKS = ['web-2021', 'ml-2023', 'llm-2025'];

export async function GET(req: NextRequest) {
  const fw = req.nextUrl.searchParams.get('framework');
  const frameworkFilter = fw && VALID_FRAMEWORKS.includes(fw) ? fw : null;

  const result = await query<{
    category_id: string; name: string; description: string | null;
    url: string | null; cwe_ids: string[]; framework: string;
    atlas_technique_ids: string[]; is_draft: boolean;
    technique_count: string; cve_count: string;
  }>(
    `WITH counts AS (
       SELECT o.id,
         (SELECT COUNT(DISTINCT cm.attack_technique_id)
          FROM capec_mappings cm
          WHERE cm.technique_id IS NOT NULL AND cm.cwe_id = ANY(o.cwe_ids) AND ${notCatchallCwe('cm.cwe_id')}
            AND EXISTS (SELECT 1 FROM techniques t WHERE t.id = cm.technique_id AND ${liveTechnique('t')}))::text AS technique_count,
         (SELECT COUNT(DISTINCT cw.cve_id)
          FROM cve_weaknesses cw
          WHERE cw.cwe_id = ANY(o.cwe_ids))::text AS cve_count
       FROM owasp_top10 o
     )
     SELECT o.category_id, o.name, o.description, o.url, o.cwe_ids,
            o.framework, o.atlas_technique_ids, o.is_draft,
            c.technique_count, c.cve_count
     FROM owasp_top10 o
     JOIN counts c ON c.id = o.id
     ${frameworkFilter ? 'WHERE o.framework = $1' : ''}
     ORDER BY o.framework, o.category_id`,
    frameworkFilter ? [frameworkFilter] : [],
  );

  const data = result.rows.map((r) => ({
    categoryId: r.category_id,
    name: r.name,
    description: r.description,
    url: r.url,
    framework: r.framework,
    isDraft: r.is_draft,
    cweIds: r.cwe_ids ?? [],
    cweCount: (r.cwe_ids ?? []).length,
    techniqueCount: parseInt(r.technique_count, 10),
    atlasCount: (r.atlas_technique_ids ?? []).length,
    cveCount: parseInt(r.cve_count, 10),
  }));

  const frameworks = [...new Set(result.rows.map((r) => r.framework))].sort();
  return withCors(jsonResponse({ data, frameworks }, 3600));
}
