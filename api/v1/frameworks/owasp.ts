import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../lib/db.js';
import { withHandler } from '../lib/middleware.js';

const VALID_FRAMEWORKS = ['web-2021', 'ml-2023', 'llm-2025'];

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const fw = Array.isArray(req.query.framework) ? req.query.framework[0] : req.query.framework;
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
          WHERE cm.technique_id IS NOT NULL AND cm.cwe_id = ANY(o.cwe_ids))::text AS technique_count,
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
    cweCount: r.cwe_ids.length,
    techniqueCount: parseInt(r.technique_count, 10),
    atlasCount: r.atlas_technique_ids.length,
    cveCount: parseInt(r.cve_count, 10),
  }));

  const frameworks = [...new Set(result.rows.map((r) => r.framework))].sort();
  res.status(200).json({ data, frameworks });
}

export default withHandler(handler, { cacheTtl: 3600 });
