import { NextRequest } from 'next/server';
import { query } from '../../lib/db';
import { jsonResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';

export { OPTIONS };

const CACHE_TTL = 3600;

interface Row {
  theme: string;
  control: string;
  attackId: string;
  name: string;
}

interface IsoControl {
  control: string;
  techniques: Array<{ attackId: string; name: string }>;
}

interface IsoThemeGroup {
  theme: string;
  controls: IsoControl[];
}

// ISO/IEC 27001:2022 Annex A themes, in canonical order, then the Mandatory
// Clauses. Anything unexpected falls through to the end alphabetically.
const THEME_ORDER = ['Annex A Controls', 'Mandatory Clause'];

/**
 * GET /api/v1/frameworks/iso27001
 *
 * ISO/IEC 27001:2022 controls mapped to ATT&CK techniques, surfaced through the
 * crosswalk already in the DB: ISO control ← csf_informative_references → CSF
 * subcategory → csf_technique_mappings → technique. Inference-free (these are
 * curated CSF↔ISO + CSF↔ATT&CK references), but we still drop revoked/deprecated
 * techniques for consistency with the rest of the site.
 */
export async function GET(_req: NextRequest) {
  const result = await query<Row>(
    `SELECT DISTINCT
       split_part(ir.target_id, ': ', 1) AS theme,
       split_part(ir.target_id, ': ', 2) AS control,
       t.attack_id                       AS "attackId",
       t.name
     FROM csf_informative_references ir
     JOIN csf_technique_mappings tm
       ON tm.subcategory_id = ir.subcategory_id AND tm.is_draft = FALSE
     JOIN techniques t
       ON t.id = tm.technique_id AND t.is_revoked = false AND t.is_deprecated = false
     WHERE ir.target_framework = 'iso-27001-2022'
       -- Drop placeholder refs with no specific control ("…: None", "…:")
       AND split_part(ir.target_id, ': ', 2) NOT IN ('', 'None')
     ORDER BY theme, control, "attackId"`,
  );

  const groups = new Map<string, Map<string, Array<{ attackId: string; name: string }>>>();
  const techniqueSet = new Set<string>();
  for (const r of result.rows) {
    const theme = r.theme || 'Other';
    const control = r.control || '(unspecified)';
    if (!groups.has(theme)) groups.set(theme, new Map());
    const controls = groups.get(theme)!;
    if (!controls.has(control)) controls.set(control, []);
    controls.get(control)!.push({ attackId: r.attackId, name: r.name });
    techniqueSet.add(r.attackId);
  }

  const data: IsoThemeGroup[] = Array.from(groups.entries())
    .map(([theme, controls]) => ({
      theme,
      controls: Array.from(controls.entries()).map(([control, techniques]) => ({ control, techniques })),
    }))
    .sort((a, b) => {
      const ia = THEME_ORDER.indexOf(a.theme);
      const ib = THEME_ORDER.indexOf(b.theme);
      if (ia !== ib) return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib);
      return a.theme.localeCompare(b.theme);
    });

  return withCors(jsonResponse({
    data,
    totalControls: data.reduce((n, g) => n + g.controls.length, 0),
    totalTechniques: techniqueSet.size,
  }, CACHE_TTL));
}
