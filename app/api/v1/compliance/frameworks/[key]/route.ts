import { NextRequest } from 'next/server';
import { query } from '../../../lib/db';
import { jsonResponse, errorResponse } from '../../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../../lib/cors';

export { OPTIONS };

// GET /api/v1/compliance/frameworks/<framework_key>
//
// Returns everything the framework detail page needs:
//   - framework metadata + coverage stats
//   - articles → ATT&CK techniques (grouped)
//   - top related frameworks by technique overlap
//
// Filters mappings to NOT is_unresolved (Decision 11).

interface RouteCtx { params: Promise<{ key: string }> }

interface RawRow {
  ref_id: string;
  scf_id: string;
  attack_id: string;
  technique_name: string | null;
  tactic: string | null;
  tactic_attack_id: string | null;
  parent_attack_id: string | null;
  parent_name: string | null;
  is_unresolved: boolean;
}

/** Extract a stable "section" / "article" prefix from an SCF ref_id. */
function extractSection(refId: string): string {
  if (!refId) return '(unspecified)';
  // "Article N[.something]" → "Article N"
  const art = refId.match(/^(Article\s+\d+)/i);
  if (art) return art[1];
  // CFR-style "164.NNN(a)..." → "164.NNN"
  const cfr = refId.match(/^(\d{3}\.\d+)/);
  if (cfr) return cfr[1];
  // Family-prefix "XX-NN.YY" → "XX"
  const family = refId.match(/^([A-Z]{2,4})-/);
  if (family) return family[1];
  // Numeric "1.2.3" → "1"
  const num = refId.match(/^(\d+)\./);
  if (num) return num[1];
  return refId.split(/[\s(]/)[0];
}

export async function GET(req: NextRequest, ctx: RouteCtx) {
  const { key } = await ctx.params;

  // Framework metadata
  const fwRes = await query<{
    framework_key: string; name: string; version: string | null;
    source_org: string; upstream_url: string; region: string; tier: number;
    license: string | null; short_blurb: string | null;
    scf_controls: number | null; techniques_total: number | null; techniques_filtered: number | null;
  }>(
    `SELECT f.framework_key, f.name, f.version, f.source_org, f.upstream_url,
            f.region, f.tier, f.license, f.short_blurb,
            c.scf_controls, c.techniques_total, c.techniques_filtered
     FROM scf_frameworks f
     LEFT JOIN scf_framework_coverage c USING (framework_key)
     WHERE f.framework_key = $1`,
    [key],
  );
  if (fwRes.rowCount === 0) return errorResponse(404, 'Framework not found', 'NOT_FOUND');
  const fw = fwRes.rows[0];

  // DISTINCT ON the (ref_id, attack_id, scf_id) tuple avoids Cartesian fan-out
  // when a control × technique pair appears via multiple framework refs. We
  // also pick a stable "primary tactic" by tactic.attack_id rather than UUID.
  const mappingsRes = await query<RawRow & {
    cve_count: number | null; has_kev: boolean | null;
    group_count: number | null;
  }>(
    `SELECT DISTINCT ON (fr.ref_id, fr.scf_id, m.attack_id)
            fr.ref_id, fr.scf_id, m.attack_id,
            t.name AS technique_name,
            ta.name AS tactic,
            ta.attack_id AS tactic_attack_id,
            tp.attack_id AS parent_attack_id,
            tp.name AS parent_name,
            m.is_unresolved,
            h.cve_count, h.has_kev, h.group_count
     FROM scf_framework_refs fr
     JOIN scf_attack_mappings m ON m.scf_id = fr.scf_id
     LEFT JOIN techniques t  ON t.attack_id = m.attack_id
     LEFT JOIN techniques tp ON tp.id = t.parent_technique_id
     LEFT JOIN scf_technique_heat h ON h.attack_id = m.attack_id
     LEFT JOIN LATERAL (
       SELECT tac.name, tac.attack_id
       FROM technique_tactics tt
       JOIN tactics tac ON tac.id = tt.tactic_id
       WHERE tt.technique_id = t.id
       ORDER BY tac.attack_id
       LIMIT 1
     ) ta ON TRUE
     WHERE fr.framework_key = $1 AND NOT m.is_unresolved
     ORDER BY fr.ref_id, fr.scf_id, m.attack_id`,
    [key],
  );

  // Group into articles (sections)
  type TechRef = {
    attack_id: string;
    technique_name: string | null;
    tactic: string | null;
    tactic_attack_id: string | null;
    parent_attack_id: string | null;
    parent_name: string | null;
    scf_id: string;
    cve_count: number;
    has_kev: boolean;
    group_count: number;
  };
  const bySection = new Map<string, Map<string, TechRef[]>>();
  const techToRefs = new Map<string, { technique_name: string | null; tactic: string | null; refs: Set<string> }>();
  const articleSet = new Set<string>();

  for (const row of mappingsRes.rows) {
    const section = extractSection(row.ref_id);
    articleSet.add(section);

    if (!bySection.has(section)) bySection.set(section, new Map());
    const inner = bySection.get(section)!;
    if (!inner.has(row.ref_id)) inner.set(row.ref_id, []);
    inner.get(row.ref_id)!.push({
      attack_id: row.attack_id,
      technique_name: row.technique_name,
      tactic: row.tactic,
      tactic_attack_id: row.tactic_attack_id,
      parent_attack_id: row.parent_attack_id,
      parent_name: row.parent_name,
      scf_id: row.scf_id,
      cve_count: Number(row.cve_count ?? 0),
      has_kev: Boolean(row.has_kev),
      group_count: Number(row.group_count ?? 0),
    });

    if (!techToRefs.has(row.attack_id)) {
      techToRefs.set(row.attack_id, { technique_name: row.technique_name, tactic: row.tactic, refs: new Set() });
    }
    techToRefs.get(row.attack_id)!.refs.add(row.ref_id);
  }

  // Section view: { section, technique_count, refs: [{ ref_id, techniques: [...] }] }
  const sections = [...bySection.entries()].map(([section, refMap]) => {
    const refsArray = [...refMap.entries()].map(([ref_id, techs]) => ({ ref_id, techniques: techs }));
    const allTechIds = new Set<string>();
    for (const r of refsArray) for (const t of r.techniques) allTechIds.add(t.attack_id);
    return {
      section,
      ref_count: refsArray.length,
      technique_count: allTechIds.size,
      refs: refsArray.sort((a, b) => a.ref_id.localeCompare(b.ref_id, undefined, { numeric: true })),
    };
  }).sort((a, b) => a.section.localeCompare(b.section, undefined, { numeric: true }));

  // Technique view
  const techniques = [...techToRefs.entries()].map(([attack_id, v]) => ({
    attack_id,
    technique_name: v.technique_name,
    tactic: v.tactic,
    refs: [...v.refs].sort((a, b) => a.localeCompare(b, undefined, { numeric: true })),
  })).sort((a, b) => a.attack_id.localeCompare(b.attack_id));

  // Related frameworks by overlap
  const overlapRes = await query<{
    other_key: string; name: string; technique_overlap: number; region: string; tier: number;
  }>(
    `SELECT o.fw_b AS other_key, f.name, o.technique_overlap, f.region, f.tier
     FROM scf_framework_overlap o JOIN scf_frameworks f ON f.framework_key = o.fw_b
     WHERE o.fw_a = $1
     UNION ALL
     SELECT o.fw_a AS other_key, f.name, o.technique_overlap, f.region, f.tier
     FROM scf_framework_overlap o JOIN scf_frameworks f ON f.framework_key = o.fw_a
     WHERE o.fw_b = $1
     ORDER BY technique_overlap DESC
     LIMIT 8`,
    [key],
  );

  return withCors(
    jsonResponse(
      {
        framework: fw,
        article_count: articleSet.size,
        sections,
        techniques,
        related: overlapRes.rows,
      },
      // Framework + SCF mapping data is static between deploys (refreshed via
      // sync-scf.yml twice yearly). 24h cache with 7d SWR cuts cold-invoke load
      // significantly on the heaviest framework pages.
      86400,
    ),
  );
}
