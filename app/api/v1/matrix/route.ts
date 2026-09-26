import { NextRequest } from 'next/server';
import { query } from '../lib/db';
import { jsonResponse, errorResponse } from '../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../lib/cors';
import { domainSchema } from '../lib/validate';
import { z } from 'zod';

export { OPTIONS };

const querySchema = z.object({
  domain: domainSchema,
  sector: z.string().max(50).optional(),
});

export async function GET(req: NextRequest) {
  const rawParams: Record<string, string> = {};
  req.nextUrl.searchParams.forEach((v, k) => { rawParams[k] = v; });

  const parsed = querySchema.safeParse(rawParams);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Invalid query parameters', 'VALIDATION_ERROR'));
  }

  const { domain, sector } = parsed.data;

  // Tactics
  const tacticParams: unknown[] = [];
  const domainWhere = domain ? (() => { tacticParams.push(domain); return `WHERE domain = $${tacticParams.length}`; })() : '';

  const tacticsResult = await query<{
    id: string; attackId: string; name: string; description: string | null;
    sortOrder: number | null; domain: string | null;
  }>(
    `SELECT id, attack_id AS "attackId", name, description,
            sort_order AS "sortOrder", domain
     FROM tactics
     ${domainWhere}
     ORDER BY sort_order ASC NULLS LAST`,
    tacticParams,
  );

  if (tacticsResult.rows.length === 0) {
    return withCors(jsonResponse({ data: [] }, 1800));
  }

  /**
   * Parent techniques per tactic with group usage count.
   *
   * When a sector is applied, group usage is matched against the technique AND
   * its sub-techniques (`fam`). Without that, a group that only ever used
   * T1003.001 did not count towards T1003, and the HAVING below dropped T1003
   * from the sector's matrix altogether — measured on energy: its 17 groups use
   * 69 parent techniques directly and 136 sub-techniques, and 47 parents were
   * reachable ONLY through a sub. The sector lens was hiding 47 techniques its
   * own groups demonstrably use.
   *
   * The unfiltered path deliberately keeps the parent-only join, so the
   * heat values on the main matrix are unchanged by this fix.
   */
  const techParams: unknown[] = [];
  const domainTechCond = domain ? (() => { techParams.push(domain); return `AND t.domain = $${techParams.length}`; })() : '';

  const techniquesResult = await query<{
    tacticId: string; techId: string; attackId: string; name: string;
    groupUsageCount: string;
  }>(
    `SELECT
       tt.tactic_id   AS "tacticId",
       t.id           AS "techId",
       t.attack_id    AS "attackId",
       t.name,
       COUNT(DISTINCT ${sector ? 'CASE WHEN s.id IS NOT NULL THEN gt.group_id END' : 'gt.group_id'}) AS "groupUsageCount"
     FROM technique_tactics tt
     JOIN techniques t ON t.id = tt.technique_id
       AND t.is_subtechnique = false
       AND t.is_revoked = false
       AND t.is_deprecated = false
       ${domainTechCond}
     ${sector
       ? `LEFT JOIN techniques fam ON fam.id = t.id OR fam.parent_technique_id = t.id
     LEFT JOIN group_techniques gt ON gt.technique_id = fam.id`
       : `LEFT JOIN group_techniques gt ON gt.technique_id = t.id`}
     ${sector ? (() => { techParams.push(sector); return `LEFT JOIN group_sectors gs ON gs.group_id = gt.group_id LEFT JOIN sectors s ON s.id = gs.sector_id AND s.slug = $${techParams.length}`; })() : ''}
     GROUP BY tt.tactic_id, t.id, t.attack_id, t.name
     ${sector ? 'HAVING COUNT(DISTINCT CASE WHEN s.id IS NOT NULL THEN gt.group_id END) > 0' : ''}
     ORDER BY t.attack_id ASC`,
    techParams,
  );

  // Sub-techniques — sector-filtered when active
  const subParams: unknown[] = [];
  const subDomainFilter = domain ? (() => { subParams.push(domain); return `AND t.domain = $${subParams.length}`; })() : '';
  const subSectorFilter = sector
    ? (() => { subParams.push(sector); return `AND t.id IN (
        SELECT gt.technique_id FROM group_techniques gt
        JOIN group_sectors gs ON gs.group_id = gt.group_id
        JOIN sectors s ON s.id = gs.sector_id WHERE s.slug = $${subParams.length}
      )`; })()
    : '';

  const subTechResult = await query<{
    parentId: string; attackId: string; name: string;
  }>(
    `SELECT
       t.parent_technique_id AS "parentId",
       t.attack_id           AS "attackId",
       t.name
     FROM techniques t
     WHERE t.is_subtechnique = true
       AND t.is_revoked = false
       AND t.is_deprecated = false
       ${subDomainFilter}
       ${subSectorFilter}
     ORDER BY t.attack_id ASC`,
    subParams,
  );

  // Build sub-technique map keyed by parent UUID
  const subMap: Record<string, Array<{ attackId: string; name: string }>> = {};
  for (const sub of subTechResult.rows) {
    if (!subMap[sub.parentId]) subMap[sub.parentId] = [];
    subMap[sub.parentId].push({ attackId: sub.attackId, name: sub.name });
  }

  // Build tactic map
  const tacticMap: Record<string, typeof tacticsResult.rows[0]> = {};
  for (const t of tacticsResult.rows) tacticMap[t.id] = t;

  // Group techniques by tactic
  const colMap: Record<string, {
    tactic: typeof tacticsResult.rows[0];
    techniques: Array<{
      id: string; attackId: string; name: string;
      groupUsageCount: number;
      subTechniques: Array<{ attackId: string; name: string }>;
    }>;
  }> = {};

  for (const t of techniquesResult.rows) {
    if (!colMap[t.tacticId]) {
      colMap[t.tacticId] = { tactic: tacticMap[t.tacticId], techniques: [] };
    }
    colMap[t.tacticId].techniques.push({
      id: t.techId,
      attackId: t.attackId,
      name: t.name,
      groupUsageCount: parseInt(t.groupUsageCount, 10),
      subTechniques: subMap[t.techId] ?? [],
    });
  }

  // Assemble ordered columns
  const matrix = tacticsResult.rows
    .filter((ta) => colMap[ta.id])
    .map((ta) => ({
      tactic: {
        attackId: ta.attackId,
        name: ta.name,
        description: ta.description,
        sortOrder: ta.sortOrder,
        domain: ta.domain,
      },
      techniques: colMap[ta.id].techniques,
    }));

  /**
   * What a sector filter HIDES, stated rather than left to be inferred.
   *
   * `?sector=` is not a highlight: the query drops a technique entirely unless
   * some group attributed to that sector is recorded using it
   * (HAVING ... > 0 above). ATT&CK's group-to-sector attribution is sparse, so
   * the drop is large and uneven — energy/enterprise shows 75 of 254
   * technique-tactic cells — and a reader sees only the smaller number with
   * nothing to compare it against. A technique missing here may simply have no
   * attributed group yet, which is not the same as being irrelevant to the
   * sector, and the difference matters when the matrix is read as coverage.
   *
   * One extra count, measured at ~20ms, and only when a sector is applied.
   */
  let meta: Record<string, unknown> | undefined;
  if (sector) {
    const totalParams: unknown[] = [];
    const totalDomainCond = domain
      ? (() => { totalParams.push(domain); return `AND t.domain = $${totalParams.length}`; })()
      : '';
    const totalResult = await query<{ total: string }>(
      `SELECT COUNT(*) AS total
         FROM technique_tactics tt
         JOIN techniques t ON t.id = tt.technique_id
          AND t.is_subtechnique = false
          AND t.is_revoked = false
          AND t.is_deprecated = false
          ${totalDomainCond}`,
      totalParams,
    );
    const shown = techniquesResult.rows.length;
    const total = parseInt(totalResult.rows[0].total, 10);
    meta = {
      sector,
      techniquesShown: shown,
      techniquesTotal: total,
      techniquesHidden: total - shown,
      basis:
        'A sector filter keeps only techniques used by a threat group attributed to that sector. A hidden technique may have no attributed group yet rather than being irrelevant to the sector.',
    };
  }

  return withCors(jsonResponse(meta ? { data: matrix, meta } : { data: matrix }, 1800));
}
