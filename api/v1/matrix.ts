import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from './_lib/db';
import { withHandler } from './_lib/middleware';
import { z } from 'zod';

const querySchema = z.object({
  domain: z.string().optional(),
});

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const parsed = querySchema.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid query parameters', code: 'VALIDATION_ERROR' });
    return;
  }

  const { domain } = parsed.data;
  const params: unknown[] = [];
  const domainCondition = domain ? (() => { params.push(domain); return `AND ta.domain = $${params.length}`; })() : '';

  // Tactics
  const tacticsResult = await query<{
    id: string; attackId: string; name: string; description: string | null;
    sortOrder: number | null; domain: string | null;
  }>(
    `SELECT id, attack_id AS "attackId", name, description,
            sort_order AS "sortOrder", domain
     FROM tactics
     ${domain ? `WHERE domain = $1` : ''}
     ORDER BY sort_order ASC NULLS LAST`,
    params,
  );

  if (tacticsResult.rows.length === 0) {
    res.status(200).json({ data: [] });
    return;
  }

  // Parent techniques per tactic with group usage count
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
       COUNT(DISTINCT gt.group_id) AS "groupUsageCount"
     FROM technique_tactics tt
     JOIN techniques t ON t.id = tt.technique_id
       AND t.is_subtechnique = false
       AND t.is_revoked = false
       AND t.is_deprecated = false
       ${domainTechCond}
     LEFT JOIN group_techniques gt ON gt.technique_id = t.id
     GROUP BY tt.tactic_id, t.id, t.attack_id, t.name
     ORDER BY t.attack_id ASC`,
    techParams,
  );

  // Sub-techniques
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
     ORDER BY t.attack_id ASC`,
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

  res.status(200).json({ data: matrix });
}

export default withHandler(handler, { cacheTtl: 1800 });
