import { NextRequest } from 'next/server';
import { query } from '../../lib/db';
import { jsonResponse, errorResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';
import {
  EMULATION_REPO,
  EMULATION_LICENSE,
  NOT_INGESTED,
  upstreamUrl,
} from '../../../../../src/lib/emulation-plans.mjs';

export { OPTIONS };

const CACHE_TTL = 3600;
const GROUP_RE = /^G\d{4}$/;
const TECHNIQUE_RE = /^T\d{4}(\.\d{3})?$/;

interface PlanRow {
  planKey: string;
  name: string;
  groupAttackId: string;
  groupName: string | null;
  attackVersion: string | null;
  sourcePath: string;
  sourceCommit: string | null;
  stepCount: number;
  techniqueCount: number;
  unlinkedStepCount: number;
  groupTechniqueCount: number;
  overlapCount: number;
  familyOverlapCount: number;
}

/**
 * GET /api/v1/frameworks/emulation[?group=G0016][&technique=T1059]
 *
 * The CTID adversary emulation plans this site ingests, one row per plan.
 *
 * `overlapCount` / `groupTechniqueCount` is DERIVED, and named as such in the
 * UI: of the Enterprise techniques ATT&CK attributes to the plan's group, how
 * many the plan exercises (exact resolved id). `familyOverlapCount` counts
 * plan techniques whose parent family the group is known for — measured on
 * the 2026-10 STIX, APT29's plan matches 9 exactly but 17 by family, because
 * plans written at ATT&CK v8 and group attributions differ in sub-technique
 * granularity. Both are shown so neither reads as the whole story.
 *
 * Computed here rather than in the browser because the client's group data
 * follows the domain toggle (Sandworm has ICS techniques), and the number must
 * not move with it.
 *
 * `technique=` matches the technique and, for a parent id, its
 * sub-techniques, the same way the atomic-test rollup does.
 *
 * On a database without scripts/migrate-emulation-plans.sql applied the route
 * answers `available: false` with no plans instead of a 500.
 */
export async function GET(req: NextRequest) {
  const sp = req.nextUrl.searchParams;
  const group = sp.get('group')?.toUpperCase() ?? null;
  const technique = sp.get('technique')?.toUpperCase() ?? null;
  if (group !== null && !GROUP_RE.test(group)) {
    return withCors(errorResponse(400, 'Invalid group id (expected G0000)', 'VALIDATION_ERROR'));
  }
  if (technique !== null && !TECHNIQUE_RE.test(technique)) {
    return withCors(errorResponse(400, 'Invalid technique id (expected T0000 or T0000.000)', 'VALIDATION_ERROR'));
  }

  const meta = { repo: `https://github.com/${EMULATION_REPO}`, license: EMULATION_LICENSE, notIngested: NOT_INGESTED };

  let rows: PlanRow[];
  try {
    const result = await query<PlanRow>(
      `WITH group_tech AS (
         SELECT g.attack_id AS group_attack_id, t.attack_id
         FROM threat_groups g
         JOIN group_techniques gt ON gt.group_id = g.id
         JOIN techniques t ON t.id = gt.technique_id
         WHERE g.attack_id IN (SELECT attack_group_id FROM emulation_plans)
           AND t.domain = 'enterprise-attack' AND NOT t.is_revoked AND NOT t.is_deprecated
       ),
       plan_tech AS (
         SELECT DISTINCT plan_id, resolved_attack_id
         FROM emulation_plan_steps
         WHERE resolved_attack_id IS NOT NULL
       )
       SELECT
         p.plan_key         AS "planKey",
         p.name,
         p.attack_group_id  AS "groupAttackId",
         g.name             AS "groupName",
         p.attack_version   AS "attackVersion",
         p.source_path      AS "sourcePath",
         p.source_commit    AS "sourceCommit",
         p.step_count       AS "stepCount",
         (SELECT count(*) FROM plan_tech pt WHERE pt.plan_id = p.id)::int AS "techniqueCount",
         (SELECT count(*) FROM emulation_plan_steps s
           WHERE s.plan_id = p.id AND s.technique_id IS NULL)::int AS "unlinkedStepCount",
         (SELECT count(*) FROM group_tech gt
           WHERE gt.group_attack_id = p.attack_group_id)::int AS "groupTechniqueCount",
         (SELECT count(*) FROM plan_tech pt
            JOIN group_tech gt ON gt.attack_id = pt.resolved_attack_id AND gt.group_attack_id = p.attack_group_id
           WHERE pt.plan_id = p.id)::int AS "overlapCount",
         (SELECT count(*) FROM plan_tech pt
           WHERE pt.plan_id = p.id
             AND EXISTS (SELECT 1 FROM group_tech gt
                          WHERE gt.group_attack_id = p.attack_group_id
                            AND split_part(gt.attack_id, '.', 1) = split_part(pt.resolved_attack_id, '.', 1))
         )::int AS "familyOverlapCount"
       FROM emulation_plans p
       LEFT JOIN threat_groups g ON g.attack_id = p.attack_group_id
       WHERE ($1::text IS NULL OR p.attack_group_id = $1)
         AND ($2::text IS NULL OR EXISTS (
               SELECT 1 FROM emulation_plan_steps x
               WHERE x.plan_id = p.id
                 AND (x.resolved_attack_id = $2 OR x.resolved_attack_id LIKE $2 || '.%')))
       ORDER BY p.name`,
      [group, technique],
    );
    rows = result.rows;
  } catch (err) {
    if ((err as { code?: string }).code === '42P01') {
      return withCors(jsonResponse({ available: false, data: [], ...meta }, 300));
    }
    throw err;
  }

  return withCors(
    jsonResponse(
      {
        available: true,
        data: rows.map((r) => ({ ...r, sourceUrl: upstreamUrl(r.sourcePath, r.sourceCommit) })),
        total: rows.length,
        ...meta,
      },
      CACHE_TTL,
    ),
  );
}
