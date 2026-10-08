import { NextRequest } from 'next/server';
import { query } from '../../../lib/db';
import { jsonResponse, errorResponse } from '../../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../../lib/cors';
import { upstreamUrl } from '../../../../../../src/lib/emulation-plans.mjs';

export { OPTIONS };

const CACHE_TTL = 3600;
// Same shape as the CHECK on emulation_plans.plan_key.
const PLAN_KEY_RE = /^[a-z0-9-]{1,40}$/;

interface PlanHeader {
  id: string;
  planKey: string;
  name: string;
  groupAttackId: string;
  groupName: string | null;
  upstreamPlanId: string | null;
  attackVersion: string | null;
  sourcePath: string;
  sourceCommit: string | null;
  stepCount: number;
}

interface StepRow {
  ordinal: number;
  procedureStep: string | null;
  name: string;
  description: string | null;
  tacticRaw: string | null;
  upstreamAttackId: string | null;
  resolvedAttackId: string | null;
  resolution: 'exact' | 'deprecated' | 'revoked_replaced' | 'unresolved' | 'none';
  techniqueName: string | null;
  tactics: string[] | null;
  platforms: string[];
}

/**
 * GET /api/v1/frameworks/emulation/:planKey
 *
 * One plan and its steps in file order. Each step carries both the id the
 * plan wrote (`upstreamAttackId`) and the current one it resolved to
 * (`resolvedAttackId`), so a revoked-and-replaced id is visible as such; the
 * tactics come from the resolved technique, because the plans' own tactic
 * strings are inconsistent (kept as `tacticRaw`).
 */
export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ planKey: string }> },
) {
  const { planKey: raw } = await params;
  const planKey = raw.toLowerCase();
  if (!PLAN_KEY_RE.test(planKey)) {
    return withCors(errorResponse(400, 'Invalid plan key', 'VALIDATION_ERROR'));
  }

  let header: PlanHeader | undefined;
  try {
    header = (
      await query<PlanHeader>(
        `SELECT p.id, p.plan_key AS "planKey", p.name, p.attack_group_id AS "groupAttackId",
                g.name AS "groupName", p.upstream_plan_id AS "upstreamPlanId",
                p.attack_version AS "attackVersion", p.source_path AS "sourcePath",
                p.source_commit AS "sourceCommit",
                (SELECT count(*) FROM emulation_plan_steps s WHERE s.plan_id = p.id)::int AS "stepCount"
         FROM emulation_plans p
         LEFT JOIN threat_groups g ON g.attack_id = p.attack_group_id
         WHERE p.plan_key = $1`,
        [planKey],
      )
    ).rows[0];
  } catch (err) {
    if ((err as { code?: string }).code === '42P01') {
      return withCors(errorResponse(404, 'Emulation plans are not loaded on this deployment', 'NOT_FOUND'));
    }
    throw err;
  }
  if (!header) return withCors(errorResponse(404, 'Emulation plan not found', 'NOT_FOUND'));

  const steps = await query<StepRow>(
    `SELECT s.ordinal, s.procedure_step AS "procedureStep", s.name, s.description,
            s.tactic_raw AS "tacticRaw", s.attack_technique_id AS "upstreamAttackId",
            s.resolved_attack_id AS "resolvedAttackId", s.resolution,
            t.name AS "techniqueName",
            (SELECT array_agg(ta.name ORDER BY ta.sort_order)
               FROM technique_tactics tt JOIN tactics ta ON ta.id = tt.tactic_id
              WHERE tt.technique_id = t.id) AS tactics,
            s.platforms
     FROM emulation_plan_steps s
     LEFT JOIN techniques t ON t.id = s.technique_id
     WHERE s.plan_id = $1
     ORDER BY s.ordinal`,
    [header.id],
  );

  const { id: _id, ...plan } = header;
  return withCors(
    jsonResponse(
      {
        data: {
          ...plan,
          sourceUrl: upstreamUrl(plan.sourcePath, plan.sourceCommit),
          steps: steps.rows,
        },
      },
      CACHE_TTL,
    ),
  );
}
