/**
 * sync-emulation.mjs
 * Loads the CTID Adversary Emulation Library's YAML plans into
 * emulation_plans / emulation_plan_steps, resolving every step to an ATT&CK
 * technique.
 *
 * Usage:
 *   node scripts/sync-emulation.mjs <clone-root> [--dry-run]
 *   EMULATION_COMMIT=<sha> recorded as source_commit (the workflow sets it).
 * Requires: DATABASE_URL (not for --dry-run), pg and yaml installed.
 *   .github/workflows/sync-emulation.yml installs both per run, as
 *   sync-atomic.yml does — yaml is deliberately not a repo dependency.
 *
 * Which files, and which group each belongs to, is curation in
 * src/lib/emulation-plans.mjs; parsing is normalizePlan() there, tested by
 * scripts/lib/emulation-plans.test.mjs.
 *
 * WRITE STRATEGY
 * Everything in ONE transaction that first takes
 * pg_try_advisory_xact_lock(hashtext('sync-emulation')). Transaction-scoped on
 * purpose: a session lock is unreliable through Neon's pooler, and 375 rows is
 * nothing. If another run holds the lock this one logs `skipped` and exits 0.
 * Per plan: upsert the plan row, delete its steps, insert the new ones — full
 * replace, because upstream steps can disappear and an upsert would keep them.
 * Plans no longer in the registry are deleted. A missing plan file aborts the
 * whole run: a half-cloned repo must not empty the table.
 *
 * Re-run after any full `seed.py`: its TRUNCATE techniques ... CASCADE empties
 * emulation_plan_steps (see scripts/migrate-emulation-plans.sql).
 */

import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { EMULATION_PLANS, normalizePlan } from '../src/lib/emulation-plans.mjs';

const args = process.argv.slice(2);
const dryRun = args.includes('--dry-run');
const cloneRoot = args.find((a) => !a.startsWith('--'));
const sourceCommit = process.env.EMULATION_COMMIT?.trim() || null;

if (!cloneRoot) {
  console.error('usage: node scripts/sync-emulation.mjs <clone-root> [--dry-run]');
  process.exit(2);
}

/**
 * Follow revocation (revoked_by_stix_id -> techniques.stix_id) up to four hops
 * and take the deepest row per upstream id. Written with the postgres review
 * (2026-10-08); an id absent from the result has no techniques row at all.
 */
const RESOLVE_SQL = `
  WITH RECURSIVE chain AS (
    SELECT i.aid, t.id, t.attack_id, t.is_revoked, t.is_deprecated, t.revoked_by_stix_id, 0 AS depth
    FROM unnest($1::text[]) AS i(aid)
    JOIN techniques t ON t.attack_id = i.aid
    UNION ALL
    SELECT c.aid, t2.id, t2.attack_id, t2.is_revoked, t2.is_deprecated, t2.revoked_by_stix_id, c.depth + 1
    FROM chain c
    JOIN techniques t2 ON t2.stix_id = c.revoked_by_stix_id
    WHERE c.is_revoked AND c.depth < 4
  )
  SELECT DISTINCT ON (aid) aid, id, attack_id AS resolved_attack_id, is_revoked, is_deprecated, depth
  FROM chain
  ORDER BY aid, depth DESC`;

/**
 * @param {Map<string, {id: string, resolved_attack_id: string, is_revoked: boolean, is_deprecated: boolean, depth: number}>} resolved
 * @param {string | null} validId
 */
function resolveStep(resolved, validId) {
  if (!validId) return { technique_id: null, resolved_attack_id: null, resolution: 'none' };
  const r = resolved.get(validId);
  // Not in techniques at all, or a revocation chain that ends without a
  // live replacement.
  if (!r || r.is_revoked) return { technique_id: null, resolved_attack_id: null, resolution: 'unresolved' };
  if (r.depth > 0) return { technique_id: r.id, resolved_attack_id: r.resolved_attack_id, resolution: 'revoked_replaced' };
  if (r.is_deprecated) return { technique_id: r.id, resolved_attack_id: r.resolved_attack_id, resolution: 'deprecated' };
  return { technique_id: r.id, resolved_attack_id: r.resolved_attack_id, resolution: 'exact' };
}

async function loadPlans() {
  const { default: YAML } = await import('yaml');
  const out = [];
  for (const entry of EMULATION_PLANS) {
    const text = await readFile(join(cloneRoot, entry.path), 'utf8'); // throws if missing: abort, see header
    const normalized = normalizePlan(YAML.parse(text));
    for (const w of normalized.warnings) console.warn(`[sync-emulation] ${entry.planKey}: ${w}`);
    out.push({ entry, ...normalized });
  }
  return out;
}

/** @param {Awaited<ReturnType<typeof loadPlans>>} plans */
function summarize(plans) {
  const validIds = [...new Set(plans.flatMap((p) => p.steps.map((s) => s.validTechniqueId).filter(Boolean)))];
  console.log(
    `[sync-emulation] ${plans.length} plans, ${plans.reduce((n, p) => n + p.steps.length, 0)} steps, ` +
      `${validIds.length} distinct technique ids${sourceCommit ? ` @ ${sourceCommit.slice(0, 12)}` : ''}`,
  );
  return validIds;
}

async function main() {
  if (dryRun) {
    const plans = await loadPlans();
    summarize(plans);
    for (const p of plans) {
      const junk = p.steps.filter((s) => !s.validTechniqueId).length;
      console.log(`  ${p.entry.planKey.padEnd(14)} ${p.entry.attackGroupId}  ${String(p.steps.length).padStart(3)} steps  ${junk} without technique id`);
    }
    console.log('[sync-emulation] DRY-RUN: no database writes');
    return;
  }

  if (!process.env.DATABASE_URL) {
    console.error('DATABASE_URL environment variable is required');
    process.exit(1);
  }
  const { default: pg } = await import('pg');
  const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL, max: 1 });
  const client = await pool.connect();
  const startedAt = Date.now();
  /** @type {Record<string, number>} */
  const counters = { plans: 0, steps: 0, exact: 0, deprecated: 0, revoked_replaced: 0, unresolved: 0, none: 0, relinked: 0 };
  let logId = null;

  const logDone = async (status, errorMessage) => {
    if (!logId) return;
    await client.query(
      `UPDATE feed_sync_log
          SET status = $1, completed_at = NOW(), records_inserted = $2, records_skipped = $3,
              metadata = $4, error_message = $5
        WHERE id = $6`,
      [
        status,
        counters.steps,
        counters.unresolved + counters.none,
        JSON.stringify({ ...counters, elapsedMs: Date.now() - startedAt, sourceCommit, trigger: 'github-actions' }),
        errorMessage?.slice(0, 500) ?? null,
        logId,
      ],
    );
  };

  try {
    await client.query(
      `UPDATE feed_sync_log SET status = 'error', completed_at = NOW(),
              error_message = 'Stale (auto-cleaned on new run start)'
        WHERE source = 'emulation' AND status = 'running' AND started_at < NOW() - INTERVAL '2 hours'`,
    );
    logId = (
      await client.query(
        `INSERT INTO feed_sync_log (source, status, started_at) VALUES ('emulation', 'running', NOW()) RETURNING id`,
      )
    ).rows[0].id;

    // Parsed after the log row exists, so a missing file or broken YAML shows
    // up as a failed run on /cti/feed-status rather than only in the job log.
    const plans = await loadPlans();
    const validIds = summarize(plans);

    await client.query('BEGIN');
    const lock = await client.query(`SELECT pg_try_advisory_xact_lock(hashtext('sync-emulation')) AS ok`);
    if (!lock.rows[0].ok) {
      await client.query('ROLLBACK');
      console.warn('[sync-emulation] another run holds the lock — skipping');
      await logDone('skipped', 'another run holds the advisory lock');
      return;
    }

    const res = await client.query(RESOLVE_SQL, [validIds]);
    const resolved = new Map(res.rows.map((r) => [r.aid, r]));

    for (const p of plans) {
      const planRow = await client.query(
        `INSERT INTO emulation_plans
           (plan_key, name, attack_group_id, upstream_plan_id, attack_version, source_path, source_commit, step_count, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
         ON CONFLICT (plan_key) DO UPDATE SET
           name = EXCLUDED.name,
           attack_group_id = EXCLUDED.attack_group_id,
           upstream_plan_id = EXCLUDED.upstream_plan_id,
           attack_version = EXCLUDED.attack_version,
           source_path = EXCLUDED.source_path,
           source_commit = EXCLUDED.source_commit,
           step_count = EXCLUDED.step_count,
           updated_at = NOW()
         RETURNING id`,
        [
          p.entry.planKey, p.plan.name, p.entry.attackGroupId, p.plan.upstreamPlanId,
          p.plan.attackVersion, p.entry.path, sourceCommit, p.steps.length,
        ],
      );
      const planId = planRow.rows[0].id;
      await client.query('DELETE FROM emulation_plan_steps WHERE plan_id = $1', [planId]);

      const rows = p.steps.map((s) => {
        const r = resolveStep(resolved, s.validTechniqueId);
        counters[r.resolution] += 1;
        return {
          step_uid: s.stepUid,
          ordinal: s.ordinal,
          procedure_step: s.procedureStep,
          name: s.name,
          description: s.description,
          tactic_raw: s.tacticRaw,
          attack_technique_id: s.attackTechniqueId,
          technique_id: r.technique_id,
          resolved_attack_id: r.resolved_attack_id,
          resolution: r.resolution,
          platforms: s.platforms,
          cti_source: s.ctiSource,
        };
      });
      if (rows.length > 0) {
        await client.query(
          `INSERT INTO emulation_plan_steps
             (plan_id, step_uid, ordinal, procedure_step, name, description, tactic_raw,
              attack_technique_id, technique_id, resolved_attack_id, resolution, platforms, cti_source)
           SELECT $1, r.step_uid, r.ordinal, r.procedure_step, r.name, r.description, r.tactic_raw,
                  r.attack_technique_id, r.technique_id, r.resolved_attack_id, r.resolution,
                  COALESCE(r.platforms, '{}'), r.cti_source
           FROM jsonb_to_recordset($2::jsonb) AS r(
             step_uid text, ordinal int, procedure_step text, name text, description text, tactic_raw text,
             attack_technique_id text, technique_id uuid, resolved_attack_id text, resolution text,
             platforms text[], cti_source text)`,
          [planId, JSON.stringify(rows)],
        );
      }
      counters.plans += 1;
      counters.steps += rows.length;
    }

    // Registry is the source of truth for which plans exist.
    await client.query('DELETE FROM emulation_plans WHERE plan_key <> ALL($1::text[])', [
      EMULATION_PLANS.map((e) => e.planKey),
    ]);

    // Belt and braces: re-attach any linked step whose FK was nulled (a
    // technique row replaced since resolution). A no-op on a fresh load.
    const relink = await client.query(
      `UPDATE emulation_plan_steps s SET technique_id = t.id, updated_at = NOW()
         FROM techniques t
        WHERE t.attack_id = s.resolved_attack_id AND s.technique_id IS NULL
          AND s.resolution IN ('exact', 'deprecated', 'revoked_replaced')`,
    );
    counters.relinked = relink.rowCount ?? 0;

    await client.query('COMMIT');
    console.log('[sync-emulation] done:', counters);
    await logDone('success', null);
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    try {
      await logDone('error', err instanceof Error ? err.message : String(err));
    } catch (logErr) {
      console.error('[sync-emulation] also failed writing feed_sync_log:', logErr);
    }
    throw err;
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch((err) => {
  console.error('[sync-emulation] fatal:', err);
  process.exit(1);
});
