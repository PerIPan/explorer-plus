import { NextRequest, NextResponse } from 'next/server';
import { query } from '../../v1/lib/db';
import { verifyCronAuth } from '../lib/auth';
import { withSoftTimeout, DEFAULT_SOFT_TIMEOUT_MS } from '../lib/softTimeout';

export const maxDuration = 300;

/**
 * Periodic refresh of materialized views.
 *
 * Individual ingest crons do NOT refresh matviews — that would couple the
 * ingest lifecycle to view maintenance and force every new cron author to
 * remember to add a refresh call. Instead, this cron runs twice daily (06:00,
 * 18:00 UTC, after the CVE syncs) and refreshes every matview in the list
 * below. To add a new matview, extend MATVIEWS.
 *
 * REFRESH MATERIALIZED VIEW CONCURRENTLY is non-blocking for readers and
 * requires a unique index on the matview — already present on all entries
 * below.
 */
const MATVIEWS = [
  // Refreshed first: the ~10-row catch-all CWE lookup that the inference hot
  // paths (app/api/v1/lib/inference.ts notCatchallCwe) read on every request.
  'catchall_cwes',
  'app_technique_groups',
  'package_summary',
  // Threat Profile ranking. sector_technique_lift is only as fresh as the last
  // sector_extractor run — see the staleness contract in the spec.
  'sector_technique_lift',
  'technique_cve_evidence',
  // Public-API aggregates. See scripts/migrate-ecosystem-stats.sql and
  // scripts/migrate-advisory-rank.sql.
  //
  // ecosystem_advisory_days MUST be here: /api/v1/ecosystems reads whole UTC
  // days out of it and computes only the sub-day boundary remainder live, so a
  // frozen day matview would make `last14dCount` shrink by one day, every day,
  // reporting a window that ended whenever the migration ran. No ordering
  // dependency between it and ecosystem_advisory_stats — neither reads the
  // other — but they are the same endpoint so they are kept adjacent.
  'ecosystem_advisory_days',
  'ecosystem_advisory_stats',
  // The expensive one: 1.9M rows built off a per-row cve_details LATERAL, 90.2s
  // to refresh. It has its OWN daily cron slot at 06:45 — an hour after the OSV
  // delta, which runs from GitHub Actions (.github/workflows/sync-osv.yml,
  // every 2 days at 05:30 plus a monthly full), NOT from vercel.json. Commit
  // 564d6e7 moved OSV and cve-products off Vercel deliberately, so an absence
  // here does not mean the source is static: the 2026-09-25 delta inserted
  // 82,948 rows.
  'osv_advisory_rank',
];

export async function GET(req: NextRequest) {
  const authError = verifyCronAuth(req);
  if (authError) return authError;

  /**
   * One matview per cron slot — see the `crons` block in vercel.json.
   *
   * Measured against Neon 2026-09-26, REFRESH ... CONCURRENTLY, seconds:
   *   catchall_cwes 0.3 · sector_technique_lift 0.2 · technique_cve_evidence 4.2
   *   package_summary 2.3 · app_technique_groups 28.1 · ecosystem_advisory_days 10.9
   *   ecosystem_advisory_stats 86.5 · osv_advisory_rank 90.2     TOTAL ~222.6
   *
   * All eight in one invocation is 222.6s against `maxDuration = 300` — 74% of
   * budget, measured from a low-latency connection with no concurrent load, so
   * the real margin is thinner. An overrun kills the function mid-REFRESH: the
   * work rolls back, the log row sits 'running' until the 15-minute sweeper
   * relabels it, and WHICH matviews went stale is recorded nowhere. Separate
   * staggered slots remove the ceiling instead of budgeting against it.
   *
   * Omitting `mv` still refreshes everything, so a manual catch-up run is
   * unchanged.
   */
  const requested = req.nextUrl.searchParams.get('mv');
  if (requested !== null && !MATVIEWS.includes(requested)) {
    return NextResponse.json(
      { error: `Unknown matview: ${requested}`, known: MATVIEWS },
      { status: 400 },
    );
  }
  const targets = requested ? [requested] : MATVIEWS;

  // Clean up stale 'running' entries (timed-out previous runs)
  await query(
    `UPDATE feed_sync_log
     SET status = 'error', completed_at = NOW(), error_message = 'Timed out (auto-cleaned)'
     WHERE source = 'matview_refresh' AND status = 'running' AND started_at < NOW() - INTERVAL '15 minutes'`,
  );

  const logResult = await query<{ id: string }>(
    `INSERT INTO feed_sync_log (source, status, started_at)
     VALUES ('matview_refresh', 'running', NOW())
     RETURNING id`,
  );
  const logId = logResult.rows[0].id;

  let refreshed = 0;
  let failed = 0;
  const results: Record<string, { ok: boolean; durationMs?: number; error?: string }> = {};

  const doWork = async (): Promise<NextResponse> => {
    for (const mv of targets) {
      const start = Date.now();
      try {
        await query(`REFRESH MATERIALIZED VIEW CONCURRENTLY ${mv}`);
        const durationMs = Date.now() - start;
        results[mv] = { ok: true, durationMs };
        refreshed++;
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        results[mv] = { ok: false, error: msg.slice(0, 200) };
        failed++;
        console.error(`[matview_refresh] ${mv} failed:`, msg);
      }
    }

    await query(
      `UPDATE feed_sync_log
       SET status = $1, completed_at = NOW(),
           records_inserted = $2, records_skipped = $3,
           metadata = $4
       WHERE id = $5 AND status = 'running'`,
      [
        failed === 0 ? 'success' : 'error',
        refreshed,
        failed,
        JSON.stringify({ results }),
        logId,
      ],
    );

    return NextResponse.json({
      ok: failed === 0,
      refreshed,
      failed,
      results,
    });
  };

  try {
    return await withSoftTimeout(doWork, DEFAULT_SOFT_TIMEOUT_MS);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('matview_refresh error:', err);
    await query(
      `UPDATE feed_sync_log
       SET status = 'error', completed_at = NOW(), error_message = $1,
           records_inserted = $2, records_skipped = $3,
           metadata = $4
       WHERE id = $5 AND status = 'running'`,
      [msg.slice(0, 500), refreshed, failed, JSON.stringify({ results }), logId],
    );
    return NextResponse.json({ ok: false, error: 'Matview refresh failed' }, { status: 500 });
  }
}
