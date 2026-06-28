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
];

export async function GET(req: NextRequest) {
  const authError = verifyCronAuth(req);
  if (authError) return authError;

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
    for (const mv of MATVIEWS) {
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
