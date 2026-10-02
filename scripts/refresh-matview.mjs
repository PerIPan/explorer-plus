#!/usr/bin/env node
// scripts/refresh-matview.mjs
//
// Standalone `REFRESH MATERIALIZED VIEW CONCURRENTLY` for one matview.
//
// WHY THIS EXISTS RATHER THAN THE CRON ROUTE
//
// app/api/cron/refresh-matviews/route.ts still owns the seven matviews that
// finish well inside a Vercel invocation. `osv_advisory_rank` does not, and it
// was failing roughly half the time:
//
//   2026-09-26  42.4s  ok        2026-09-29  15.8s  canceling statement due to
//   2026-09-27  46.0s  ok                           statement timeout
//   2026-09-28  15.8s  FAILED    2026-09-30  40.5s  ok
//                                2026-10-01  15.8s  FAILED
//
// Successes at 40-46s rule out a fixed 15s ceiling -- the cancel is
// intermittent, and it only ever lands on this matview because this is the
// longest statement the route runs (1,972,497 rows; 64s measured 2026-10-02
// from a plain pg client, and the route's own header records 90.2s). Its slot
// is also 19:00 UTC, the only matview slot at a busy hour; the other seven run
// 02:00-03:00. The exact provenance of the ~15s bound is NOT established --
// it is not `db.ts`'s `statement_timeout: 5000`, which Neon's pooler silently
// drops (SHOW statement_timeout = 0, source = default, on both the pooled and
// the direct endpoint), and no timeout-related variable exists in the Vercel
// project.
//
// What IS established is that the same statement on the same database from
// outside Vercel is reliable: GitHub Actions jobs here routinely hold single
// statements open for 35-373s, including the `app_technique_groups` refresh
// inside sync-cve-delta. So this runs there instead -- no 300s invocation cap
// to grow into either, which matters for a matview that gains ~70k rows per
// OSV delta.
//
// Triggered by .github/workflows/refresh-matview.yml.
//
// Rows land in feed_sync_log under source='matview_refresh' with the same
// `metadata.results` shape the route writes, so /feed-status and the
// per-matview health queries treat both producers identically -- and the
// route's 15-minute sweeper still cleans up after a killed run here.

import pg from 'pg';

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) { console.error('DATABASE_URL required'); process.exit(1); }

const arg = process.argv.slice(2).find((a) => a.startsWith('--mv='));
const requested = arg ? arg.slice('--mv='.length) : process.env.MATVIEW;
if (!requested) {
  console.error('usage: node scripts/refresh-matview.mjs --mv=<matview>   (or MATVIEW=<matview>)');
  process.exit(1);
}

async function main() {
  const pool = new pg.Pool({ connectionString: DATABASE_URL, keepAlive: true, max: 1 });
  const client = await pool.connect();
  let logId = null;
  try {
    // The name is interpolated into the REFRESH, which cannot take a bind
    // parameter -- so it is never taken from argv directly. Postgres is asked
    // whether a matview by that name exists and whether it carries the unique
    // index CONCURRENTLY requires, and the identifier that gets interpolated
    // is the one Postgres quotes back. An unknown name exits before any DDL,
    // and no allow-list is kept here to drift out of step with the route's.
    const found = await client.query(
      `SELECT quote_ident(c.relname) AS ident,
              EXISTS (
                SELECT 1 FROM pg_index i
                WHERE i.indrelid = c.oid AND i.indisunique
              ) AS has_unique_index
       FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
       WHERE c.relkind = 'm' AND c.relname = $1 AND n.nspname = current_schema()`,
      [requested],
    );
    if (found.rowCount === 0) {
      const known = await client.query(
        `SELECT matviewname FROM pg_matviews WHERE schemaname = current_schema() ORDER BY 1`,
      );
      throw new Error(
        `unknown matview "${requested}" -- known: ${known.rows.map((r) => r.matviewname).join(', ')}`,
      );
    }
    const { ident, has_unique_index: hasUniqueIndex } = found.rows[0];
    if (!hasUniqueIndex) {
      // Without one, CONCURRENTLY is rejected by Postgres. Failing here says
      // which matview and why, instead of surfacing the bare server error.
      throw new Error(`matview "${requested}" has no unique index; REFRESH ... CONCURRENTLY requires one`);
    }

    const r = await client.query(
      `INSERT INTO feed_sync_log (source, status, started_at)
       VALUES ('matview_refresh', 'running', NOW()) RETURNING id`,
    );
    logId = r.rows[0].id;

    const start = Date.now();
    await client.query(`REFRESH MATERIALIZED VIEW CONCURRENTLY ${ident}`);
    const durationMs = Date.now() - start;
    console.log(`[matview_refresh] ${requested} refreshed in ${durationMs}ms`);

    await client.query(
      `UPDATE feed_sync_log
       SET status='success', completed_at=NOW(),
           records_inserted=1, records_skipped=0, metadata=$1
       WHERE id=$2`,
      [
        JSON.stringify({
          trigger: 'github-actions',
          results: { [requested]: { ok: true, durationMs } },
        }),
        logId,
      ],
    );
  } catch (e) {
    const msg = e?.message ?? String(e);
    console.error(`[matview_refresh] ${requested} FAILED:`, e);
    if (logId) {
      try {
        await client.query(
          `UPDATE feed_sync_log
           SET status='error', completed_at=NOW(), error_message=$1,
               records_inserted=0, records_skipped=1, metadata=$2
           WHERE id=$3`,
          [
            msg.slice(0, 1000),
            JSON.stringify({
              trigger: 'github-actions',
              results: { [requested]: { ok: false, error: msg.slice(0, 200) } },
            }),
            logId,
          ],
        );
      } catch {}
    }
    process.exitCode = 1;
  } finally {
    client.release();
    await pool.end();
  }
}

main();
