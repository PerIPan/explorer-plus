import { NextRequest, NextResponse } from 'next/server';
import { createGunzip } from 'node:zlib';
import { pipeline } from 'node:stream/promises';
import { Readable, Writable } from 'node:stream';
import { query } from '../../v1/lib/db';
import { verifyCronAuth } from '../lib/auth';
import { withSoftTimeout, DEFAULT_SOFT_TIMEOUT_MS } from '../lib/softTimeout';

export const maxDuration = 300;

const EPSS_URL = 'https://epss.cyentia.com/epss_scores-current.csv.gz';
const BATCH_SIZE = 1000;

export async function GET(req: NextRequest) {
  const authError = verifyCronAuth(req);
  if (authError) return authError;

  // Stale cleanup
  await query(
    `UPDATE feed_sync_log
     SET status = 'error', completed_at = NOW(), error_message = 'Timed out (auto-cleaned)'
     WHERE source = 'epss' AND status = 'running' AND started_at < NOW() - INTERVAL '15 minutes'`,
  );

  const logResult = await query<{ id: string }>(
    `INSERT INTO feed_sync_log (source, status, started_at)
     VALUES ('epss', 'running', NOW()) RETURNING id`,
  );
  const logId = logResult.rows[0].id;

  let rowsUpdated = 0;
  let rowsSkippedUnknown = 0;
  let rowsSkippedMalformed = 0;
  let modelDate: string | null = null;

  const doWork = async (): Promise<NextResponse> => {
    const resp = await fetch(EPSS_URL);
    if (!resp.ok) throw new Error(`EPSS fetch failed: ${resp.status}`);
    if (!resp.body) throw new Error('EPSS response body is null');

    let buffer = '';
    let headerSkipped = false;
    let batch: Array<{ cve: string; score: number; percentile: number }> = [];

    // UPDATE-only via VALUES CTE. Never creates new cve_details rows —
    // EPSS should only enrich rows that already exist (CVEs not in our DB
    // are silently dropped; rowsSkippedUnknown tracks how many).
    const flush = async () => {
      if (batch.length === 0) return;
      const values = batch
        .map((_, i) =>
          `($${i * 4 + 1}::text, $${i * 4 + 2}::numeric, $${i * 4 + 3}::numeric, $${i * 4 + 4}::timestamptz)`,
        )
        .join(', ');
      const params = batch.flatMap((r) => [r.cve, r.score, r.percentile, modelDate]);
      const result = await query(
        `WITH incoming(cve_id, epss_score, epss_percentile, epss_updated_at) AS (
           VALUES ${values}
         )
         UPDATE cve_details cd
         SET epss_score      = incoming.epss_score,
             epss_percentile = incoming.epss_percentile,
             epss_updated_at = incoming.epss_updated_at,
             updated_at      = NOW()
         FROM incoming
         WHERE cd.cve_id = incoming.cve_id`,
        params,
      );
      rowsUpdated += result.rowCount ?? 0;
      rowsSkippedUnknown += batch.length - (result.rowCount ?? 0);
      batch = [];
    };

    const writer = new Writable({
      async write(chunk, _enc, cb) {
        try {
          buffer += chunk.toString('utf8');
          const lines = buffer.split('\n');
          buffer = lines.pop() ?? '';
          for (const raw of lines) {
            const line = raw.trim();
            if (!line) continue;
            if (line.startsWith('#')) {
              const m = line.match(/score_date:([0-9T:+\-.]+)/);
              if (m) modelDate = m[1];
              continue;
            }
            if (!headerSkipped) { headerSkipped = true; continue; }
            const [cve, score, pct] = line.split(',');
            if (!cve || !cve.startsWith('CVE-') || isNaN(parseFloat(score))) {
              rowsSkippedMalformed++;
              continue;
            }
            batch.push({ cve, score: parseFloat(score), percentile: parseFloat(pct) });
            if (batch.length >= BATCH_SIZE) await flush();
          }
          cb();
        } catch (err) {
          cb(err as Error);
        }
      },
    });

    // fetch() returns WHATWG ReadableStream; bridge to Node Readable for pipeline().
    await pipeline(
      Readable.fromWeb(resp.body as unknown as Parameters<typeof Readable.fromWeb>[0]),
      createGunzip(),
      writer,
    );
    await flush();

    // FIRST.org publishes the score_date in a `#` comment on the first
    // line. If they ever rotate the format, modelDate stays null and every
    // EPSS row gets a NULL date — silent data-quality regression. Refuse
    // to mark the run successful in that case.
    if (!modelDate) {
      throw new Error('EPSS feed missing score_date comment header — every row would write NULL model_date; refusing to commit run as success');
    }

    await query(
      `UPDATE feed_sync_log
       SET status = 'success', completed_at = NOW(),
           records_inserted = $1, records_skipped = $2,
           metadata = $3
       WHERE id = $4 AND status = 'running'`,
      [
        rowsUpdated,
        rowsSkippedUnknown + rowsSkippedMalformed,
        JSON.stringify({ modelDate, rowsSkippedUnknown, rowsSkippedMalformed }),
        logId,
      ],
    );

    return NextResponse.json({
      ok: true,
      source: 'epss',
      rowsUpdated,
      rowsSkippedUnknown,
      rowsSkippedMalformed,
      modelDate,
    });
  };

  try {
    return await withSoftTimeout(doWork, DEFAULT_SOFT_TIMEOUT_MS);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('EPSS sync error:', err);
    await query(
      `UPDATE feed_sync_log
       SET status = 'error', completed_at = NOW(), error_message = $1,
           records_inserted = $2, records_skipped = $3
       WHERE id = $4 AND status = 'running'`,
      [msg.slice(0, 500), rowsUpdated, rowsSkippedUnknown + rowsSkippedMalformed, logId],
    );
    return NextResponse.json({ ok: false, error: 'EPSS sync failed' }, { status: 500 });
  }
}
