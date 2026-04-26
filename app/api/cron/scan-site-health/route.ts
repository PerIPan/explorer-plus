import { NextRequest, NextResponse } from 'next/server';
import { query } from '../../v1/lib/db';
import { verifyCronAuth } from '../lib/auth';

export const maxDuration = 300;

/**
 * Daily self-scan: checks mitre-explorer.org against VirusTotal.
 * Stores result in site_health table for the trust badge.
 */
const VT_DOMAIN_URL = 'https://www.virustotal.com/api/v3/domains/mitre-explorer.org';

export async function GET(req: NextRequest) {
  const authError = verifyCronAuth(req);
  if (authError) return authError;

  const apiKey = process.env.VT_API_KEY;
  if (!apiKey) {
    return NextResponse.json({ error: 'VT_API_KEY not configured' }, { status: 500 });
  }

  // Stale-row cleanup + new log row, so failures surface on Feed Status.
  await query(
    `UPDATE feed_sync_log
     SET status = 'error', completed_at = NOW(), error_message = 'Stale (auto-cleaned on new run start)'
     WHERE source = 'site_health' AND status = 'running' AND started_at < NOW() - INTERVAL '15 minutes'`,
  );
  const logResult = await query<{ id: string }>(
    `INSERT INTO feed_sync_log (source, status, started_at)
     VALUES ('site_health', 'running', NOW())
     RETURNING id`,
  );
  const logId = logResult.rows[0].id;

  try {
    const resp = await fetch(VT_DOMAIN_URL, {
      headers: { 'x-apikey': apiKey },
      signal: AbortSignal.timeout(10000),
    });

    if (!resp.ok) throw new Error(`VT API error: ${resp.status}`);

    const data = await resp.json() as {
      data: { attributes: { last_analysis_stats: { malicious: number; suspicious: number; harmless: number; undetected: number } } };
    };

    const stats = data.data.attributes.last_analysis_stats;
    const total = stats.malicious + stats.suspicious + stats.harmless + stats.undetected;

    await query(
      `INSERT INTO site_health (vt_malicious, vt_suspicious, vt_harmless, vt_undetected, vt_total)
       VALUES ($1, $2, $3, $4, $5)`,
      [stats.malicious, stats.suspicious, stats.harmless, stats.undetected, total],
    );

    await query(
      `UPDATE feed_sync_log
       SET status = 'success', completed_at = NOW(),
           records_inserted = 1, records_skipped = 0,
           metadata = $1
       WHERE id = $2 AND status = 'running'`,
      [JSON.stringify(stats), logId],
    );

    return NextResponse.json({ ok: true, ...stats, total });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('Site health scan error:', msg);
    await query(
      `UPDATE feed_sync_log
       SET status = 'error', completed_at = NOW(), error_message = $1
       WHERE id = $2 AND status = 'running'`,
      [msg.slice(0, 500), logId],
    );
    return NextResponse.json({ ok: false, error: msg }, { status: 500 });
  }
}
