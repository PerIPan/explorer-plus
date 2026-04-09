import { NextRequest } from 'next/server';
import { query } from '../lib/db';
import { jsonResponse } from '../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../lib/cors';

export { OPTIONS };

export async function GET(_req: NextRequest) {
  const result = await query<{
    vt_malicious: number; vt_suspicious: number; vt_harmless: number;
    vt_undetected: number; vt_total: number; scanned_at: string;
  }>(
    `SELECT vt_malicious, vt_suspicious, vt_harmless, vt_undetected, vt_total, scanned_at
     FROM site_health ORDER BY scanned_at DESC LIMIT 1`,
  );

  if (result.rows.length === 0) {
    return withCors(jsonResponse({ available: false }, 3600));
  }

  const r = result.rows[0];
  return withCors(jsonResponse({
    available: true,
    malicious: r.vt_malicious,
    suspicious: r.vt_suspicious,
    harmless: r.vt_harmless,
    undetected: r.vt_undetected,
    total: r.vt_total,
    scannedAt: r.scanned_at,
    reportUrl: 'https://www.virustotal.com/gui/domain/mitre-explorer.org',
  }, 3600));
}
