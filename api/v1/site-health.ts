import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from './lib/db.js';
import { withHandler } from './lib/middleware.js';

async function handler(_req: VercelRequest, res: VercelResponse): Promise<void> {
  const result = await query<{
    vt_malicious: number; vt_suspicious: number; vt_harmless: number;
    vt_undetected: number; vt_total: number; scanned_at: string;
  }>(
    `SELECT vt_malicious, vt_suspicious, vt_harmless, vt_undetected, vt_total, scanned_at
     FROM site_health ORDER BY scanned_at DESC LIMIT 1`,
  );

  if (result.rows.length === 0) {
    res.status(200).json({ available: false });
    return;
  }

  const r = result.rows[0];
  res.status(200).json({
    available: true,
    malicious: r.vt_malicious,
    suspicious: r.vt_suspicious,
    harmless: r.vt_harmless,
    undetected: r.vt_undetected,
    total: r.vt_total,
    scannedAt: r.scanned_at,
    reportUrl: 'https://www.virustotal.com/gui/domain/mitre-explorer.org',
  });
}

export default withHandler(handler, { cacheTtl: 3600 });
