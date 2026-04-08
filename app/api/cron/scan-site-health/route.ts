import { NextRequest, NextResponse } from 'next/server';
import { query } from '../../v1/lib/db.js';
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

    return NextResponse.json({ ok: true, ...stats, total });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('Site health scan error:', msg);
    return NextResponse.json({ ok: false, error: msg }, { status: 500 });
  }
}
