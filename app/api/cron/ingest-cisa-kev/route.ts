import { NextRequest, NextResponse } from 'next/server';
import { query } from '../../v1/lib/db';
import { verifyCronAuth } from '../lib/auth';
import { linkCveTechniquesViaCwe } from '../lib/capec-bridge';
import { withSoftTimeout, DEFAULT_SOFT_TIMEOUT_MS } from '../lib/softTimeout';

export const maxDuration = 300;

const CISA_KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

interface CisaVuln {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
}

interface CisaKevResponse {
  catalogVersion: string;
  count: number;
  vulnerabilities: CisaVuln[];
}

export async function GET(req: NextRequest) {
  const authError = verifyCronAuth(req);
  if (authError) return authError;

  // Clean up stale "running" entries (timed-out previous runs)
  await query(
    `UPDATE feed_sync_log
     SET status = 'error', completed_at = NOW(), error_message = 'Timed out (auto-cleaned)'
     WHERE source = 'cisa_kev' AND status = 'running' AND started_at < NOW() - INTERVAL '15 minutes'`,
  );

  const logResult = await query<{ id: string }>(
    `INSERT INTO feed_sync_log (source, status, started_at)
     VALUES ('cisa_kev', 'running', NOW())
     RETURNING id`,
  );
  const logId = logResult.rows[0].id;

  let recordsInserted = 0;
  let recordsSkipped = 0;

  try {
    return await withSoftTimeout(async () => {
    const resp = await fetch(CISA_KEV_URL);
    if (!resp.ok) {
      throw new Error(`CISA KEV fetch failed: ${resp.status} ${resp.statusText}`);
    }

    const data = (await resp.json()) as CisaKevResponse;
    const vulns = data.vulnerabilities ?? [];

    // Batch insert in chunks of 100 to stay within Vercel timeout
    const BATCH_SIZE = 100;
    for (let i = 0; i < vulns.length; i += BATCH_SIZE) {
      const batch = vulns.slice(i, i + BATCH_SIZE);
      const values: string[] = [];
      const params: unknown[] = [];

      for (const vuln of batch) {
        const sourceRef = [vuln.vendorProject, vuln.product, vuln.vulnerabilityName]
          .filter(Boolean)
          .join(' | ');
        const desc = vuln.shortDescription?.trim() || null;
        const offset = params.length;
        values.push(`('cve', $${offset + 1}, 'cisa_kev', NULL, $${offset + 2}, $${offset + 3}, $${offset + 4})`);
        params.push(vuln.cveID, vuln.dateAdded || null, sourceRef || null, desc);
      }

      const result = await query<{ id: string; is_insert: boolean }>(
        `INSERT INTO ioc_entries (type, value, source, malware_family, first_seen, source_ref, description)
         VALUES ${values.join(', ')}
         ON CONFLICT (type, value, source) DO UPDATE SET description = EXCLUDED.description
         RETURNING id, (xmax = 0) AS is_insert`,
        params,
      );
      recordsInserted += result.rows.filter((r) => r.is_insert).length;
      recordsSkipped += batch.length - result.rows.filter((r) => r.is_insert).length;
    }

    await query(
      `UPDATE feed_sync_log
       SET status = 'success', completed_at = NOW(),
           records_inserted = $1, records_skipped = $2
       WHERE id = $3 AND status = 'running'`,
      [recordsInserted, recordsSkipped, logId],
    );

    // Reconcile is_kev in cve_details against the CURRENT feed snapshot.
    // KEV is a full catalog fetched whole each run, so we both set the flag on
    // current entries AND clear it on any CVE CISA has de-listed (the flag was
    // previously monotonic — never reset). Guarded by a sanity floor so a
    // partial/failed fetch can't wipe every flag.
    try {
      const kevCveIds = vulns.map((v) => v.cveID).filter(Boolean);
      if (kevCveIds.length > 500) {
        await query(
          `UPDATE cve_details SET is_kev = true
           WHERE cve_id = ANY($1::text[]) AND is_kev = false`,
          [kevCveIds],
        );
        await query(
          `UPDATE cve_details SET is_kev = false
           WHERE is_kev = true AND NOT (cve_id = ANY($1::text[]))`,
          [kevCveIds],
        );
      }
    } catch { /* cve_details may not exist yet */ }

    // Link new CVEs to techniques via CWE->CAPEC->ATT&CK bridge
    let techniquesLinked = 0;
    try {
      techniquesLinked = await linkCveTechniquesViaCwe();
    } catch (e) {
      console.warn('CAPEC bridge failed (non-fatal):', e instanceof Error ? e.message : e);
    }

    return NextResponse.json({
      ok: true,
      source: 'cisa_kev',
      recordsInserted,
      recordsSkipped,
      totalInFeed: data.count,
      techniquesLinked,
    });
    }, DEFAULT_SOFT_TIMEOUT_MS);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('CISA KEV ingest error:', err);

    await query(
      `UPDATE feed_sync_log
       SET status = 'error', completed_at = NOW(), error_message = $1
       WHERE id = $2 AND status = 'running'`,
      [msg.slice(0, 500), logId],
    );

    console.error('[cron] error:', msg);
    return NextResponse.json({ ok: false, error: 'Feed sync failed' }, { status: 500 });
  }
}
