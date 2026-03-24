import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../v1/lib/db.js';
import { verifyCronAuth } from './lib/auth.js';

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

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== 'GET' && req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }
  if (!verifyCronAuth(req, res)) return;

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
       WHERE id = $3`,
      [recordsInserted, recordsSkipped, logId],
    );

    res.status(200).json({
      ok: true,
      source: 'cisa_kev',
      recordsInserted,
      recordsSkipped,
      totalInFeed: data.count,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('CISA KEV ingest error:', err);

    await query(
      `UPDATE feed_sync_log
       SET status = 'error', completed_at = NOW(), error_message = $1
       WHERE id = $2`,
      [msg, logId],
    );

    console.error('[cron] error:', msg);
    res.status(500).json({ ok: false, error: 'Feed sync failed' });
  }
}
