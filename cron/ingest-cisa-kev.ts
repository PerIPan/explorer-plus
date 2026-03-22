import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../api/v1/_lib/db';

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

    for (const vuln of vulns) {
      // Use source_ref to store vendor/product info since there's no notes column
      const sourceRef = [vuln.vendorProject, vuln.product, vuln.vulnerabilityName]
        .filter(Boolean)
        .join(' | ');

      const result = await query(
        `INSERT INTO ioc_entries
           (type, value, source, malware_family, first_seen, source_ref)
         VALUES ('cve', $1, 'cisa_kev', NULL, $2, $3)
         ON CONFLICT (type, value, source) DO NOTHING
         RETURNING id`,
        [vuln.cveID, vuln.dateAdded || null, sourceRef || null],
      );

      if (result.rows.length > 0) {
        recordsInserted++;
      } else {
        recordsSkipped++;
      }
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

    res.status(500).json({ ok: false, error: msg });
  }
}
