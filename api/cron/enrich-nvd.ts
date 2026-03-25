import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../v1/lib/db.js';
import { verifyCronAuth } from './lib/auth.js';
import { linkCveTechniquesViaCwe } from './lib/capec-bridge.js';

const NVD_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

interface NvdCvssData {
  baseScore: number;
  baseSeverity: string;
  vectorString: string;
}

interface NvdCvssMetric {
  source: string;
  type: string;
  cvssData: NvdCvssData;
}

interface NvdWeakness {
  source: string;
  type: string;
  description: Array<{ lang: string; value: string }>;
}

interface NvdCve {
  id: string;
  published: string;
  descriptions: Array<{ lang: string; value: string }>;
  metrics?: {
    cvssMetricV31?: NvdCvssMetric[];
  };
  weaknesses?: NvdWeakness[];
}

interface NvdResponse {
  vulnerabilities: Array<{ cve: NvdCve }>;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== 'GET' && req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }
  if (!verifyCronAuth(req, res)) return;

  const apiKey = process.env.NVD_API_KEY ?? null;
  const batchSize = apiKey ? 50 : 20;

  // Clean up stale "running" entries (timed-out previous runs)
  await query(
    `UPDATE feed_sync_log
     SET status = 'error', completed_at = NOW(), error_message = 'Timed out (auto-cleaned)'
     WHERE source = 'nvd' AND status = 'running' AND started_at < NOW() - INTERVAL '15 minutes'`,
  );

  const logResult = await query<{ id: string }>(
    `INSERT INTO feed_sync_log (source, status, started_at)
     VALUES ('nvd', 'running', NOW())
     RETURNING id`,
  );
  const logId = logResult.rows[0].id;

  let recordsInserted = 0;
  let recordsSkipped = 0;

  try {
    // Find CVEs needing enrichment
    const pending = await query<{ cve_id: string }>(
      `SELECT DISTINCT i.value AS cve_id
       FROM ioc_entries i
       LEFT JOIN cve_details cd ON cd.cve_id = i.value
       WHERE i.type = 'cve' AND cd.id IS NULL
       LIMIT $1`,
      [batchSize],
    );

    for (const row of pending.rows) {
      try {
        const url = `${NVD_BASE}?cveId=${row.cve_id}`;
        const headers: Record<string, string> = { 'User-Agent': 'mitre-explorer/1.0' };
        if (apiKey) headers['apiKey'] = apiKey;

        const resp = await fetch(url, { headers });

        if (!resp.ok) {
          console.error(`NVD API error for ${row.cve_id}: ${resp.status}`);
          recordsSkipped++;
          await sleep(2000);
          continue;
        }

        const data = (await resp.json()) as NvdResponse;
        const vulns = data.vulnerabilities ?? [];

        if (!vulns.length) {
          // CVE not in NVD yet — skip, will retry on next run
          recordsSkipped++;
          await sleep(1000);
          continue;
        }

        const cve = vulns[0].cve;

        // Extract English description
        const desc = cve.descriptions.find((d) => d.lang === 'en')?.value ?? null;

        // Extract primary CVSS v3.1 metrics
        const primaryCvss = cve.metrics?.cvssMetricV31?.find((m) => m.type === 'Primary')
          ?? cve.metrics?.cvssMetricV31?.[0]
          ?? null;

        const cvssScore = primaryCvss?.cvssData.baseScore ?? null;
        const cvssSeverity = primaryCvss?.cvssData.baseSeverity ?? null;
        const cvssVector = primaryCvss?.cvssData.vectorString ?? null;

        // Extract primary CWE
        const primaryWeakness = cve.weaknesses?.find((w) => w.type === 'Primary')
          ?? cve.weaknesses?.[0]
          ?? null;
        const rawCweId = primaryWeakness?.description.find((d) => d.lang === 'en')?.value ?? null;
        const cweId = rawCweId && /^CWE-\d+$/.test(rawCweId) ? rawCweId : null;

        const publishedAt = cve.published ?? null;

        // Upsert into cve_details
        await query(
          `INSERT INTO cve_details (cve_id, description, cvss_score, cvss_severity, cvss_vector, cwe_id, published_at, nvd_enriched_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
           ON CONFLICT (cve_id) DO UPDATE SET
             description = EXCLUDED.description,
             cvss_score = EXCLUDED.cvss_score,
             cvss_severity = EXCLUDED.cvss_severity,
             cvss_vector = EXCLUDED.cvss_vector,
             cwe_id = EXCLUDED.cwe_id,
             published_at = EXCLUDED.published_at,
             nvd_enriched_at = NOW(),
             updated_at = NOW()`,
          [row.cve_id, desc, cvssScore, cvssSeverity, cvssVector, cweId, publishedAt],
        );

        // Also update ioc_entries.description for inline subtitle
        if (desc) {
          await query(
            `UPDATE ioc_entries SET description = $1, updated_at = NOW() WHERE type = 'cve' AND value = $2`,
            [desc, row.cve_id],
          );
        }

        recordsInserted++;
        await sleep(apiKey ? 1000 : 6000); // NVD rate-limit: 50/30s w/ key, 5/30s without
      } catch (cveErr) {
        console.error(`Failed to enrich ${row.cve_id}:`, cveErr);
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

    // After NVD assigns CWE IDs, link CVEs to techniques via CAPEC bridge
    let techniquesLinked = 0;
    try {
      techniquesLinked = await linkCveTechniquesViaCwe();
    } catch (e) {
      console.warn('CAPEC bridge failed (non-fatal):', e instanceof Error ? e.message : e);
    }

    res.status(200).json({
      ok: true,
      source: 'nvd',
      recordsInserted,
      recordsSkipped,
      batchSize,
      pending: pending.rows.length,
      techniquesLinked,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('NVD enrich error:', err);

    await query(
      `UPDATE feed_sync_log
       SET status = 'error', completed_at = NOW(), error_message = $1
       WHERE id = $2`,
      [msg, logId],
    );

    res.status(500).json({ ok: false, error: 'NVD enrichment failed' });
  }
}
