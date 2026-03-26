import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../v1/lib/db.js';
import { verifyCronAuth } from './lib/auth.js';

const OTX_BASE = 'https://otx.alienvault.com/api/v1';
const MAX_PAGES = 1;       // Keep small — Vercel function timeout
const PULSES_PER_PAGE = 1; // Single pulse per run to avoid OTX 504 timeouts

interface OtxIndicator {
  type: string;
  indicator: string;
}

interface OtxPulse {
  id: string;
  name: string;
  description: string;
  created: string;
  modified: string;
  author_name: string;
  references: string[];
  attack_ids: Array<string | { id: string }>;
  indicators: OtxIndicator[];
}

interface OtxResponse {
  results: OtxPulse[];
  next: string | null;
  previous: string | null;
  count: number;
}

/** Map OTX indicator type → our ioc type */
function mapIocType(otxType: string): string | null {
  const map: Record<string, string> = {
    IPv4: 'ip',
    IPv6: 'ip',
    domain: 'domain',
    hostname: 'domain',
    URL: 'url',
    'FileHash-MD5': 'hash',
    'FileHash-SHA1': 'hash',
    'FileHash-SHA256': 'hash',
    CVE: 'cve',
    email: 'email',
  };
  return map[otxType] ?? null;
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== 'GET' && req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }
  if (!verifyCronAuth(req, res)) return;

  const apiKey = process.env.OTX_API_KEY;
  if (!apiKey) {
    res.status(500).json({ error: 'OTX_API_KEY not configured' });
    return;
  }

  // Clean up stale "running" entries (timed-out previous runs)
  await query(
    `UPDATE feed_sync_log
     SET status = 'error', completed_at = NOW(), error_message = 'Timed out (auto-cleaned)'
     WHERE source = 'otx' AND status = 'running' AND started_at < NOW() - INTERVAL '15 minutes'`,
  );

  // Create sync log entry
  const logResult = await query<{ id: string }>(
    `INSERT INTO feed_sync_log (source, status, started_at)
     VALUES ('otx', 'running', NOW())
     RETURNING id`,
  );
  const logId = logResult.rows[0].id;

  let recordsInserted = 0;
  let recordsSkipped = 0;
  let errorMessage: string | null = null;

  try {
    // Get cursor from last successful sync's completed_at as modified_since proxy
    const cursorResult = await query<{ completed_at: string | null }>(
      `SELECT completed_at FROM feed_sync_log
       WHERE source = 'otx' AND status = 'success'
       ORDER BY completed_at DESC LIMIT 1`,
    );
    const lastCursor = cursorResult.rows[0]?.completed_at ?? null;
    const modifiedSince =
      lastCursor ?? new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();

    let url: string | null =
      `${OTX_BASE}/pulses/subscribed?modified_since=${encodeURIComponent(modifiedSince)}&limit=${PULSES_PER_PAGE}`;
    let pages = 0;
    let latestModified = lastCursor;

    while (url && pages < MAX_PAGES) {
      const resp = await fetch(url, { headers: { 'X-OTX-API-KEY': apiKey } });
      if (!resp.ok) {
        throw new Error(`OTX API error: ${resp.status} ${resp.statusText}`);
      }

      const data = (await resp.json()) as OtxResponse;
      pages++;

      for (const pulse of data.results) {
        if (!latestModified || pulse.modified > latestModified) {
          latestModified = pulse.modified;
        }

        const reportUrl = `https://otx.alienvault.com/pulse/${pulse.id}`;
        try {
          const reportResult = await query<{ id: string }>(
            `INSERT INTO threat_reports
               (title, url, source, published_at, otx_pulse_id, summary, raw_content)
             VALUES ($1, $2, 'otx', $3, $4, $5, $6)
             ON CONFLICT (url) DO UPDATE
               SET title = EXCLUDED.title,
                   summary = EXCLUDED.summary,
                   updated_at = NOW()
             RETURNING id`,
            [
              pulse.name,
              reportUrl,
              pulse.created,
              pulse.id,
              pulse.description?.slice(0, 2000) ?? null,
              JSON.stringify({ author: pulse.author_name }),
            ],
          );
          // If we get a row back it was either inserted or updated; track inserts via OTX pulse_id uniqueness approach
          const reportId = reportResult.rows[0].id;
          recordsInserted++;

          // Link ATT&CK techniques and collect IDs for IOC linking
          const normalizedAttackIds: string[] = [];
          for (const atkEntry of pulse.attack_ids ?? []) {
            // OTX returns attack_ids as string[] or Array<{id:string}>
            const rawId = typeof atkEntry === 'string' ? atkEntry : atkEntry.id;
            const normalized = /^T\d{4}(\.\d{3})?$/.test(rawId ?? '')
              ? rawId
              : null;
            if (normalized) normalizedAttackIds.push(normalized);
          }

          // Batch-resolve all technique UUIDs in one query (avoids N+1)
          const techIds: string[] = [];
          if (normalizedAttackIds.length > 0) {
            const techResult = await query<{ id: string; attack_id: string }>(
              `SELECT id, attack_id FROM techniques WHERE attack_id = ANY($1::text[])`,
              [normalizedAttackIds],
            );
            for (const row of techResult.rows) {
              techIds.push(row.id);
              await query(
                `INSERT INTO report_techniques (report_id, technique_id)
                 VALUES ($1, $2)
                 ON CONFLICT DO NOTHING`,
                [reportId, row.id],
              );
            }
          }

          // Extract IOCs — batch insert for speed
          const indicators = (pulse.indicators ?? [])
            .map((ind) => ({ type: mapIocType(ind.type), value: ind.indicator }))
            .filter((ind): ind is { type: string; value: string } => Boolean(ind.type && ind.value))
            .slice(0, 200); // Cap per pulse to avoid timeout

          if (indicators.length > 0) {
            const otxTypeMap: Record<string, string> = {
              ip: 'IPv4', domain: 'domain', url: 'url', hash: 'file', cve: 'cve', email: 'email',
            };

            // Batch insert IOCs — 50 at a time
            for (let b = 0; b < indicators.length; b += 50) {
              const batch = indicators.slice(b, b + 50);
              const values: string[] = [];
              const params: unknown[] = [];
              for (const ind of batch) {
                const offset = params.length;
                const otxPath = otxTypeMap[ind.type] ?? ind.type;
                const sourceRef = `https://otx.alienvault.com/indicator/${otxPath}/${encodeURIComponent(ind.value)}`;
                values.push(`($${offset + 1}, $${offset + 2}, 'otx', $${offset + 3}, NOW())`);
                params.push(ind.type, ind.value, sourceRef);
              }

              const iocResult = await query<{ id: string }>(
                `INSERT INTO ioc_entries (type, value, source, source_ref, first_seen)
                 VALUES ${values.join(', ')}
                 ON CONFLICT (type, value, source) DO UPDATE SET source_ref = EXCLUDED.source_ref
                 RETURNING id`,
                params,
              );

              // Link each inserted IOC to the pulse's techniques
              for (const row of iocResult.rows) {
                if (!row.id || techIds.length === 0) continue;
                const tiValues = techIds.map((_, i) => `($${i + 1}, $${techIds.length + 1}, 'inferred')`).join(', ');
                await query(
                  `INSERT INTO technique_iocs (technique_id, ioc_id, confidence)
                   VALUES ${tiValues}
                   ON CONFLICT DO NOTHING`,
                  [...techIds, row.id],
                );
              }
            }
          }
        } catch (pulseErr) {
          console.error(`Failed to process pulse ${pulse.id}:`, pulseErr);
          recordsSkipped++;
        }
      }

      url = data.next ?? null;
    }

    await query(
      `UPDATE feed_sync_log
       SET status = 'success',
           completed_at = NOW(),
           records_inserted = $1,
           records_skipped = $2
       WHERE id = $3`,
      [recordsInserted, recordsSkipped, logId],
    );

    res.status(200).json({ ok: true, source: 'otx', recordsInserted, recordsSkipped, pagesFetched: pages });
  } catch (err) {
    errorMessage = err instanceof Error ? err.message : String(err);
    console.error('OTX ingest error:', err);

    await query(
      `UPDATE feed_sync_log
       SET status = 'error', completed_at = NOW(), error_message = $1
       WHERE id = $2`,
      [errorMessage, logId],
    );

    res.status(500).json({ ok: false, error: 'Feed sync failed' });
  }
}
