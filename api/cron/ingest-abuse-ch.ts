import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../v1/_lib/db.js';

const THREATFOX_API = 'https://threatfox-api.abuse.ch/api/v1/';
const MALWAREBAZAAR_API = 'https://mb-api.abuse.ch/api/v1/';

interface ThreatFoxIoc {
  ioc_type: string;
  ioc: string;
  malware: string;
  first_seen: string;
}

interface ThreatFoxResponse {
  query_status: string;
  data?: ThreatFoxIoc[];
}

interface MalwareBazaarSample {
  sha256_hash: string;
  md5_hash: string;
  first_seen: string;
  signature: string | null;
}

interface MalwareBazaarResponse {
  query_status: string;
  data?: MalwareBazaarSample[];
}

function mapThreatFoxType(t: string): string | null {
  const map: Record<string, string> = {
    'ip:port': 'ip',
    domain: 'domain',
    url: 'url',
    md5_hash: 'hash',
    sha256_hash: 'hash',
  };
  return map[t] ?? null;
}

function normalizeIocValue(type: string, value: string): string {
  if (type === 'ip:port') return value.split(':')[0];
  return value;
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== 'GET' && req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }

  const authKey = process.env.ABUSE_CH_AUTH_KEY ?? '';

  const logResult = await query<{ id: string }>(
    `INSERT INTO feed_sync_log (source, status, started_at)
     VALUES ('abuse_ch', 'running', NOW())
     RETURNING id`,
  );
  const logId = logResult.rows[0].id;

  let recordsInserted = 0;
  let recordsSkipped = 0;

  try {
    // ── ThreatFox ──────────────────────────────────────────────────────────────
    let threatfoxOk = false;
    try {
      const tfResp = await fetch(THREATFOX_API, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Auth-Key': authKey },
        body: JSON.stringify({ query: 'get_iocs', days: 1 }),
      });

      if (tfResp.ok) {
        const tfData = (await tfResp.json()) as ThreatFoxResponse;
        if (tfData.query_status === 'ok' && Array.isArray(tfData.data)) {
          for (const ioc of tfData.data) {
            const iocType = mapThreatFoxType(ioc.ioc_type);
            if (!iocType) continue;
            const iocValue = normalizeIocValue(ioc.ioc_type, ioc.ioc);

            const result = await query<{ id: string }>(
              `INSERT INTO ioc_entries
                 (type, value, source, malware_family, first_seen)
               VALUES ($1, $2, 'threatfox', $3, $4)
               ON CONFLICT (type, value, source) DO NOTHING
               RETURNING id`,
              [iocType, iocValue, ioc.malware || null, ioc.first_seen || null],
            );

            if (result.rows.length > 0) {
              recordsInserted++;
              const iocId = result.rows[0].id;

              // Cross-reference malware family against attack_software
              if (ioc.malware) {
                const swResult = await query<{ id: string }>(
                  `SELECT id FROM attack_software
                   WHERE name ILIKE $1
                      OR (aliases IS NOT NULL AND $2 ILIKE ANY(aliases))
                   LIMIT 1`,
                  [ioc.malware, ioc.malware],
                );

                if (swResult.rows[0]) {
                  const techResult = await query<{ technique_id: string }>(
                    `SELECT technique_id FROM software_techniques
                     WHERE software_id = $1`,
                    [swResult.rows[0].id],
                  );

                  for (const tech of techResult.rows) {
                    await query(
                      `INSERT INTO technique_iocs (technique_id, ioc_id, confidence)
                       VALUES ($1, $2, 'inferred')
                       ON CONFLICT DO NOTHING`,
                      [tech.technique_id, iocId],
                    );
                  }
                }
              }
            } else {
              recordsSkipped++;
            }
          }
          threatfoxOk = true;
        }
      } else {
        console.warn(`ThreatFox HTTP ${tfResp.status} — skipping`);
      }
    } catch (tfErr) {
      console.error('ThreatFox error (non-fatal):', tfErr);
    }

    // ── MalwareBazaar ─────────────────────────────────────────────────────────
    let mbOk = false;
    try {
      const mbResp = await fetch(MALWAREBAZAAR_API, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Auth-Key': authKey },
        body: JSON.stringify({ query: 'get_recent', selector: '100' }),
      });

      if (mbResp.ok) {
        const mbData = (await mbResp.json()) as MalwareBazaarResponse;
        if (mbData.query_status === 'ok' && Array.isArray(mbData.data)) {
          for (const sample of mbData.data) {
            if (sample.sha256_hash) {
              const r = await query(
                `INSERT INTO ioc_entries (type, value, source, malware_family, first_seen)
                 VALUES ('hash', $1, 'malwarebazaar', $2, $3)
                 ON CONFLICT (type, value, source) DO NOTHING
                 RETURNING id`,
                [sample.sha256_hash, sample.signature || null, sample.first_seen || null],
              );
              if (r.rows.length > 0) recordsInserted++; else recordsSkipped++;
            }
            if (sample.md5_hash) {
              const r = await query(
                `INSERT INTO ioc_entries (type, value, source, malware_family, first_seen)
                 VALUES ('hash', $1, 'malwarebazaar', $2, $3)
                 ON CONFLICT (type, value, source) DO NOTHING
                 RETURNING id`,
                [sample.md5_hash, sample.signature || null, sample.first_seen || null],
              );
              if (r.rows.length > 0) recordsInserted++; else recordsSkipped++;
            }
          }
          mbOk = true;
        }
      } else {
        console.warn(`MalwareBazaar HTTP ${mbResp.status} — skipping`);
      }
    } catch (mbErr) {
      console.error('MalwareBazaar error (non-fatal):', mbErr);
    }

    if (!threatfoxOk && !mbOk) {
      throw new Error('Both ThreatFox and MalwareBazaar failed — check auth key and network');
    }

    await query(
      `UPDATE feed_sync_log
       SET status = 'success', completed_at = NOW(),
           records_inserted = $1, records_skipped = $2
       WHERE id = $3`,
      [recordsInserted, recordsSkipped, logId],
    );

    res.status(200).json({ ok: true, source: 'abuse_ch', recordsInserted, recordsSkipped });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('abuse.ch ingest error:', err);

    await query(
      `UPDATE feed_sync_log
       SET status = 'error', completed_at = NOW(), error_message = $1
       WHERE id = $2`,
      [msg, logId],
    );

    res.status(500).json({ ok: false, error: msg });
  }
}
