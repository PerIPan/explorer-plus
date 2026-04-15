import { NextRequest, NextResponse } from 'next/server';
import { query } from '../../v1/lib/db';
import { verifyCronAuth } from '../lib/auth';
import { withSoftTimeout, DEFAULT_SOFT_TIMEOUT_MS } from '../lib/softTimeout';

export const maxDuration = 300;

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

export async function GET(req: NextRequest) {
  const authError = verifyCronAuth(req);
  if (authError) return authError;

  const authKey = process.env.ABUSE_CH_AUTH_KEY ?? '';

  // Clean up stale "running" entries (timed-out previous runs)
  await query(
    `UPDATE feed_sync_log
     SET status = 'error', completed_at = NOW(), error_message = 'Timed out (auto-cleaned)'
     WHERE source = 'abuse_ch' AND status = 'running' AND started_at < NOW() - INTERVAL '15 minutes'`,
  );

  const logResult = await query<{ id: string }>(
    `INSERT INTO feed_sync_log (source, status, started_at)
     VALUES ('abuse_ch', 'running', NOW())
     RETURNING id`,
  );
  const logId = logResult.rows[0].id;

  let recordsInserted = 0;
  let recordsSkipped = 0;

  const doWork = async (): Promise<NextResponse> => {
    // -- ThreatFox ---------------------------------------------------------------
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
          // Collect unique malware family names for batch software lookup
          // Normalize malware names: strip platform prefix, replace _ with space
          const normalizeMalware = (m: string) =>
            m.toLowerCase().replace(/^(win|elf|js|apk|doc|osx|py|vbs)\./i, '').replace(/_/g, ' ');

          const malwareNames = [
            ...new Set(
              tfData.data
                .map((ioc) => ioc.malware)
                .filter((m): m is string => Boolean(m))
                .map(normalizeMalware),
            ),
          ];

          // Single batch query to resolve all malware families to software rows
          const swMap = new Map<string, { id: string; techniqueIds: string[] }>();
          if (malwareNames.length > 0) {
            const swBatch = await query<{ id: string; name: string }>(
              `SELECT id, name FROM attack_software
               WHERE LOWER(name) = ANY($1::text[])
                  OR LOWER(REPLACE(name, ' ', '_')) = ANY($1::text[])
                  OR EXISTS (
                    SELECT 1 FROM unnest(aliases) a WHERE LOWER(a) = ANY($1::text[]) OR LOWER(REPLACE(a, ' ', '_')) = ANY($1::text[])
                  )`,
              [malwareNames],
            );

            // Build lookup with both normalized forms
            for (const sw of swBatch.rows) {
              const techRes = await query<{ technique_id: string }>(
                `SELECT technique_id FROM software_techniques WHERE software_id = $1`,
                [sw.id],
              );
              const entry = { id: sw.id, techniqueIds: techRes.rows.map((r) => r.technique_id) };
              swMap.set(sw.name.toLowerCase(), entry);
              swMap.set(sw.name.toLowerCase().replace(/ /g, '_'), entry);
            }
          }

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

              // Cross-reference via pre-resolved software map
              if (ioc.malware) {
                const swEntry = swMap.get(normalizeMalware(ioc.malware));
                if (swEntry && swEntry.techniqueIds.length > 0) {
                  const iocValues = swEntry.techniqueIds
                    .map((_, i) => `($${i + 1}, $${swEntry.techniqueIds.length + 1}, 'inferred')`)
                    .join(', ');
                  await query(
                    `INSERT INTO technique_iocs (technique_id, ioc_id, confidence)
                     VALUES ${iocValues}
                     ON CONFLICT DO NOTHING`,
                    [...swEntry.techniqueIds, iocId],
                  );
                }
              }
            } else {
              recordsSkipped++;
            }
          }
          threatfoxOk = true;
        }
      } else {
        console.warn(`ThreatFox HTTP ${tfResp.status} -- skipping`);
      }
    } catch (tfErr) {
      console.error('ThreatFox error (non-fatal):', tfErr);
    }

    // -- MalwareBazaar -----------------------------------------------------------
    let mbOk = false;
    try {
      // MalwareBazaar switched their endpoint to require form-encoded bodies
      // (ThreatFox still accepts JSON). JSON now returns query_status:
      // "missing_query" and the run silently produces zero MB IOCs. Keep the
      // auth key in the header — it's valid for both.
      const mbResp = await fetch(MALWAREBAZAAR_API, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Auth-Key': authKey },
        body: new URLSearchParams({ query: 'get_recent', selector: '100' }).toString(),
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
        console.warn(`MalwareBazaar HTTP ${mbResp.status} -- skipping`);
      }
    } catch (mbErr) {
      console.error('MalwareBazaar error (non-fatal):', mbErr);
    }

    if (!threatfoxOk && !mbOk) {
      throw new Error('Both ThreatFox and MalwareBazaar failed -- check auth key and network');
    }

    await query(
      `UPDATE feed_sync_log
       SET status = 'success', completed_at = NOW(),
           records_inserted = $1, records_skipped = $2
       WHERE id = $3 AND status = 'running'`,
      [recordsInserted, recordsSkipped, logId],
    );

    return NextResponse.json({ ok: true, source: 'abuse_ch', recordsInserted, recordsSkipped });
  };

  try {
    return await withSoftTimeout(doWork, DEFAULT_SOFT_TIMEOUT_MS);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('abuse.ch ingest error:', err);

    await query(
      `UPDATE feed_sync_log
       SET status = 'error', completed_at = NOW(), error_message = $1,
           records_inserted = $2, records_skipped = $3
       WHERE id = $4 AND status = 'running'`,
      [msg.slice(0, 500), recordsInserted, recordsSkipped, logId],
    );

    return NextResponse.json({ ok: false, error: 'Feed sync failed' }, { status: 500 });
  }
}
