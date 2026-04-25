import { NextRequest, NextResponse } from 'next/server';
import { query } from '../../v1/lib/db';
import { verifyCronAuth } from '../lib/auth';
import { withSoftTimeout, DEFAULT_SOFT_TIMEOUT_MS } from '../lib/softTimeout';

export const maxDuration = 300;

const THREATFOX_API = 'https://threatfox-api.abuse.ch/api/v1/';
const MALWAREBAZAAR_API = 'https://mb-api.abuse.ch/api/v1/';
const BATCH_SIZE = 200;

// abuse.ch IP-blocks GitHub Actions runners with 403 even when the Auth-Key
// is valid (verified: same key returns 200 from a laptop, 403 from GH). So
// unlike OSV / cve-products / cve-delta, we cannot migrate this off Vercel.
// Instead we collapse the per-IOC INSERT roundtrips (the cause of the 270s
// soft-timeout) into batched UPSERTs via unnest() — the daily ~500-2000
// IOC payload now finishes in seconds instead of minutes.

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

function normalizeMalware(m: string): string {
  return m.toLowerCase().replace(/^(win|elf|js|apk|doc|osx|py|vbs)\./i, '').replace(/_/g, ' ');
}

interface SoftwareEntry { id: string; techniqueIds: string[] }

async function buildSoftwareMap(malwareNames: string[]): Promise<Map<string, SoftwareEntry>> {
  const swMap = new Map<string, SoftwareEntry>();
  if (malwareNames.length === 0) return swMap;
  const swBatch = await query<{ id: string; name: string }>(
    `SELECT id, name FROM attack_software
     WHERE LOWER(name) = ANY($1::text[])
        OR LOWER(REPLACE(name, ' ', '_')) = ANY($1::text[])
        OR EXISTS (
          SELECT 1 FROM unnest(aliases) a
          WHERE LOWER(a) = ANY($1::text[]) OR LOWER(REPLACE(a, ' ', '_')) = ANY($1::text[])
        )`,
    [malwareNames],
  );
  for (const sw of swBatch.rows) {
    const techRes = await query<{ technique_id: string }>(
      `SELECT technique_id FROM software_techniques WHERE software_id = $1`,
      [sw.id],
    );
    const entry: SoftwareEntry = { id: sw.id, techniqueIds: techRes.rows.map((r) => r.technique_id) };
    swMap.set(sw.name.toLowerCase(), entry);
    swMap.set(sw.name.toLowerCase().replace(/ /g, '_'), entry);
  }
  return swMap;
}

interface IocRow { type: string; value: string; malware: string | null; firstSeen: string | null }

async function batchInsertIocs(
  source: 'threatfox' | 'malwarebazaar',
  rows: IocRow[],
): Promise<Array<{ id: string; value: string; malware_family: string | null }>> {
  if (rows.length === 0) return [];
  const inserted: Array<{ id: string; value: string; malware_family: string | null }> = [];
  for (let i = 0; i < rows.length; i += BATCH_SIZE) {
    const batch = rows.slice(i, i + BATCH_SIZE);
    const r = await query<{ id: string; value: string; malware_family: string | null }>(
      `INSERT INTO ioc_entries (type, value, source, malware_family, first_seen)
       SELECT t, v, $1, m, NULLIF(fs, '')::timestamptz
       FROM unnest($2::text[], $3::text[], $4::text[], $5::text[]) AS u(t, v, m, fs)
       ON CONFLICT (type, value, source) DO NOTHING
       RETURNING id, value, malware_family`,
      [
        source,
        batch.map((b) => b.type),
        batch.map((b) => b.value),
        batch.map((b) => b.malware ?? ''),
        batch.map((b) => b.firstSeen ?? ''),
      ],
    );
    inserted.push(...r.rows);
  }
  return inserted;
}

async function batchLinkTechniques(
  iocsByMalware: Map<string, string[]>,
  swMap: Map<string, SoftwareEntry>,
): Promise<void> {
  const techArr: string[] = [];
  const iocArr: string[] = [];
  for (const [mw, iocIds] of iocsByMalware) {
    const swEntry = swMap.get(mw);
    if (!swEntry || swEntry.techniqueIds.length === 0) continue;
    for (const tid of swEntry.techniqueIds) {
      for (const iid of iocIds) {
        techArr.push(tid);
        iocArr.push(iid);
      }
    }
  }
  if (techArr.length === 0) return;
  // Insert in chunks too — large pulses with many techniques can blow past
  // postgres parameter limits otherwise.
  for (let i = 0; i < techArr.length; i += 1000) {
    const tBatch = techArr.slice(i, i + 1000);
    const iBatch = iocArr.slice(i, i + 1000);
    await query(
      `INSERT INTO technique_iocs (technique_id, ioc_id, confidence)
       SELECT t::uuid, i::uuid, 'inferred'
       FROM unnest($1::text[], $2::text[]) AS u(t, i)
       ON CONFLICT DO NOTHING`,
      [tBatch, iBatch],
    );
  }
}

export async function GET(req: NextRequest) {
  const authError = verifyCronAuth(req);
  if (authError) return authError;

  const authKey = process.env.ABUSE_CH_AUTH_KEY ?? '';

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
          // Stage 1 — flatten + filter
          const tfRows: IocRow[] = [];
          for (const ioc of tfData.data) {
            const iocType = mapThreatFoxType(ioc.ioc_type);
            if (!iocType) { recordsSkipped++; continue; }
            tfRows.push({
              type: iocType,
              value: normalizeIocValue(ioc.ioc_type, ioc.ioc),
              malware: ioc.malware || null,
              firstSeen: ioc.first_seen || null,
            });
          }

          // Stage 2 — resolve every malware family in one query
          const malwareNames = [...new Set(
            tfRows.map((r) => r.malware).filter((m): m is string => Boolean(m)).map(normalizeMalware),
          )];
          const swMap = await buildSoftwareMap(malwareNames);

          // Stage 3 — batch UPSERT IOCs
          const inserted = await batchInsertIocs('threatfox', tfRows);
          recordsInserted += inserted.length;
          recordsSkipped += tfRows.length - inserted.length;

          // Stage 4 — group inserted IOCs by malware family + batch link to techniques
          const iocsByMalware = new Map<string, string[]>();
          for (const row of inserted) {
            if (!row.malware_family) continue;
            const norm = normalizeMalware(row.malware_family);
            const list = iocsByMalware.get(norm);
            if (list) list.push(row.id);
            else iocsByMalware.set(norm, [row.id]);
          }
          await batchLinkTechniques(iocsByMalware, swMap);

          threatfoxOk = true;
        }
      } else {
        console.warn(`ThreatFox HTTP ${tfResp.status} -- skipping`);
      }
    } catch (tfErr) {
      console.error('ThreatFox error (non-fatal):', tfErr);
    }

    let mbOk = false;
    try {
      // MalwareBazaar requires form-encoded bodies (ThreatFox accepts JSON).
      const mbResp = await fetch(MALWAREBAZAAR_API, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Auth-Key': authKey },
        body: new URLSearchParams({ query: 'get_recent', selector: '100' }).toString(),
      });

      if (mbResp.ok) {
        const mbData = (await mbResp.json()) as MalwareBazaarResponse;
        if (mbData.query_status === 'ok' && Array.isArray(mbData.data)) {
          const mbRows: IocRow[] = [];
          for (const sample of mbData.data) {
            for (const hash of [sample.sha256_hash, sample.md5_hash].filter((h): h is string => Boolean(h))) {
              mbRows.push({
                type: 'hash',
                value: hash,
                malware: sample.signature || null,
                firstSeen: sample.first_seen || null,
              });
            }
          }
          const inserted = await batchInsertIocs('malwarebazaar', mbRows);
          recordsInserted += inserted.length;
          recordsSkipped += mbRows.length - inserted.length;
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
           records_inserted = $1, records_skipped = $2,
           metadata = $3
       WHERE id = $4 AND status = 'running'`,
      [
        recordsInserted,
        recordsSkipped,
        JSON.stringify({ threatfoxOk, malwareBazaarOk: mbOk }),
        logId,
      ],
    );

    return NextResponse.json({ ok: true, source: 'abuse_ch', recordsInserted, recordsSkipped, threatfoxOk, mbOk });
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
