#!/usr/bin/env node
// scripts/sync-abuse-ch.mjs
//
// Ingest IOCs from abuse.ch (ThreatFox + MalwareBazaar). Same dual-source
// pattern as the original Vercel cron at /api/cron/ingest-abuse-ch — moved
// here because daily ThreatFox volume (~500-2000 IOCs) × per-row Neon
// roundtrips for ioc_entries + technique_iocs blew past the 270s soft-timeout.
//
// Each source independently try/catched: if ThreatFox fails the run still
// completes from MalwareBazaar's payload (and vice versa), and the failure
// is logged in feed_sync_log.metadata.warnings so the Feed Status page
// surfaces partial-success states.
//
// Env:
//   DATABASE_URL          required
//   ABUSE_CH_AUTH_KEY     required (same Auth-Key for both APIs)

import pg from 'pg';

const THREATFOX_API = 'https://threatfox-api.abuse.ch/api/v1/';
const MALWAREBAZAAR_API = 'https://mb-api.abuse.ch/api/v1/';

const DATABASE_URL = process.env.DATABASE_URL;
const AUTH_KEY = process.env.ABUSE_CH_AUTH_KEY ?? '';

if (!DATABASE_URL) { console.error('DATABASE_URL required'); process.exit(1); }
if (!AUTH_KEY) { console.error('ABUSE_CH_AUTH_KEY required'); process.exit(1); }

const TF_TYPE_MAP = {
  'ip:port': 'ip',
  domain: 'domain',
  url: 'url',
  md5_hash: 'hash',
  sha256_hash: 'hash',
};

function mapThreatFoxType(t) {
  return TF_TYPE_MAP[t] ?? null;
}

function normalizeIocValue(type, value) {
  return type === 'ip:port' ? value.split(':')[0] : value;
}

// Strip platform prefix + replace _ with space — matches the original cron
// so software-row lookups behave the same.
function normalizeMalware(m) {
  return m.toLowerCase().replace(/^(win|elf|js|apk|doc|osx|py|vbs)\./i, '').replace(/_/g, ' ');
}

async function insertLogStart(client) {
  await client.query(
    `UPDATE feed_sync_log SET status='error', completed_at=NOW(),
       error_message='Stale (auto-cleaned on new run start)'
     WHERE source='abuse_ch' AND status='running' AND started_at < NOW() - INTERVAL '30 minutes'`,
  );
  const res = await client.query(
    `INSERT INTO feed_sync_log (source, status, started_at)
     VALUES ('abuse_ch', 'running', NOW()) RETURNING id`,
  );
  return res.rows[0].id;
}

async function updateLogDone(client, logId, status, counters, meta, errorMessage) {
  await client.query(
    `UPDATE feed_sync_log
     SET status=$1, completed_at=NOW(),
         records_inserted=$2, records_skipped=$3,
         metadata=$4, error_message=$5
     WHERE id=$6`,
    [
      status,
      counters.recordsInserted,
      counters.recordsSkipped,
      JSON.stringify({ ...meta, trigger: 'github-actions' }),
      errorMessage?.slice(0, 500) ?? null,
      logId,
    ],
  );
}

async function ingestThreatFox(client, counters, warnings) {
  const resp = await fetch(THREATFOX_API, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Auth-Key': AUTH_KEY },
    body: JSON.stringify({ query: 'get_iocs', days: 1 }),
  });
  if (!resp.ok) { warnings.push(`threatfox http ${resp.status}`); return false; }
  const data = await resp.json();
  if (data.query_status !== 'ok' || !Array.isArray(data.data)) {
    warnings.push(`threatfox query_status=${data.query_status}`);
    return false;
  }

  // Resolve every malware family → software row in a single query.
  const malwareNames = [...new Set(
    data.data
      .map((ioc) => ioc.malware)
      .filter(Boolean)
      .map(normalizeMalware),
  )];

  const swMap = new Map();
  if (malwareNames.length > 0) {
    const sw = await client.query(
      `SELECT id, name FROM attack_software
       WHERE LOWER(name) = ANY($1::text[])
          OR LOWER(REPLACE(name, ' ', '_')) = ANY($1::text[])
          OR EXISTS (
            SELECT 1 FROM unnest(aliases) a
            WHERE LOWER(a) = ANY($1::text[])
               OR LOWER(REPLACE(a, ' ', '_')) = ANY($1::text[])
          )`,
      [malwareNames],
    );
    for (const row of sw.rows) {
      const techRes = await client.query(
        `SELECT technique_id FROM software_techniques WHERE software_id = $1`,
        [row.id],
      );
      const entry = { id: row.id, techniqueIds: techRes.rows.map((r) => r.technique_id) };
      swMap.set(row.name.toLowerCase(), entry);
      swMap.set(row.name.toLowerCase().replace(/ /g, '_'), entry);
    }
  }

  for (const ioc of data.data) {
    const iocType = mapThreatFoxType(ioc.ioc_type);
    if (!iocType) continue;
    const iocValue = normalizeIocValue(ioc.ioc_type, ioc.ioc);

    const ins = await client.query(
      `INSERT INTO ioc_entries (type, value, source, malware_family, first_seen)
       VALUES ($1, $2, 'threatfox', $3, $4)
       ON CONFLICT (type, value, source) DO NOTHING
       RETURNING id`,
      [iocType, iocValue, ioc.malware || null, ioc.first_seen || null],
    );

    if (ins.rows.length === 0) { counters.recordsSkipped++; continue; }
    counters.recordsInserted++;
    const iocId = ins.rows[0].id;

    if (ioc.malware) {
      const swEntry = swMap.get(normalizeMalware(ioc.malware));
      if (swEntry?.techniqueIds.length > 0) {
        const tiVals = swEntry.techniqueIds
          .map((_, i) => `($${i + 1}, $${swEntry.techniqueIds.length + 1}, 'inferred')`)
          .join(', ');
        await client.query(
          `INSERT INTO technique_iocs (technique_id, ioc_id, confidence)
           VALUES ${tiVals} ON CONFLICT DO NOTHING`,
          [...swEntry.techniqueIds, iocId],
        );
      }
    }
  }
  return true;
}

async function ingestMalwareBazaar(client, counters, warnings) {
  // MalwareBazaar moved off JSON; uses application/x-www-form-urlencoded now.
  // ThreatFox still accepts JSON. Auth-Key works for both.
  const resp = await fetch(MALWAREBAZAAR_API, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Auth-Key': AUTH_KEY },
    body: new URLSearchParams({ query: 'get_recent', selector: '100' }).toString(),
  });
  if (!resp.ok) { warnings.push(`malwarebazaar http ${resp.status}`); return false; }
  const data = await resp.json();
  if (data.query_status !== 'ok' || !Array.isArray(data.data)) {
    warnings.push(`malwarebazaar query_status=${data.query_status}`);
    return false;
  }

  for (const sample of data.data) {
    for (const hash of [sample.sha256_hash, sample.md5_hash].filter(Boolean)) {
      const r = await client.query(
        `INSERT INTO ioc_entries (type, value, source, malware_family, first_seen)
         VALUES ('hash', $1, 'malwarebazaar', $2, $3)
         ON CONFLICT (type, value, source) DO NOTHING RETURNING id`,
        [hash, sample.signature || null, sample.first_seen || null],
      );
      if (r.rows.length > 0) counters.recordsInserted++; else counters.recordsSkipped++;
    }
  }
  return true;
}

async function main() {
  const client = new pg.Client({ connectionString: DATABASE_URL });
  await client.connect();
  const logId = await insertLogStart(client);
  const startedAt = Date.now();
  console.log(`[abuse-ch] starting logId=${logId}`);

  const counters = { recordsInserted: 0, recordsSkipped: 0 };
  const warnings = [];

  try {
    let tfOk = false, mbOk = false;
    try { tfOk = await ingestThreatFox(client, counters, warnings); }
    catch (err) { warnings.push(`threatfox: ${err.message}`); console.error('[abuse-ch] threatfox error:', err); }
    try { mbOk = await ingestMalwareBazaar(client, counters, warnings); }
    catch (err) { warnings.push(`malwarebazaar: ${err.message}`); console.error('[abuse-ch] malwarebazaar error:', err); }

    if (!tfOk && !mbOk) throw new Error(`Both feeds failed: ${warnings.join('; ')}`);

    const elapsedMs = Date.now() - startedAt;
    console.log(`[abuse-ch] done in ${elapsedMs}ms — inserted=${counters.recordsInserted} skipped=${counters.recordsSkipped} tfOk=${tfOk} mbOk=${mbOk}`);
    await updateLogDone(client, logId, 'success', counters, {
      threatfoxOk: tfOk, malwareBazaarOk: mbOk, warnings, elapsedMs,
    }, null);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('[abuse-ch] fatal:', err);
    await updateLogDone(client, logId, 'error', counters, {
      warnings, elapsedMs: Date.now() - startedAt,
    }, msg);
    throw err;
  } finally {
    await client.end();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
