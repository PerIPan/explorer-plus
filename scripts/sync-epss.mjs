#!/usr/bin/env node
// scripts/sync-epss.mjs
//
// Daily ingest of EPSS (Exploit Prediction Scoring System) scores from First.org.
// Run:  DATABASE_URL=postgres://... node scripts/sync-epss.mjs
//
// The Vercel cron at /api/cron/sync-epss runs an equivalent pipeline daily.
// This script is for local / scratch runs.
//
// Design note: EPSS enriches existing cve_details rows but never creates new
// ones. CVE rows are created by ingest-cve-delta / ingest-cvelistv5 with their
// NOT NULL columns populated. EPSS rows for CVEs we don't have are silently
// dropped and reported via rowsSkippedUnknown.

import { createGunzip } from 'node:zlib';
import { pipeline } from 'node:stream/promises';
import { Readable, Writable } from 'node:stream';
import pg from 'pg';

const EPSS_URL = 'https://epss.cyentia.com/epss_scores-current.csv.gz';
const BATCH_SIZE = 1000;

const DATABASE_URL = process.env.DATABASE_URL || process.env.POSTGRES_URL;
if (!DATABASE_URL) {
  console.error('DATABASE_URL or POSTGRES_URL required');
  process.exit(1);
}

async function run() {
  console.log(`Fetching EPSS from ${EPSS_URL}...`);
  const resp = await fetch(EPSS_URL);
  if (!resp.ok) throw new Error(`EPSS fetch failed: ${resp.status}`);
  if (!resp.body) throw new Error('EPSS response body is null');

  const client = new pg.Client({ connectionString: DATABASE_URL });
  await client.connect();

  let rowsUpdated = 0;
  let rowsSkippedUnknown = 0;
  let rowsSkippedMalformed = 0;
  let modelDate = null;
  let batch = [];
  let buffer = '';
  let headerSkipped = false;

  const flush = async () => {
    if (batch.length === 0) return;
    const values = batch
      .map((_, i) =>
        `($${i * 4 + 1}::text, $${i * 4 + 2}::numeric, $${i * 4 + 3}::numeric, $${i * 4 + 4}::timestamptz)`,
      )
      .join(', ');
    const params = batch.flatMap((r) => [r.cve, r.score, r.percentile, modelDate]);
    const result = await client.query(
      `WITH incoming(cve_id, epss_score, epss_percentile, epss_updated_at) AS (
         VALUES ${values}
       )
       UPDATE cve_details cd
       SET epss_score      = incoming.epss_score,
           epss_percentile = incoming.epss_percentile,
           epss_updated_at = incoming.epss_updated_at,
           updated_at      = NOW()
       FROM incoming
       WHERE cd.cve_id = incoming.cve_id`,
      params,
    );
    rowsUpdated += result.rowCount ?? 0;
    rowsSkippedUnknown += batch.length - (result.rowCount ?? 0);
    batch = [];
  };

  const writer = new Writable({
    async write(chunk, _enc, cb) {
      try {
        buffer += chunk.toString('utf8');
        const lines = buffer.split('\n');
        buffer = lines.pop() ?? '';
        for (const raw of lines) {
          const line = raw.trim();
          if (!line) continue;
          if (line.startsWith('#')) {
            const m = line.match(/score_date:([0-9T:+\-.]+)/);
            if (m) modelDate = m[1];
            continue;
          }
          if (!headerSkipped) { headerSkipped = true; continue; }
          const [cve, score, pct] = line.split(',');
          if (!cve || !cve.startsWith('CVE-') || isNaN(parseFloat(score))) {
            rowsSkippedMalformed++;
            continue;
          }
          batch.push({ cve, score: parseFloat(score), percentile: parseFloat(pct) });
          if (batch.length >= BATCH_SIZE) await flush();
        }
        cb();
      } catch (err) {
        cb(err);
      }
    },
  });

  try {
    // fetch() returns WHATWG ReadableStream; bridge to Node Readable for pipeline().
    await pipeline(Readable.fromWeb(resp.body), createGunzip(), writer);
    await flush();
    console.log(
      `EPSS sync complete. updated=${rowsUpdated}, skipped_unknown_cve=${rowsSkippedUnknown}, skipped_malformed=${rowsSkippedMalformed}, modelDate=${modelDate}`,
    );
  } finally {
    await client.end();
  }
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
