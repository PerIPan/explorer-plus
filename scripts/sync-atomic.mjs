/**
 * sync-atomic.mjs
 * Scans /tmp/atomic-red-team/atomics/ for T*.yaml files,
 * parses each test, and upserts into atomic_tests table.
 *
 * Usage: node scripts/sync-atomic.mjs
 * Requires: DATABASE_URL env var, pg and yaml installed
 */

import { readdir, readFile, stat } from 'fs/promises';
import { join } from 'path';
import pkg from 'pg';
import yaml from 'yaml';

const { Pool } = pkg;

const ATOMICS_ROOT = '/tmp/atomic-red-team/atomics';
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

async function findAtomicFiles(dir) {
  const results = [];
  let entries;
  try {
    entries = await readdir(dir);
  } catch {
    return results;
  }

  for (const entry of entries) {
    if (!/^T\d{4}/.test(entry)) continue;

    const full = join(dir, entry);
    const info = await stat(full).catch(() => null);
    if (!info?.isDirectory()) continue;

    const subEntries = await readdir(full).catch(() => []);
    for (const sub of subEntries) {
      if (sub.endsWith('.yaml') || sub.endsWith('.yml')) {
        results.push(join(full, sub));
      }
    }
  }
  return results;
}

async function insertLogStart(client) {
  await client.query(
    `UPDATE feed_sync_log SET status='error', completed_at=NOW(),
       error_message='Stale (auto-cleaned on new run start)'
     WHERE source='atomic' AND status='running' AND started_at < NOW() - INTERVAL '2 hours'`,
  );
  const r = await client.query(
    `INSERT INTO feed_sync_log (source, status, started_at)
     VALUES ('atomic', 'running', NOW()) RETURNING id`,
  );
  return r.rows[0].id;
}

async function updateLogDone(client, logId, status, counters, errorMessage) {
  await client.query(
    `UPDATE feed_sync_log
     SET status=$1, completed_at=NOW(),
         records_inserted=$2, records_skipped=$3,
         metadata=$4, error_message=$5
     WHERE id=$6`,
    [
      status,
      counters.inserted + counters.updated,
      counters.errors,
      JSON.stringify({ ...counters, trigger: 'github-actions' }),
      errorMessage?.slice(0, 500) ?? null,
      logId,
    ],
  );
}

async function main() {
  const client = await pool.connect();
  let inserted = 0;
  let updated = 0;
  let errors = 0;
  const startedAt = Date.now();
  let logId;

  try {
    logId = await insertLogStart(client);
    const files = await findAtomicFiles(ATOMICS_ROOT);
    console.log(`Found ${files.length} Atomic Red Team YAML files (logId=${logId})`);

    if (files.length === 0) {
      throw new Error(`No Atomic YAML files at ${ATOMICS_ROOT} — clone likely failed`);
    }

    for (const file of files) {
      try {
        const text = await readFile(file, 'utf-8');
        const doc = yaml.parse(text);

        if (!doc?.attack_technique || !Array.isArray(doc.atomic_tests)) continue;

        const attackId = doc.attack_technique;

        // Look up technique UUID from DB (optional — can be null)
        const techResult = await client.query(
          'SELECT id FROM techniques WHERE attack_id = $1 LIMIT 1',
          [attackId],
        );
        const techniqueId = techResult.rows[0]?.id ?? null;

        for (let i = 0; i < doc.atomic_tests.length; i++) {
          const test = doc.atomic_tests[i];
          if (!test?.name) continue;

          const testNumber = i + 1;
          const executor = test.executor ?? {};
          const platforms = Array.isArray(test.supported_platforms)
            ? test.supported_platforms
            : [];

          try {
            // atomic_tests UNIQUE is on (attack_technique_id, test_number) — both text/int
            const res = await client.query(
              `INSERT INTO atomic_tests
                 (attack_technique_id, technique_id, test_number, name, description,
                  platforms, executor_type, executor_command, cleanup_command)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
               ON CONFLICT (attack_technique_id, test_number) DO UPDATE
                 SET name = EXCLUDED.name,
                     description = EXCLUDED.description,
                     technique_id = EXCLUDED.technique_id,
                     platforms = EXCLUDED.platforms,
                     executor_type = EXCLUDED.executor_type,
                     executor_command = EXCLUDED.executor_command,
                     cleanup_command = EXCLUDED.cleanup_command
               RETURNING (xmax = 0) AS was_inserted`,
              [
                attackId,
                techniqueId,
                testNumber,
                test.name,
                test.description ?? null,
                platforms,
                executor.name ?? null,
                executor.command ?? null,
                executor.cleanup_command ?? null,
              ],
            );

            if (res.rows[0]?.was_inserted) inserted++; else updated++;
          } catch (insertErr) {
            errors++;
            if (errors <= 10) {
              console.error(`Error inserting ${attackId}#${testNumber}:`, insertErr.message);
            }
          }
        }
      } catch (fileErr) {
        errors++;
        if (errors <= 10) console.error(`Error processing ${file}:`, fileErr.message);
      }
    }

    const elapsedMs = Date.now() - startedAt;
    console.log(`Atomic sync complete: ${inserted} inserted, ${updated} updated, ${errors} errors (${elapsedMs}ms)`);
    if (logId) await updateLogDone(client, logId, 'success', { inserted, updated, errors, elapsedMs }, null);
  } catch (err) {
    if (logId) {
      try { await updateLogDone(client, logId, 'error', { inserted, updated, errors, elapsedMs: Date.now() - startedAt }, err.message); }
      catch (logErr) { console.error('Also failed to write error log row:', logErr.message); }
    }
    throw err;
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
