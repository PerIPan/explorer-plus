#!/usr/bin/env node
// scripts/update-attack.mjs
//
// Safe-update path for absorbing new MITRE ATT&CK STIX releases without
// running the destructive seed (seed/seed.py TRUNCATEs 15 tables on every
// run). UPSERTs by stix_id so DB UUIDs stay stable, preserving FK
// references from custom mapping tables (capec, csf, atlas_xrefs, ctid,
// external_actors, owasp, nist_controls, engage, react, veris, cloud,
// detection_strategies). Pre/post snapshot diff (Chunk 5) verifies nothing
// regressed.
//
// Spec: docs/mitre_update.md
// Plan: docs/superpowers/plans/2026-04-28-attack-update-script-plan.md
//
// CLI:
//   --domains=enterprise-attack,mobile-attack,ics-attack    (default)
//   --dry-run                                                (preview, no writes)
//   --force                                                  (skip version guard)
//
// ATLAS is intentionally out of scope — scripts/sync-atlas.mjs owns it.

import pg from 'pg';
import fs from 'fs';
import path from 'path';
import { spawnSync } from 'child_process';

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) { console.error('DATABASE_URL required'); process.exit(1); }

const STIX_BASE = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master';
const ADVISORY_LOCK_KEY = 0x617474; // ASCII 'att'
const FETCH_TIMEOUT_MS = 60_000;
const EXTRACT_BUFFER = 256 * 1024 * 1024; // STIX bundles can be ~10MB; output dict bigger

function parseArgs() {
  const args = {
    domains: ['enterprise-attack', 'mobile-attack', 'ics-attack'],
    dryRun: false,
    force: false,
  };
  for (const arg of process.argv.slice(2)) {
    if (arg === '--dry-run') args.dryRun = true;
    else if (arg === '--force') args.force = true;
    else if (arg.startsWith('--domains=')) {
      args.domains = arg.slice('--domains='.length).split(',').map((d) => d.trim()).filter(Boolean);
    }
  }
  if (args.domains.some((d) => d === 'atlas-attack' || d === 'atlas')) {
    console.error('atlas-attack is out of scope; use scripts/sync-atlas.mjs');
    process.exit(1);
  }
  return args;
}

// --- feed_sync_log + lock + version -----------------------------------------

async function insertLogStart(pool) {
  await pool.query(
    `UPDATE feed_sync_log SET status='error', completed_at=NOW(),
       error_message='Stale (auto-cleaned on new run start)'
     WHERE source='attack_update' AND status='running' AND started_at < NOW() - INTERVAL '1 hour'`,
  );
  const r = await pool.query(
    `INSERT INTO feed_sync_log (source, status, started_at)
     VALUES ('attack_update', 'running', NOW()) RETURNING id`,
  );
  return r.rows[0].id;
}

async function updateLogDone(pool, logId, status, counters, meta, errorMessage) {
  await pool.query(
    `UPDATE feed_sync_log
     SET status=$1, completed_at=NOW(),
         records_inserted=$2, records_skipped=$3,
         metadata=$4, error_message=$5
     WHERE id=$6`,
    [
      status,
      counters.entitiesUpserted ?? 0,
      counters.entitiesSkipped ?? 0,
      JSON.stringify({ ...meta, trigger: 'github-actions' }),
      errorMessage?.slice(0, 1000) ?? null,
      logId,
    ],
  );
}

async function acquireAdvisoryLock(pool) {
  const r = await pool.query('SELECT pg_try_advisory_lock($1) AS locked', [ADVISORY_LOCK_KEY]);
  return r.rows[0].locked === true;
}

async function releaseAdvisoryLock(pool) {
  await pool.query('SELECT pg_advisory_unlock($1)', [ADVISORY_LOCK_KEY]);
}

async function getLastVersion(pool) {
  const r = await pool.query(
    `SELECT metadata->>'attackVersion' AS v
     FROM feed_sync_log
     WHERE source='attack_update' AND status='success'
     ORDER BY completed_at DESC NULLS LAST LIMIT 1`,
  );
  return r.rows[0]?.v ?? null;
}

// --- STIX fetch + extract subprocess ----------------------------------------

async function fetchStixBundle(domain, dest) {
  const url = `${STIX_BASE}/${domain}/${domain}.json`;
  console.log(`[attack-update] fetching ${url}`);
  const resp = await fetch(url, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  if (!resp.ok) throw new Error(`STIX fetch ${resp.status} for ${domain}`);
  const text = await resp.text();
  fs.writeFileSync(dest, text);
  return text.length;
}

function extractStixDomain(domain, stixPath) {
  // Subprocess to seed/extract.py — single source of truth for STIX edge cases.
  const r = spawnSync('python3', [
    'seed/extract.py',
    `--domain=${domain}`,
    `--stix-path=${stixPath}`,
  ], { encoding: 'utf8', maxBuffer: EXTRACT_BUFFER });
  if (r.status !== 0) {
    throw new Error(`extract.py exited ${r.status} for ${domain}: ${(r.stderr || '').slice(0, 500)}`);
  }
  return JSON.parse(r.stdout);
}

function readSpecVersion(stixPath) {
  // Prefer x_mitre_attack_spec_version on the bundle's marking-definition or
  // x-mitre-collection object — fall back to scanning all objects.
  const bundle = JSON.parse(fs.readFileSync(stixPath, 'utf8'));
  for (const obj of bundle.objects ?? []) {
    if (obj.x_mitre_attack_spec_version) return obj.x_mitre_attack_spec_version;
    if (obj.x_mitre_version && obj.type === 'x-mitre-collection') return obj.x_mitre_version;
  }
  return null;
}

// --- Entity UPSERT helpers --------------------------------------------------

/**
 * Two-CTE UPSERT for entities WITHOUT cross-domain sharing (tactics,
 * techniques, mitigations, data_sources, data_components — these have
 * single-value `domain VARCHAR`). Returns {inserted, updated} counts.
 *
 * `xmax = 0` for insert/update detection is unreliable on PG 15+, so we
 * split into two CTEs: INSERT … ON CONFLICT DO NOTHING + UPDATE …
 * WHERE NOT IN (inserted). Each CTE returns its own keys; we union and
 * count.
 */
async function upsertEntity(pool, args) {
  const { table, columns, rows, conflictKey, updateColumns } = args;
  if (rows.length === 0) return { inserted: 0, updated: 0 };

  const colNames = columns.map((c) => c.name).join(', ');
  const arrPlaceholders = columns.map((c, i) => `$${i + 1}::${c.type}[]`).join(', ');
  const updateAssign = updateColumns
    .map((c) => `${c} = i.${c}`)
    .concat(['updated_at = NOW()'])
    .join(', ');

  const sql = `
    WITH input AS (
      SELECT ${colNames} FROM unnest(${arrPlaceholders}) AS u(${colNames})
    ),
    inserted AS (
      INSERT INTO ${table} (${colNames})
      SELECT ${colNames} FROM input
      ON CONFLICT (${conflictKey}) DO NOTHING
      RETURNING ${conflictKey}
    ),
    updated AS (
      UPDATE ${table} t SET ${updateAssign}
      FROM input i
      WHERE t.${conflictKey} = i.${conflictKey}
        AND t.${conflictKey} NOT IN (SELECT ${conflictKey} FROM inserted)
      RETURNING t.${conflictKey}
    )
    SELECT 'inserted' AS kind FROM inserted
    UNION ALL
    SELECT 'updated'  AS kind FROM updated
  `;

  // pg interpolates JS arrays as Postgres arrays; nulls handled.
  const params = columns.map((c) => rows.map((r) => r[c.name] ?? null));
  const res = await pool.query(sql, params);
  let inserted = 0, updated = 0;
  for (const row of res.rows) (row.kind === 'inserted' ? inserted++ : updated++);
  return { inserted, updated };
}

// --- Entity column specs ----------------------------------------------------

const TACTIC_COLS = [
  { name: 'stix_id', type: 'text' },
  { name: 'attack_id', type: 'text' },
  { name: 'name', type: 'text' },
  { name: 'description', type: 'text' },
  { name: 'url', type: 'text' },
  { name: 'sort_order', type: 'int4' },
  { name: 'domain', type: 'text' },
  { name: 'stix_created', type: 'timestamptz' },
  { name: 'stix_modified', type: 'timestamptz' },
];
const TACTIC_UPDATE = ['attack_id', 'name', 'description', 'url', 'sort_order', 'domain', 'stix_modified'];

const TECHNIQUE_COLS = [
  { name: 'stix_id', type: 'text' },
  { name: 'attack_id', type: 'text' },
  { name: 'name', type: 'text' },
  { name: 'description', type: 'text' },
  { name: 'url', type: 'text' },
  { name: 'platforms', type: 'text' },     // STORED as text[] but pass as text via array literal
  { name: 'is_subtechnique', type: 'bool' },
  { name: 'detection', type: 'text' },
  { name: 'is_revoked', type: 'bool' },
  { name: 'is_deprecated', type: 'bool' },
  { name: 'revoked_by_stix_id', type: 'text' },
  { name: 'domain', type: 'text' },
  { name: 'stix_created', type: 'timestamptz' },
  { name: 'stix_modified', type: 'timestamptz' },
];
const TECHNIQUE_UPDATE = [
  'attack_id', 'name', 'description', 'url', 'platforms',
  'is_subtechnique', 'detection', 'is_revoked', 'is_deprecated',
  'revoked_by_stix_id', 'domain', 'stix_modified',
];

const MITIGATION_COLS = [
  { name: 'stix_id', type: 'text' },
  { name: 'attack_id', type: 'text' },
  { name: 'name', type: 'text' },
  { name: 'description', type: 'text' },
  { name: 'url', type: 'text' },
  { name: 'is_revoked', type: 'bool' },
  { name: 'is_deprecated', type: 'bool' },
  { name: 'domain', type: 'text' },
  { name: 'stix_created', type: 'timestamptz' },
  { name: 'stix_modified', type: 'timestamptz' },
];
const MITIGATION_UPDATE = ['attack_id', 'name', 'description', 'url', 'is_revoked', 'is_deprecated', 'domain', 'stix_modified'];

const DATA_SOURCE_COLS = MITIGATION_COLS;       // same shape
const DATA_SOURCE_UPDATE = MITIGATION_UPDATE;

const DATA_COMPONENT_COLS = [
  { name: 'stix_id', type: 'text' },
  { name: 'name', type: 'text' },
  { name: 'description', type: 'text' },
  { name: 'data_source_id', type: 'uuid' },
  { name: 'is_revoked', type: 'bool' },
  { name: 'is_deprecated', type: 'bool' },
  { name: 'domain', type: 'text' },
  { name: 'stix_created', type: 'timestamptz' },
  { name: 'stix_modified', type: 'timestamptz' },
];
const DATA_COMPONENT_UPDATE = ['name', 'description', 'data_source_id', 'is_revoked', 'is_deprecated', 'domain', 'stix_modified'];

// --- Merge helpers ----------------------------------------------------------

function mergeByStixId(extracted, key) {
  // Keep first occurrence per stix_id across all domain extractions.
  const m = new Map();
  for (const domain of Object.keys(extracted)) {
    for (const e of extracted[domain][key] ?? []) {
      if (e.stix_id && !m.has(e.stix_id)) m.set(e.stix_id, e);
    }
  }
  return [...m.values()];
}

// --- Main -------------------------------------------------------------------

async function main() {
  const args = parseArgs();
  const pool = new pg.Pool({
    connectionString: DATABASE_URL,
    max: 4,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 15_000,
    keepAlive: true,
  });
  pool.on('error', (err) => console.error('[attack-update] pool error:', err.message));

  const startedAt = Date.now();

  // Concurrency: refuse to start if another update is mid-flight.
  const locked = await acquireAdvisoryLock(pool);
  if (!locked) {
    console.error('[attack-update] another update is already running — bailing out');
    await pool.end();
    process.exit(2);
  }

  let logId;
  const counters = { entitiesUpserted: 0, entitiesSkipped: 0, perTable: {} };
  let detectedVersion = null;

  try {
    logId = await insertLogStart(pool);
    console.log(`[attack-update] starting logId=${logId} domains=${args.domains.join(',')} dryRun=${args.dryRun} force=${args.force}`);

    // Fetch + extract all domains
    const tmpDir = fs.mkdtempSync(path.join('/tmp', 'attack-update-'));
    const extracted = {};
    for (const domain of args.domains) {
      const stixPath = path.join(tmpDir, `${domain}.json`);
      await fetchStixBundle(domain, stixPath);
      detectedVersion = detectedVersion ?? readSpecVersion(stixPath);
      console.log(`[attack-update] extracting ${domain}…`);
      extracted[domain] = extractStixDomain(domain, stixPath);
      console.log(`[attack-update]   ${domain}: techniques=${extracted[domain].techniques?.length ?? 0} groups=${extracted[domain].threat_groups?.length ?? 0} tactics=${extracted[domain].tactics?.length ?? 0}`);
    }

    // Version guard — STIX bundle's spec version must be strictly greater
    // than the last successful run's recorded version (defense against a
    // stale CDN response silently no-op'ing the run).
    const lastVersion = await getLastVersion(pool);
    if (!args.force && lastVersion && detectedVersion && detectedVersion <= lastVersion) {
      throw new Error(`STIX spec version ${detectedVersion} not strictly greater than last successful run (${lastVersion}). Use --force to override.`);
    }
    console.log(`[attack-update] STIX spec version ${detectedVersion ?? 'unknown'} (last successful: ${lastVersion ?? 'none'})`);

    if (args.dryRun) {
      console.log('[attack-update] DRY-RUN: skipping all UPSERTs. Counts above are projected delta.');
      await updateLogDone(pool, logId, 'success', counters, {
        domains: args.domains, dryRun: true, attackVersion: detectedVersion,
        elapsedMs: Date.now() - startedAt,
      }, null);
      return;
    }

    // --- Tactics (no cross-domain sharing — kill_chain_phase shortnames are
    //     per domain). Merge by stix_id, single UPSERT pass.
    {
      const rows = mergeByStixId(extracted, 'tactics');
      const r = await upsertEntity(pool, {
        table: 'tactics', columns: TACTIC_COLS, rows,
        conflictKey: 'stix_id', updateColumns: TACTIC_UPDATE,
      });
      counters.perTable.tactics = r;
      counters.entitiesUpserted += r.inserted + r.updated;
      console.log(`[attack-update] tactics:           +${r.inserted} new / ~${r.updated} updated`);
    }

    // --- Techniques (parents first, then sub-techniques). The
    //     parent_technique_id FK is set in a second pass after parents are
    //     in the DB.
    {
      const all = mergeByStixId(extracted, 'techniques');
      // First pass: insert/update WITHOUT parent linkage. Parents have
      // is_subtechnique=false; subs have is_subtechnique=true. We upsert
      // both in one shot — parent_technique_id is set in a second pass.
      const r = await upsertEntity(pool, {
        table: 'techniques', columns: TECHNIQUE_COLS, rows: all,
        conflictKey: 'stix_id', updateColumns: TECHNIQUE_UPDATE,
      });
      counters.perTable.techniques = r;
      counters.entitiesUpserted += r.inserted + r.updated;
      console.log(`[attack-update] techniques:        +${r.inserted} new / ~${r.updated} updated`);

      // Second pass: link sub-technique parents by attack_id.
      const subs = all.filter((t) => t.is_subtechnique && t.parent_attack_id);
      if (subs.length > 0) {
        const childIds = subs.map((t) => t.attack_id);
        const parentIds = subs.map((t) => t.parent_attack_id);
        await pool.query(
          `UPDATE techniques c SET parent_technique_id = p.id
             FROM techniques p,
                  unnest($1::text[], $2::text[]) AS u(child_aid, parent_aid)
            WHERE c.attack_id = u.child_aid
              AND p.attack_id = u.parent_aid`,
          [childIds, parentIds],
        );
        console.log(`[attack-update]   linked ${subs.length} sub-techniques to parents`);
      }
    }

    // --- Mitigations (single domain, simple UPSERT)
    {
      const rows = mergeByStixId(extracted, 'mitigations');
      const r = await upsertEntity(pool, {
        table: 'mitigations', columns: MITIGATION_COLS, rows,
        conflictKey: 'stix_id', updateColumns: MITIGATION_UPDATE,
      });
      counters.perTable.mitigations = r;
      counters.entitiesUpserted += r.inserted + r.updated;
      console.log(`[attack-update] mitigations:       +${r.inserted} new / ~${r.updated} updated`);
    }

    // --- Data sources
    {
      const rows = mergeByStixId(extracted, 'data_sources');
      const r = await upsertEntity(pool, {
        table: 'data_sources', columns: DATA_SOURCE_COLS, rows,
        conflictKey: 'stix_id', updateColumns: DATA_SOURCE_UPDATE,
      });
      counters.perTable.data_sources = r;
      counters.entitiesUpserted += r.inserted + r.updated;
      console.log(`[attack-update] data_sources:      +${r.inserted} new / ~${r.updated} updated`);
    }

    // --- Data components (FK to data_sources via data_source_stix_id → resolve to UUID first)
    {
      const merged = mergeByStixId(extracted, 'data_components');
      const dsLookup = await pool.query('SELECT id, stix_id FROM data_sources');
      const stixToId = new Map(dsLookup.rows.map((r) => [r.stix_id, r.id]));
      const rows = merged
        .map((dc) => ({ ...dc, data_source_id: stixToId.get(dc.data_source_stix_id) ?? null }))
        .filter((dc) => dc.data_source_id != null);
      const skipped = merged.length - rows.length;
      if (skipped > 0) console.warn(`[attack-update]   ${skipped} data_components skipped — parent data_source not found`);

      const r = await upsertEntity(pool, {
        table: 'data_components', columns: DATA_COMPONENT_COLS, rows,
        conflictKey: 'stix_id', updateColumns: DATA_COMPONENT_UPDATE,
      });
      counters.perTable.data_components = r;
      counters.entitiesUpserted += r.inserted + r.updated;
      counters.entitiesSkipped += skipped;
      console.log(`[attack-update] data_components:   +${r.inserted} new / ~${r.updated} updated (skipped ${skipped})`);
    }

    // Cross-domain entities (groups/software/campaigns) — Chunk 3.4 (next commit).
    // Relations — Chunk 4.
    // Verification harness — Chunk 5.

    const elapsedMs = Date.now() - startedAt;
    console.log(`[attack-update] done in ${elapsedMs}ms — entities: +${counters.entitiesUpserted} touched`);
    await updateLogDone(pool, logId, 'success', counters, {
      domains: args.domains, dryRun: false, attackVersion: detectedVersion,
      perTable: counters.perTable, elapsedMs,
    }, null);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('[attack-update] fatal:', err);
    if (logId) {
      try { await updateLogDone(pool, logId, 'error', counters, { elapsedMs: Date.now() - startedAt }, msg); }
      catch (logErr) { console.error('[attack-update] also failed to write error log:', logErr); }
    }
    throw err;
  } finally {
    try { await releaseAdvisoryLock(pool); } catch { /* ignore */ }
    await pool.end();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
