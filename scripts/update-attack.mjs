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
import crypto from 'node:crypto';
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
  // Dry-runs are excluded — they don't actually advance the DB state, so
  // they shouldn't gate the next real run.
  const r = await pool.query(
    `SELECT metadata->>'attackVersion' AS v
     FROM feed_sync_log
     WHERE source='attack_update'
       AND status='success'
       AND COALESCE(metadata->>'dryRun', 'false') <> 'true'
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

function readBundleVersions(stixPath) {
  // Two distinct version concepts in a STIX bundle:
  //   - x_mitre_version on the x-mitre-collection object → release version
  //     ("19.0", "18.1") — what the dashboard displays.
  //   - x_mitre_attack_spec_version → STIX format spec version ("3.3.0").
  // We use attackVersion for both the dashboard label AND the strictly-greater
  // version guard (it's the per-release identifier; spec version changes rarely).
  const bundle = JSON.parse(fs.readFileSync(stixPath, 'utf8'));
  for (const obj of bundle.objects ?? []) {
    if (obj.type === 'x-mitre-collection') {
      return {
        attackVersion: obj.x_mitre_version ?? null,
        specVersion: obj.x_mitre_attack_spec_version ?? null,
        collectionName: obj.name ?? null,
      };
    }
  }
  return { attackVersion: null, specVersion: null, collectionName: null };
}

function bundleHash(stixPath) {
  // sha256 of the raw bundle bytes — stored in seed_metadata.stix_bundle_hash
  // so a re-run on the same upstream bundle is detectable in the audit log.
  return crypto.createHash('sha256').update(fs.readFileSync(stixPath)).digest('hex');
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

// Cross-domain entities — `domain` column is TEXT[] (post preflight A).
const GROUP_COLS = [
  { name: 'stix_id', type: 'text' },
  { name: 'attack_id', type: 'text' },
  { name: 'name', type: 'text' },
  { name: 'description', type: 'text' },
  { name: 'url', type: 'text' },
  { name: 'aliases', type: 'text[]' },
  { name: 'is_revoked', type: 'bool' },
  { name: 'is_deprecated', type: 'bool' },
  { name: 'domain', type: 'text[]' },
  { name: 'stix_created', type: 'timestamptz' },
  { name: 'stix_modified', type: 'timestamptz' },
];
const GROUP_UPDATE = ['attack_id', 'name', 'description', 'url', 'aliases', 'is_revoked', 'is_deprecated', 'domain', 'stix_modified'];

const SOFTWARE_COLS = [
  { name: 'stix_id', type: 'text' },
  { name: 'attack_id', type: 'text' },
  { name: 'name', type: 'text' },
  { name: 'description', type: 'text' },
  { name: 'url', type: 'text' },
  { name: 'type', type: 'text' },
  { name: 'platforms', type: 'text[]' },
  { name: 'aliases', type: 'text[]' },
  { name: 'is_revoked', type: 'bool' },
  { name: 'is_deprecated', type: 'bool' },
  { name: 'domain', type: 'text[]' },
  { name: 'stix_created', type: 'timestamptz' },
  { name: 'stix_modified', type: 'timestamptz' },
];
const SOFTWARE_UPDATE = ['attack_id', 'name', 'description', 'url', 'type', 'platforms', 'aliases', 'is_revoked', 'is_deprecated', 'domain', 'stix_modified'];

const CAMPAIGN_COLS = [
  { name: 'stix_id', type: 'text' },
  { name: 'attack_id', type: 'text' },
  { name: 'name', type: 'text' },
  { name: 'description', type: 'text' },
  { name: 'url', type: 'text' },
  { name: 'aliases', type: 'text[]' },
  { name: 'first_seen', type: 'timestamptz' },
  { name: 'last_seen', type: 'timestamptz' },
  { name: 'is_revoked', type: 'bool' },
  { name: 'is_deprecated', type: 'bool' },
  { name: 'domain', type: 'text[]' },
  { name: 'stix_created', type: 'timestamptz' },
  { name: 'stix_modified', type: 'timestamptz' },
];
const CAMPAIGN_UPDATE = ['attack_id', 'name', 'description', 'url', 'aliases', 'first_seen', 'last_seen', 'is_revoked', 'is_deprecated', 'domain', 'stix_modified'];

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

/**
 * Cross-domain merge: collects every domain an entity appeared in across
 * the per-domain extractions. Used for groups/software/campaigns where
 * APT28 (G0007) lives in both Enterprise + ICS bundles. Returns rows
 * with `domain` overridden to a deduped string array.
 */
function mergeByStixIdWithDomains(extracted, key) {
  const m = new Map();
  for (const domain of Object.keys(extracted)) {
    for (const e of extracted[domain][key] ?? []) {
      if (!e.stix_id) continue;
      let entry = m.get(e.stix_id);
      if (!entry) {
        entry = { entity: { ...e }, domains: new Set() };
        m.set(e.stix_id, entry);
      }
      entry.domains.add(domain);
    }
  }
  return [...m.values()].map(({ entity, domains }) => ({
    ...entity,
    domain: [...domains],
  }));
}

/**
 * Cross-domain UPSERT: domain column is TEXT[] (post preflight A migration).
 * Two-stage:
 *   1. INSERT … ON CONFLICT DO NOTHING — captures genuine inserts.
 *   2. UPDATE existing rows MERGING the domain array (array_agg DISTINCT).
 *
 * Input shape: rows array, with row.domain as JS array of domain strings.
 * jsonb_array_elements lets us pass arbitrary-shaped rows in one param.
 */
async function upsertCrossDomainEntity(pool, args) {
  const { table, columns, rows, conflictKey, updateColumns } = args;
  if (rows.length === 0) return { inserted: 0, updated: 0 };

  // Build SELECT-from-jsonb expression list.
  const selectExprs = columns.map((c) => {
    if (c.name === 'domain') {
      // text[] from JSON array
      return `(SELECT array_agg(d) FROM jsonb_array_elements_text(r->'domain') AS d) AS domain`;
    }
    if (c.type === 'text[]') {
      return `(SELECT array_agg(d) FROM jsonb_array_elements_text(r->'${c.name}') AS d) AS ${c.name}`;
    }
    if (c.type === 'timestamptz') return `NULLIF(r->>'${c.name}', '')::timestamptz AS ${c.name}`;
    if (c.type === 'bool') return `(r->>'${c.name}')::bool AS ${c.name}`;
    if (c.type === 'int4') return `(r->>'${c.name}')::int4 AS ${c.name}`;
    return `r->>'${c.name}' AS ${c.name}`;
  }).join(', ');
  const colList = columns.map((c) => c.name).join(', ');
  const json = JSON.stringify(rows);

  // Stage 1: pure inserts
  const insSql = `
    WITH input AS (
      SELECT ${selectExprs} FROM jsonb_array_elements($1::jsonb) AS r
    )
    INSERT INTO ${table} (${colList})
    SELECT ${colList} FROM input
    ON CONFLICT (${conflictKey}) DO NOTHING
    RETURNING ${conflictKey}
  `;
  const insRes = await pool.query(insSql, [json]);
  const insertedKeys = new Set(insRes.rows.map((r) => r[conflictKey]));

  // Stage 2: update existing — merge domain arrays, refresh other cols.
  const updateAssign = updateColumns
    .map((c) => {
      if (c === 'domain') {
        return `domain = (SELECT array_agg(DISTINCT d) FROM unnest(${table}.domain || i.domain) AS d)`;
      }
      return `${c} = i.${c}`;
    })
    .concat(['updated_at = NOW()'])
    .join(', ');

  const updSql = `
    WITH input AS (
      SELECT ${selectExprs} FROM jsonb_array_elements($1::jsonb) AS r
    )
    UPDATE ${table} t SET ${updateAssign}
    FROM input i
    WHERE t.${conflictKey} = i.${conflictKey}
      AND t.${conflictKey} <> ALL($2::text[])
    RETURNING t.${conflictKey}
  `;
  const updRes = await pool.query(updSql, [json, [...insertedKeys]]);
  const updatedCount = updRes.rowCount ?? 0;

  return { inserted: insertedKeys.size, updated: updatedCount };
}

// --- Relation reconciler ----------------------------------------------------

/**
 * Bulk insert-then-delete-orphans across one relation table. Single pass:
 *   1. INSERT every (parent, child) pair from STIX (with description if any),
 *      ON CONFLICT DO UPDATE the description column.
 *   2. DELETE pairs where parent is in the new set BUT the (parent, child)
 *      pair is no longer in the new set.
 *
 * Scoping the DELETE to parents-in-the-new-set is critical: it stops us
 * accidentally wiping relations belonging to entities not present in this
 * run's bundles (e.g., revoked groups).
 *
 * Cross-domain merge: deduplicate by (parent_stix_id, child_stix_id) across
 * all extracted domains so APT28's Enterprise + ICS technique sets unify
 * into one reconcile pass.
 */
async function reconcileBulk(pool, args) {
  const { key, table, parentCol, childCol, descCol, parentField, childField, parentKey, childKey, lookups, extracted } = args;

  // Cross-domain merge by (parent_stix_id, child_stix_id) — keep first-seen
  // description, dedupe pairs across bundles.
  const seen = new Map(); // "p|c" → row
  for (const domain of Object.keys(extracted)) {
    for (const r of extracted[domain][key] ?? []) {
      const compositeKey = `${r[parentField]}|${r[childField]}`;
      if (!seen.has(compositeKey)) seen.set(compositeKey, r);
    }
  }

  // Resolve stix_ids → UUIDs, drop pairs where either side is missing.
  const parentIds = [];
  const childIds = [];
  const descriptions = [];
  let unresolved = 0;
  for (const r of seen.values()) {
    const p = lookups[parentKey].get(r[parentField]);
    const c = lookups[childKey].get(r[childField]);
    if (!p || !c) { unresolved++; continue; }
    parentIds.push(p);
    childIds.push(c);
    if (descCol) descriptions.push(r.description ?? null);
  }
  if (unresolved > 0) console.warn(`[attack-update]   ${table}: ${unresolved} relations skipped — parent or child stix_id not in DB`);
  if (parentIds.length === 0) return { touched: 0, removed: 0, unresolved };

  // Stage 1: insert + on-conflict-update
  if (descCol) {
    await pool.query(
      `INSERT INTO ${table} (${parentCol}, ${childCol}, ${descCol})
       SELECT p::uuid, c::uuid, d
       FROM unnest($1::text[], $2::text[], $3::text[]) AS u(p, c, d)
       ON CONFLICT (${parentCol}, ${childCol}) DO UPDATE SET ${descCol} = EXCLUDED.${descCol}`,
      [parentIds, childIds, descriptions],
    );
  } else {
    await pool.query(
      `INSERT INTO ${table} (${parentCol}, ${childCol})
       SELECT p::uuid, c::uuid
       FROM unnest($1::text[], $2::text[]) AS u(p, c)
       ON CONFLICT (${parentCol}, ${childCol}) DO NOTHING`,
      [parentIds, childIds],
    );
  }

  // Stage 2: delete orphans, scoped to parents in this run.
  const delRes = await pool.query(
    `DELETE FROM ${table}
     WHERE ${parentCol} IN (SELECT DISTINCT p::uuid FROM unnest($1::text[]) AS p)
       AND (${parentCol}, ${childCol}) NOT IN (
         SELECT u.p::uuid, u.c::uuid FROM unnest($1::text[], $2::text[]) AS u(p, c)
       )`,
    [parentIds, childIds],
  );

  return { touched: parentIds.length, removed: delRes.rowCount ?? 0, unresolved };
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
    const perDomainMeta = {};   // domain → { attackVersion, specVersion, hash, sourceUrl }
    for (const domain of args.domains) {
      const stixPath = path.join(tmpDir, `${domain}.json`);
      const sourceUrl = `${STIX_BASE}/${domain}/${domain}.json`;
      await fetchStixBundle(domain, stixPath);
      const v = readBundleVersions(stixPath);
      perDomainMeta[domain] = {
        attackVersion: v.attackVersion,
        specVersion: v.specVersion,
        hash: bundleHash(stixPath),
        sourceUrl,
      };
      detectedVersion = detectedVersion ?? v.attackVersion;
      console.log(`[attack-update] extracting ${domain}… (v${v.attackVersion ?? '?'} spec ${v.specVersion ?? '?'})`);
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

    // --- Cross-domain entities — domain TEXT[] merge across bundle passes
    {
      const rows = mergeByStixIdWithDomains(extracted, 'threat_groups');
      const r = await upsertCrossDomainEntity(pool, {
        table: 'threat_groups', columns: GROUP_COLS, rows,
        conflictKey: 'stix_id', updateColumns: GROUP_UPDATE,
      });
      counters.perTable.threat_groups = r;
      counters.entitiesUpserted += r.inserted + r.updated;
      console.log(`[attack-update] threat_groups:     +${r.inserted} new / ~${r.updated} updated`);
    }

    {
      const rows = mergeByStixIdWithDomains(extracted, 'attack_software');
      const r = await upsertCrossDomainEntity(pool, {
        table: 'attack_software', columns: SOFTWARE_COLS, rows,
        conflictKey: 'stix_id', updateColumns: SOFTWARE_UPDATE,
      });
      counters.perTable.attack_software = r;
      counters.entitiesUpserted += r.inserted + r.updated;
      console.log(`[attack-update] attack_software:   +${r.inserted} new / ~${r.updated} updated`);
    }

    {
      const rows = mergeByStixIdWithDomains(extracted, 'campaigns');
      const r = await upsertCrossDomainEntity(pool, {
        table: 'campaigns', columns: CAMPAIGN_COLS, rows,
        conflictKey: 'stix_id', updateColumns: CAMPAIGN_UPDATE,
      });
      counters.perTable.campaigns = r;
      counters.entitiesUpserted += r.inserted + r.updated;
      console.log(`[attack-update] campaigns:         +${r.inserted} new / ~${r.updated} updated`);
    }

    // --- Relations: bulk insert-then-delete-orphans across 9 join tables.
    //     One reconcile per table, scoped to parents in the new STIX so we
    //     don't accidentally wipe relations belonging to entities not in
    //     this run's bundles.
    {
      // Build stix_id → DB UUID lookup maps for every entity type referenced.
      console.log(`[attack-update] building stix_id → uuid lookup maps for relations…`);
      const lookups = {};
      for (const [key, table] of [
        ['techniques', 'techniques'],
        ['tactics', 'tactics'],
        ['threat_groups', 'threat_groups'],
        ['attack_software', 'attack_software'],
        ['mitigations', 'mitigations'],
        ['campaigns', 'campaigns'],
        ['data_components', 'data_components'],
      ]) {
        const r = await pool.query(`SELECT stix_id, id FROM ${table}`);
        lookups[key] = new Map(r.rows.map((row) => [row.stix_id, row.id]));
        console.log(`[attack-update]   ${key}: ${lookups[key].size} entries`);
      }

      const relations = [
        { key: 'technique_tactics',         table: 'technique_tactics',         parentKey: 'techniques',      parentCol: 'technique_id', childKey: 'tactics',         childCol: 'tactic_id',         parentField: 'technique_stix_id', childField: 'tactic_stix_id',        descCol: null },
        { key: 'group_techniques',          table: 'group_techniques',          parentKey: 'threat_groups',   parentCol: 'group_id',     childKey: 'techniques',      childCol: 'technique_id',      parentField: 'group_stix_id',     childField: 'technique_stix_id',     descCol: 'description' },
        { key: 'group_software',            table: 'group_software',            parentKey: 'threat_groups',   parentCol: 'group_id',     childKey: 'attack_software', childCol: 'software_id',       parentField: 'group_stix_id',     childField: 'software_stix_id',      descCol: 'description' },
        { key: 'software_techniques',       table: 'software_techniques',       parentKey: 'attack_software', parentCol: 'software_id',  childKey: 'techniques',      childCol: 'technique_id',      parentField: 'software_stix_id',  childField: 'technique_stix_id',     descCol: 'description' },
        { key: 'mitigation_techniques',     table: 'mitigation_techniques',     parentKey: 'mitigations',     parentCol: 'mitigation_id',childKey: 'techniques',      childCol: 'technique_id',      parentField: 'mitigation_stix_id',childField: 'technique_stix_id',     descCol: 'description' },
        { key: 'campaign_techniques',       table: 'campaign_techniques',       parentKey: 'campaigns',       parentCol: 'campaign_id',  childKey: 'techniques',      childCol: 'technique_id',      parentField: 'campaign_stix_id',  childField: 'technique_stix_id',     descCol: 'description' },
        { key: 'campaign_software',         table: 'campaign_software',         parentKey: 'campaigns',       parentCol: 'campaign_id',  childKey: 'attack_software', childCol: 'software_id',       parentField: 'campaign_stix_id',  childField: 'software_stix_id',      descCol: 'description' },
        { key: 'group_campaigns',           table: 'group_campaigns',           parentKey: 'threat_groups',   parentCol: 'group_id',     childKey: 'campaigns',       childCol: 'campaign_id',       parentField: 'group_stix_id',     childField: 'campaign_stix_id',      descCol: 'description' },
        { key: 'technique_data_components', table: 'technique_data_components', parentKey: 'techniques',      parentCol: 'technique_id', childKey: 'data_components', childCol: 'data_component_id',parentField: 'technique_stix_id', childField: 'data_component_stix_id',descCol: null },
      ];

      for (const rel of relations) {
        const r = await reconcileBulk(pool, { ...rel, lookups, extracted });
        counters.perTable[rel.table] = r;
        console.log(`[attack-update] ${rel.table.padEnd(28)}: +${r.touched} edges touched / -${r.removed} orphans`);
      }
    }

    // --- seed_metadata: one row per domain so the dashboard ATT&CK Version
    //     widget reflects the new release. The seed_metadata table is
    //     append-only — newest seeded_at wins for the dashboard query.
    {
      for (const domain of args.domains) {
        const m = perDomainMeta[domain];
        const counts = {
          tactics: extracted[domain].tactics?.length ?? 0,
          techniques: extracted[domain].techniques?.length ?? 0,
          threat_groups: extracted[domain].threat_groups?.length ?? 0,
          attack_software: extracted[domain].attack_software?.length ?? 0,
          mitigations: extracted[domain].mitigations?.length ?? 0,
          campaigns: extracted[domain].campaigns?.length ?? 0,
          data_sources: extracted[domain].data_sources?.length ?? 0,
          data_components: extracted[domain].data_components?.length ?? 0,
        };
        await pool.query(
          `INSERT INTO seed_metadata (attack_version, domain, stix_bundle_hash, source_url, seeded_at, entity_counts, seed_duration_ms, seeded_by)
           VALUES ($1, $2, $3, $4, NOW(), $5::jsonb, $6, 'update-attack.mjs')`,
          [
            m.attackVersion,
            domain,
            m.hash,
            m.sourceUrl,
            JSON.stringify(counts),
            Date.now() - startedAt,
          ],
        );
      }
      console.log(`[attack-update] seed_metadata: wrote ${args.domains.length} rows for v${detectedVersion}`);
    }

    // --- Verification harness — Chunk 5 (next commit).

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
