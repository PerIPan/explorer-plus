#!/usr/bin/env node
// scripts/backfill-ics-assets.mjs
//
// One-shot backfill for ATT&CK ICS assets + the Purdue Model layer.
//
// WHY A SEPARATE SCRIPT rather than hanging this off scripts/update-attack.mjs:
//
//   1. update-attack.yml is `workflow_dispatch:` only — there is no schedule.
//      MITRE ships roughly twice a year and the workflow is a deliberate human
//      review gate, so merging asset support alone would leave /assets empty in
//      production until someone manually dispatched a release run.
//
//   2. update-attack.mjs throws when the fetched bundle version is not strictly
//      greater than the last successful run. Production has already absorbed the
//      current release, so the first post-merge run would exit rather than
//      backfill.
//
//   3. The obvious workaround — `--domains=ics-attack --force` — is DESTRUCTIVE.
//      reconcileBulk deletes (parent, child) pairs whose parent appears in the
//      current run but whose pair is absent from the new set. Groups such as
//      Sandworm and APT38 appear in BOTH the ICS and Enterprise bundles, so an
//      ICS-only run would delete all of their Enterprise group_techniques and
//      software_techniques edges. The snapshot guard does not catch it: the
//      drop threshold is table-wide (50%) and dual-domain groups are a minority.
//      scripts/update-attack.mjs now refuses partial-domain runs for this reason.
//
// This script therefore touches ONLY the asset tables. It never reconciles the
// nine shared relation tables, has no version guard (it is idempotent by
// stix_id), and takes its own advisory lock and feed_sync_log source.
//
// Once assets are added to update-attack.mjs's release path (separate commit,
// effective at the next MITRE release), this script remains useful for local
// development and for bootstrapping a fresh database.
//
// Usage:
//   DATABASE_URL=... node --experimental-strip-types scripts/backfill-ics-assets.mjs [--dry-run]

import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(__dirname, '..');

const STIX_URL = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json';
const STIX_PATH = resolve(REPO, 'data/ics-attack.json');
const FETCH_TIMEOUT_MS = 60_000;
const EXTRACT_BUFFER = 256 * 1024 * 1024;
// Distinct from update-attack.mjs's lock so the two can never be confused,
// but taken all the same so two backfills cannot interleave.
const ADVISORY_LOCK_KEY = 0x69637361; // 'icsa'

const args = {
  dryRun: process.argv.includes('--dry-run'),
  skipFetch: process.argv.includes('--skip-fetch'),
};

const DATABASE_URL = process.env.DATABASE_URL || process.env.POSTGRES_URL;
if (!DATABASE_URL) {
  console.error('DATABASE_URL (or POSTGRES_URL) required');
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Registry (curated Purdue layer)
// ---------------------------------------------------------------------------

async function loadRegistry() {
  try {
    return await import('../src/lib/purdue-registry.ts');
  } catch (e) {
    console.error('[ics-assets] cannot load TS registry — node must support --experimental-strip-types. Got:', e.message);
    throw e;
  }
}

// ---------------------------------------------------------------------------
// STIX fetch + extract
// ---------------------------------------------------------------------------

async function fetchStix() {
  if (args.skipFetch && existsSync(STIX_PATH)) {
    console.log(`[ics-assets] --skip-fetch: using existing ${STIX_PATH}`);
    return;
  }
  console.log(`[ics-assets] fetching ${STIX_URL}`);
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const resp = await fetch(STIX_URL, { signal: ctrl.signal });
    if (!resp.ok) throw new Error(`STIX fetch ${resp.status}`);
    const body = await resp.text();
    mkdirSync(dirname(STIX_PATH), { recursive: true });
    writeFileSync(STIX_PATH, body);
    console.log(`[ics-assets] wrote ${STIX_PATH} (${(body.length / 1e6).toFixed(1)} MB)`);
  } finally {
    clearTimeout(timer);
  }
}

function extractStix() {
  const python = existsSync(resolve(REPO, 'venv/bin/python'))
    ? resolve(REPO, 'venv/bin/python')
    : 'python3';
  const r = spawnSync(
    python,
    [resolve(REPO, 'seed/extract.py'), '--domain=ics-attack', `--stix-path=${STIX_PATH}`],
    { cwd: REPO, maxBuffer: EXTRACT_BUFFER, encoding: 'utf8' },
  );
  if (r.status !== 0) {
    throw new Error(`extract.py exited ${r.status}: ${(r.stderr || '').slice(0, 500)}`);
  }
  return JSON.parse(r.stdout);
}

// ---------------------------------------------------------------------------
// feed_sync_log
// ---------------------------------------------------------------------------

async function insertLogStart(pool) {
  await pool.query(
    `UPDATE feed_sync_log
       SET status='error', completed_at=NOW(),
           error_message='Stale (auto-cleaned on new run start)'
     WHERE source='ics_assets' AND status='running' AND started_at < NOW() - INTERVAL '30 minutes'`,
  );
  const r = await pool.query(
    `INSERT INTO feed_sync_log (source, status, started_at)
     VALUES ('ics_assets', 'running', NOW()) RETURNING id`,
  );
  return r.rows[0].id;
}

async function updateLogDone(pool, logId, status, stats, errorMessage) {
  await pool.query(
    `UPDATE feed_sync_log
        SET status=$1, completed_at=NOW(),
            records_inserted=$2, records_skipped=$3,
            metadata=$4, error_message=$5
      WHERE id=$6`,
    [
      status,
      stats.assetsUpserted ?? 0,
      stats.edgesUnresolved ?? 0,
      JSON.stringify({ ...stats, trigger: 'backfill-ics-assets' }),
      errorMessage?.slice(0, 500) ?? null,
      logId,
    ],
  );
}

// ---------------------------------------------------------------------------
// Writes
// ---------------------------------------------------------------------------

/** Two-CTE UPSERT via jsonb so text[] columns round-trip correctly. */
async function upsertAssets(client, rows) {
  if (rows.length === 0) return { inserted: 0, updated: 0 };
  const r = await client.query(
    `WITH incoming AS (
       SELECT
         r->>'stix_id'                                                        AS stix_id,
         r->>'attack_id'                                                      AS attack_id,
         r->>'name'                                                           AS name,
         r->>'description'                                                    AS description,
         r->>'url'                                                            AS url,
         (SELECT array_agg(d) FROM jsonb_array_elements_text(r->'sectors')   AS d) AS sectors,
         (SELECT array_agg(d) FROM jsonb_array_elements_text(r->'platforms') AS d) AS platforms,
         (r->>'is_revoked')::bool                                             AS is_revoked,
         (r->>'is_deprecated')::bool                                          AS is_deprecated,
         r->>'domain'                                                         AS domain,
         NULLIF(r->>'stix_created','')::timestamptz                           AS stix_created,
         NULLIF(r->>'stix_modified','')::timestamptz                          AS stix_modified
       FROM jsonb_array_elements($1::jsonb) AS r
     ),
     ins AS (
       INSERT INTO attack_assets
         (stix_id, attack_id, name, description, url, sectors, platforms,
          is_revoked, is_deprecated, domain, stix_created, stix_modified)
       SELECT stix_id, attack_id, name, description, url, sectors, platforms,
              is_revoked, is_deprecated, domain, stix_created, stix_modified
         FROM incoming
       ON CONFLICT (stix_id) DO NOTHING
       RETURNING 1
     ),
     upd AS (
       UPDATE attack_assets a
          SET attack_id     = i.attack_id,
              name          = i.name,
              description   = i.description,
              url           = i.url,
              sectors       = i.sectors,
              platforms     = i.platforms,
              is_revoked    = i.is_revoked,
              is_deprecated = i.is_deprecated,
              domain        = i.domain,
              stix_created  = i.stix_created,
              stix_modified = i.stix_modified,
              updated_at    = NOW()
         FROM incoming i
        WHERE a.stix_id = i.stix_id
       RETURNING 1
     )
     SELECT (SELECT count(*) FROM ins) AS inserted, (SELECT count(*) FROM upd) AS updated`,
    [JSON.stringify(rows)],
  );
  return { inserted: Number(r.rows[0].inserted), updated: Number(r.rows[0].updated) };
}

/**
 * Replace-set reconcile for asset_techniques. Scoped strictly to assets present
 * in THIS bundle — the same discipline update-attack.mjs uses — so it can never
 * touch anything outside the asset tables.
 */
async function reconcileAssetTechniques(client, edges) {
  const assetMap = new Map(
    (await client.query('SELECT stix_id, id FROM attack_assets')).rows.map((r) => [r.stix_id, r.id]),
  );
  const techMap = new Map(
    (await client.query("SELECT stix_id, id FROM techniques WHERE domain = 'ics-attack'")).rows
      .map((r) => [r.stix_id, r.id]),
  );

  const assetIds = [];
  const techIds = [];
  let unresolved = 0;
  const seen = new Set();
  for (const e of edges) {
    const a = assetMap.get(e.asset_stix_id);
    const t = techMap.get(e.technique_stix_id);
    if (!a || !t) { unresolved++; continue; }
    const k = `${a}|${t}`;
    if (seen.has(k)) continue;
    seen.add(k);
    assetIds.push(a);
    techIds.push(t);
  }

  if (assetIds.length > 0) {
    await client.query(
      `INSERT INTO asset_techniques (asset_id, technique_id)
       SELECT u.a::uuid, u.t::uuid FROM unnest($1::uuid[], $2::uuid[]) AS u(a, t)
       ON CONFLICT (asset_id, technique_id) DO NOTHING`,
      [assetIds, techIds],
    );
  }
  // Delete pairs whose asset is in this run but whose edge is gone upstream.
  const del = await client.query(
    `DELETE FROM asset_techniques at
      WHERE at.asset_id = ANY($1::uuid[])
        AND NOT EXISTS (
          SELECT 1 FROM unnest($1::uuid[], $2::uuid[]) AS u(a, t)
           WHERE u.a = at.asset_id AND u.t = at.technique_id
        )`,
    [assetIds.length ? assetIds : [null], techIds.length ? techIds : [null]],
  );
  return { linked: assetIds.length, removed: del.rowCount ?? 0, unresolved };
}

async function reconcileRelatedAssets(client, rows) {
  const assetMap = new Map(
    (await client.query('SELECT stix_id, id FROM attack_assets')).rows.map((r) => [r.stix_id, r.id]),
  );
  // jsonb input, not parallel-array unnest: related_sectors is a text[] PER ROW,
  // and unnest($n::text[][]) cannot carry a ragged array-of-arrays — Postgres
  // rejects it as a malformed array literal. Same reason update-attack.mjs's
  // upsertEntity takes jsonb.
  const payload = [];
  const ids = [], names = [];
  for (const r of rows) {
    const a = assetMap.get(r.asset_stix_id);
    if (!a) continue;
    ids.push(a); names.push(r.related_name);
    payload.push({
      asset_id: a,
      related_name: r.related_name,
      related_sectors: r.related_sectors ?? [],
      description: r.description ?? null,
    });
  }
  if (payload.length === 0) return { linked: 0, removed: 0 };
  await client.query(
    `WITH incoming AS (
       SELECT (r->>'asset_id')::uuid AS asset_id,
              r->>'related_name'     AS related_name,
              (SELECT array_agg(d) FROM jsonb_array_elements_text(r->'related_sectors') AS d) AS related_sectors,
              r->>'description'      AS description
         FROM jsonb_array_elements($1::jsonb) AS r
     )
     INSERT INTO asset_related_assets (asset_id, related_name, related_sectors, description)
     SELECT asset_id, related_name, related_sectors, description FROM incoming
     ON CONFLICT (asset_id, related_name) DO UPDATE
        SET related_sectors = EXCLUDED.related_sectors,
            description     = EXCLUDED.description`,
    [JSON.stringify(payload)],
  );
  const del = await client.query(
    `DELETE FROM asset_related_assets ara
      WHERE ara.asset_id = ANY($1::uuid[])
        AND NOT EXISTS (
          SELECT 1 FROM unnest($1::uuid[], $2::text[]) AS u(a, n)
           WHERE u.a = ara.asset_id AND u.n = ara.related_name
        )`,
    [ids, names],
  );
  return { linked: ids.length, removed: del.rowCount ?? 0 };
}

async function seedCuratedLayer(client, reg) {
  // Levels
  for (const l of reg.PURDUE_LEVELS) {
    await client.query(
      `INSERT INTO purdue_levels (level_key, label, zone, description, sort_order)
       VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (level_key) DO UPDATE
          SET label=EXCLUDED.label, zone=EXCLUDED.zone,
              description=EXCLUDED.description, sort_order=EXCLUDED.sort_order`,
      [l.level_key, l.label, l.zone, l.description, l.sort_order],
    );
  }

  // Placements — joined to attack_assets on attack_id so the composite FK holds.
  let placed = 0;
  for (const p of reg.ASSET_PLACEMENTS) {
    const r = await client.query(
      `INSERT INTO asset_purdue_placement
         (asset_id, attack_id, primary_level, spans_levels, rationale)
       SELECT a.id, a.attack_id, $2, $3::text[], $4
         FROM attack_assets a WHERE a.attack_id = $1
       ON CONFLICT (asset_id) DO UPDATE
          SET primary_level = EXCLUDED.primary_level,
              spans_levels  = EXCLUDED.spans_levels,
              rationale     = EXCLUDED.rationale,
              updated_at    = NOW()
       RETURNING 1`,
      [p.attack_id, p.primary_level, p.spans_levels, p.rationale],
    );
    placed += r.rowCount ?? 0;
  }

  // Flow rules
  for (const f of reg.PURDUE_FLOW_RULES) {
    await client.query(
      `INSERT INTO purdue_flow_rules (from_level, to_level, direct_allowed, broker_level, note)
       VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (from_level, to_level) DO UPDATE
          SET direct_allowed=EXCLUDED.direct_allowed,
              broker_level=EXCLUDED.broker_level,
              note=EXCLUDED.note`,
      [f.from_level, f.to_level, f.direct_allowed, f.broker_level ?? null, f.note ?? null],
    );
  }

  return { levels: reg.PURDUE_LEVELS.length, placed, rules: reg.PURDUE_FLOW_RULES.length };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

const stats = {};
const pool = new pg.Pool({ connectionString: DATABASE_URL, max: 3 });
let logId;
const startedAt = Date.now();

try {
  const reg = await loadRegistry();

  // Fail loud BEFORE touching the database: a bad curation edit must never
  // land half-applied.
  const regErrors = reg.validateRegistry();
  if (regErrors.length) {
    throw new Error(`purdue-registry.ts is invalid:\n  - ${regErrors.join('\n  - ')}`);
  }
  console.log(`[ics-assets] registry OK: ${reg.PURDUE_LEVELS.length} levels, ${reg.ASSET_PLACEMENTS.length} placements, ${reg.PURDUE_FLOW_RULES.length} flow rules`);

  await fetchStix();
  const extracted = extractStix();
  const assets = extracted.attack_assets ?? [];
  const edges = extracted.asset_techniques ?? [];
  const related = extracted.asset_related_assets ?? [];
  console.log(`[ics-assets] extracted ${assets.length} assets, ${edges.length} technique edges, ${related.length} related-asset rows`);

  if (assets.length === 0) throw new Error('no assets extracted — refusing to proceed');

  // Every asset MITRE ships must have a curated Purdue placement. If a release
  // adds A0019, this fails the run rather than rendering an unplaced asset.
  const placedIds = new Set(reg.ASSET_PLACEMENTS.map((p) => p.attack_id));
  const unplaced = assets.filter((a) => !placedIds.has(a.attack_id)).map((a) => `${a.attack_id} ${a.name}`);
  if (unplaced.length) {
    throw new Error(
      `ATT&CK ships ${unplaced.length} asset(s) with no Purdue placement in src/lib/purdue-registry.ts:\n  - ${unplaced.join('\n  - ')}\nAdd a placement (with rationale) before ingesting.`,
    );
  }
  const stale = [...placedIds].filter((id) => !assets.some((a) => a.attack_id === id));
  if (stale.length) {
    console.warn(`[ics-assets] WARNING: registry places ${stale.length} asset(s) absent from the bundle: ${stale.join(', ')}`);
  }
  stats.staleplacements = stale.length;

  if (args.dryRun) {
    console.log('[ics-assets] --dry-run: validated, no writes');
    process.exit(0);
  }

  const lock = await pool.query('SELECT pg_try_advisory_lock($1) AS ok', [ADVISORY_LOCK_KEY]);
  if (!lock.rows[0].ok) throw new Error('another ics-assets backfill is running (advisory lock held)');

  logId = await insertLogStart(pool);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const up = await upsertAssets(client, assets);
    stats.assetsUpserted = up.inserted + up.updated;
    stats.assetsInserted = up.inserted;
    stats.assetsUpdated = up.updated;

    const at = await reconcileAssetTechniques(client, edges);
    stats.edgesLinked = at.linked;
    stats.edgesRemoved = at.removed;
    stats.edgesUnresolved = at.unresolved;

    const ra = await reconcileRelatedAssets(client, related);
    stats.relatedLinked = ra.linked;
    stats.relatedRemoved = ra.removed;

    const cur = await seedCuratedLayer(client, reg);
    stats.levels = cur.levels;
    stats.placements = cur.placed;
    stats.flowRules = cur.rules;

    if (cur.placed !== reg.ASSET_PLACEMENTS.length) {
      throw new Error(`expected ${reg.ASSET_PLACEMENTS.length} placements, wrote ${cur.placed} — an attack_id in the registry does not match any ingested asset`);
    }

    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }

  stats.elapsedMs = Date.now() - startedAt;
  console.log('\n[ics-assets] done');
  console.log(JSON.stringify(stats, null, 2));
  if (logId) await updateLogDone(pool, logId, 'success', stats, null);
} catch (err) {
  const msg = err instanceof Error ? err.message : String(err);
  console.error('\n[ics-assets] FAILED:', msg);
  stats.elapsedMs = Date.now() - startedAt;
  if (logId) {
    try { await updateLogDone(pool, logId, 'error', stats, msg); }
    catch (e) { console.error('[ics-assets] also failed to write error log:', e.message); }
  }
  process.exitCode = 1;
} finally {
  try { await pool.query('SELECT pg_advisory_unlock($1)', [ADVISORY_LOCK_KEY]); } catch { /* ignore */ }
  await pool.end();
}
