#!/usr/bin/env node
// scripts/sync-scf.mjs
//
// Ingest the Secure Controls Framework (SCF) XLSX into Postgres.
// Backs /compliance/* — see docs/superpowers/specs/2026-05-12-scf-compliance-design.md
//
// SCF ships quarterly; we run twice a year via GH Actions cron (Jan 10 + Jul 10)
// plus manual workflow_dispatch.
//
// Patterns mirror update-attack.mjs:
//   - pg.Pool with keepAlive
//   - feed_sync_log lifecycle (source='scf')
//   - pg_try_advisory_lock key 0x736366 ('scf')
//   - strictly-greater version guard via metadata.scfVersion
//
// Write strategy (see "Shadow-table build + atomic swap" below): every derived
// table is rebuilt into a `<name>_new` shadow while the live one keeps serving
// reads, then ONE transaction renames all of them into place and prunes the
// scf_controls rows the workbook no longer contains. Nothing the API reads
// changes before that COMMIT; a failure anywhere before it leaves the live
// tables untouched.
//
// CLI:
//   --version=2026.1.1   pin to specific SCF release tag (default: latest)
//   --dry-run            preview, no writes
//   --force              skip version guard
//   --allow-shrink       proceed even when a rebuilt table is >30% smaller
//                        than the live one (see SHRINK_GATE)
//   --xlsx=/path/to.xlsx use a local file instead of downloading

import pg from 'pg';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import xlsx from 'xlsx';
import {
  normHeader,
  splitRefs,
  extractAttackIds,
  classifyColumn,
  locateAuthColumns,
  parseAuthSources,
  mapRegion,
  fdiToKey,
} from './lib/scf-parse.mjs';

const SCF_REPO = 'securecontrolsframework/securecontrolsframework';
const ADVISORY_LOCK_KEY = 0x736366; // ASCII 'scf'
const FETCH_TIMEOUT_MS = 60_000;

// ----- Registry import (TS file, compiled at request via dynamic JSON fallback)
// Registry lives in src/lib/scf-framework-registry.ts. To avoid a TS toolchain
// at ingest time, we shell to `node --experimental-strip-types`. Falls back to
// reading the source and parsing the literal if --experimental-strip-types is
// unavailable.
async function loadRegistry() {
  try {
    const mod = await import('../src/lib/scf-framework-registry.ts');
    return {
      entries: mod.SCF_FRAMEWORK_REGISTRY,
      aliasLookup: mod.buildAliasLookup(),
      tier1: mod.TIER1_KEYS,
      tier2: mod.TIER2_KEYS,
    };
  } catch (e) {
    console.error('[sync-scf] cannot load TS registry — node version must support --experimental-strip-types. Got:', e.message);
    throw e;
  }
}

export function parseArgs(argv = process.argv.slice(2)) {
  const args = { version: null, dryRun: false, force: false, allowShrink: false, xlsx: null };
  for (const a of argv) {
    if (a === '--dry-run') args.dryRun = true;
    else if (a === '--force') args.force = true;
    else if (a === '--allow-shrink') args.allowShrink = true;
    else if (a.startsWith('--version=')) args.version = a.slice('--version='.length);
    else if (a.startsWith('--xlsx=')) args.xlsx = a.slice('--xlsx='.length);
    else throw new Error(`unknown argument ${JSON.stringify(a)}`);
  }
  return args;
}

// ----- feed_sync_log + advisory lock + version helpers ---------------------

async function insertLogStart(client) {
  await client.query(
    `UPDATE feed_sync_log SET status='error', completed_at=NOW(),
       error_message='Stale (auto-cleaned on new run start)'
     WHERE source='scf' AND status='running' AND started_at < NOW() - INTERVAL '2 hour'`,
  );
  const r = await client.query(
    `INSERT INTO feed_sync_log (source, status, started_at)
     VALUES ('scf', 'running', NOW()) RETURNING id`,
  );
  return r.rows[0].id;
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
      counters.recordsInserted ?? 0,
      counters.recordsSkipped ?? 0,
      JSON.stringify({ ...meta, trigger: 'github-actions' }),
      errorMessage?.slice(0, 1000) ?? null,
      logId,
    ],
  );
}

// IMPORTANT: pg_try_advisory_lock + pg_advisory_unlock are SESSION-scoped.
// We MUST hold them on the same client instance — pool.query() leases a
// different connection per call and would silently leak the lock.
async function acquireAdvisoryLock(client) {
  const r = await client.query('SELECT pg_try_advisory_lock($1) AS locked', [ADVISORY_LOCK_KEY]);
  return r.rows[0].locked === true;
}

async function releaseAdvisoryLock(client) {
  await client.query('SELECT pg_advisory_unlock($1)', [ADVISORY_LOCK_KEY]);
}

async function getLastVersion(client) {
  const r = await client.query(
    `SELECT metadata->>'scfVersion' AS v
     FROM feed_sync_log
     WHERE source='scf' AND status='success'
       AND COALESCE(metadata->>'dryRun', 'false') <> 'true'
     ORDER BY completed_at DESC NULLS LAST LIMIT 1`,
  );
  return r.rows[0]?.v ?? null;
}

function isStrictlyGreater(newVer, oldVer) {
  if (!oldVer) return true;
  const an = String(newVer).split('.').map((p) => parseInt(p, 10) || 0);
  const ao = String(oldVer).split('.').map((p) => parseInt(p, 10) || 0);
  const len = Math.max(an.length, ao.length);
  for (let i = 0; i < len; i++) {
    const a = an[i] ?? 0, b = ao[i] ?? 0;
    if (a > b) return true;
    if (a < b) return false;
  }
  return false; // equal
}

// ----- GitHub release download --------------------------------------------

function ghHeaders() {
  const h = { 'User-Agent': 'explorer-plus-sync-scf', Accept: 'application/vnd.github+json' };
  // Unauthenticated calls share a 60/hour budget per IP, which GitHub-hosted
  // runners exhaust. The workflow passes github.token.
  if (process.env.GITHUB_TOKEN) h.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  return h;
}

/**
 * Resolve a release (latest, or a pinned tag) to its single .xlsx asset.
 *
 * SCF's asset naming is not stable across releases —
 * 'secure-controls-framework-scf-2026-2.xlsx' for 2026.2 but
 * 'Secure.Controls.Framework.SCF.-.2026.1.1.xlsx' for 2026.1.1 — so deriving
 * the file name from the tag 404s on patch releases. Ask the API instead.
 */
async function resolveRelease(versionTag) {
  const url = versionTag
    ? `https://api.github.com/repos/${SCF_REPO}/releases/tags/${encodeURIComponent(versionTag)}`
    : `https://api.github.com/repos/${SCF_REPO}/releases/latest`;
  const resp = await fetch(url, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS), headers: ghHeaders() });
  if (!resp.ok) throw new Error(`GitHub releases API ${resp.status} for ${url}`);
  const data = await resp.json();
  const xlsxAssets = (data.assets ?? []).filter((a) => /\.xlsx$/i.test(a.name));
  if (xlsxAssets.length !== 1) {
    throw new Error(
      `release ${data.tag_name}: expected exactly one .xlsx asset, found ${xlsxAssets.length}` +
      (xlsxAssets.length ? ` (${xlsxAssets.map((a) => a.name).join(', ')})` : ''),
    );
  }
  return { tag: data.tag_name, assetName: xlsxAssets[0].name, assetUrl: xlsxAssets[0].browser_download_url };
}

async function downloadXlsx(assetUrl, destPath) {
  console.log(`[sync-scf] downloading ${assetUrl}`);
  const resp = await fetch(assetUrl, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS * 3) });
  if (!resp.ok) throw new Error(`SCF asset fetch ${resp.status} for ${assetUrl}`);
  const buf = Buffer.from(await resp.arrayBuffer());
  fs.writeFileSync(destPath, buf);
  return buf.length;
}

function xlsxHash(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

// ----- Workbook parsing -----------------------------------------------------

function findMainSheetName(workbook) {
  // Pattern: 'SCF YYYY.X' — pick the one matching x of '<x> Controls' best.
  // Heuristic: starts with 'SCF ' and not a satellite sheet name.
  const match = workbook.SheetNames.find((n) => /^SCF \d{4}\.\d+$/.test(n));
  if (!match) throw new Error(`Cannot find main SCF sheet. Available: ${workbook.SheetNames.join(', ')}`);
  return match;
}

function findAttackColumn(headers) {
  // Header is multi-line: 'MITRE\r\nATT&CK\r\nN' — fold whitespace and match.
  const matches = headers
    .map((h, i) => ({ h, i }))
    .filter((x) => /mitre.*att.*ck/i.test(normHeader(x.h)));
  if (matches.length === 0) throw new Error('Could not locate MITRE ATT&CK column in main SCF sheet');
  // More than one match means the header shape changed and findIndex would have
  // silently picked the first. Refuse rather than guess: every derived table
  // (overlap, group/sector/software summary, coverage, technique heat) joins
  // through scf_attack_mappings, so choosing wrong empties all of them.
  if (matches.length > 1) {
    throw new Error(
      `ambiguous MITRE ATT&CK column: ${matches.length} headers matched — ${matches.map((m) => JSON.stringify(String(m.h))).join(', ')}`,
    );
  }
  return matches[0].i;
}

// ----- DB writes ------------------------------------------------------------

async function upsertFrameworks(client, frameworkRows, registry, observedHeaders, dryRun) {
  // Build registry → metadata map.
  const regByKey = new Map(registry.entries.map((e) => [e.framework_key, e]));

  // Map auth-source FDI rows → curated registry framework_key by alias.
  // Each auth row's column_header is checked against registry aliases.
  const fdiToCurated = new Map();
  for (const row of frameworkRows) {
    const norm = normHeader(row.column_header);
    for (const ali of registry.aliasLookup) {
      if (norm.includes(ali.alias)) {
        fdiToCurated.set(row.fdi, ali.framework_key);
        break;
      }
    }
  }

  // Phase 1: ensure curated entries exist (some may not have SCF backing — e.g. EU CRA).
  for (const entry of registry.entries) {
    if (dryRun) continue;
    await client.query(
      `INSERT INTO scf_frameworks (
         framework_key, name, version, source_org, upstream_url, region, tier, license, short_blurb
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       ON CONFLICT (framework_key) DO UPDATE SET
         name=EXCLUDED.name,
         version=EXCLUDED.version,
         source_org=EXCLUDED.source_org,
         upstream_url=EXCLUDED.upstream_url,
         region=EXCLUDED.region,
         tier=EXCLUDED.tier,
         license=EXCLUDED.license,
         short_blurb=EXCLUDED.short_blurb,
         updated_at=NOW()`,
      [
        entry.framework_key,
        entry.name,
        entry.version ?? null,
        entry.source_org,
        entry.upstream_url,
        entry.region,
        entry.tier,
        entry.license,
        entry.short_blurb,
      ],
    );
  }

  // Phase 2: UPSERT every auth-source row. Curated ones resolve to their registry key;
  // others become Tier-3 with FDI-derived key.
  for (const row of frameworkRows) {
    const curated = fdiToCurated.get(row.fdi);
    const key = curated ?? fdiToKey(row.fdi);
    const entry = curated ? regByKey.get(curated) : null;
    if (dryRun) continue;
    if (entry) {
      // Curated entry already inserted in Phase 1 — just record alias.
    } else {
      const name = row.doc_name || row.doc_title || row.column_header.replace(/\r?\n/g, ' ');
      // SCF 2026.2 dropped the separate title column, so a blurb exists only
      // when the sheet carries a title that adds something to the name. The
      // update set below always overwrites it: a blurb must describe THIS
      // workbook's row, never linger from an older one.
      const blurb = row.doc_title && row.doc_title !== name ? row.doc_title.slice(0, 240) : null;
      await client.query(
        `INSERT INTO scf_frameworks (
           framework_key, name, version, source_org, upstream_url, region, tier, license, short_blurb
         ) VALUES ($1,$2,$3,$4,$5,$6,3,$7,$8)
         ON CONFLICT (framework_key) DO UPDATE SET
           name=EXCLUDED.name,
           source_org=EXCLUDED.source_org,
           upstream_url=EXCLUDED.upstream_url,
           region=EXCLUDED.region,
           short_blurb=EXCLUDED.short_blurb,
           updated_at=NOW()`,
        [
          key,
          name,
          null,
          row.source_org,
          row.doc_url,
          mapRegion(row.geography),
          null,
          blurb,
        ],
      );
    }
  }

  // Phase 3: aliases. For every observed column header → record (framework_key, source_header).
  for (const { framework_key, source_header } of observedHeaders) {
    if (dryRun) continue;
    await client.query(
      `INSERT INTO scf_framework_aliases (framework_key, source_header, first_seen_at, last_seen_at)
       VALUES ($1, $2, NOW(), NOW())
       ON CONFLICT (framework_key, source_header) DO UPDATE SET last_seen_at=NOW()`,
      [framework_key, source_header],
    );
  }
}

/**
 * Returns Tier-1 keys with no alias seen in this run, split by whether that is
 * a REGRESSION (the key had aliases as of the last successful run) or a
 * pre-existing gap.
 *
 * Only regressions are fatal. Making every zero-alias event fatal would mean a
 * framework SCF legitimately never covers hard-blocks every future sync; making
 * none fatal is what let eu-cra sit at zero refs unnoticed and iso-27002-2022
 * break silently on 2026.2.
 */
async function tier1AliasCheck(client, registry, runStart) {
  // Tier-1 keys are launch-critical. We compare against runStart (timestamp at
  // ingest entry) so stale aliases from a prior run can't mask a vanished column.
  // An alias is "current" only if last_seen_at >= runStart.
  const failed = [];
  for (const key of registry.tier1) {
    const r = await client.query(
      `SELECT COUNT(*)::int AS n
       FROM scf_framework_aliases
       WHERE framework_key=$1 AND last_seen_at >= $2`,
      [key, runStart],
    );
    if (r.rows[0].n === 0) failed.push(key);
  }
  if (failed.length === 0) return { failed, regressions: [] };

  // A key that had a current alias at the last successful run and has none now
  // is a break, not an accepted gap.
  const prior = await client.query(
    `SELECT completed_at
       FROM feed_sync_log
      WHERE source='scf' AND status='success'
        AND COALESCE(metadata->>'dryRun','false') <> 'true'
      ORDER BY completed_at DESC NULLS LAST LIMIT 1 OFFSET 0`,
  );
  const priorAt = prior.rows[0]?.completed_at ?? null;
  if (!priorAt) return { failed, regressions: [] };

  const regressions = [];
  for (const key of failed) {
    const r = await client.query(
      `SELECT COUNT(*)::int AS n FROM scf_framework_aliases
        WHERE framework_key=$1 AND last_seen_at >= $2 AND last_seen_at < $3`,
      [key, new Date(priorAt.getTime() - 60 * 60 * 1000), runStart],
    );
    if (r.rows[0].n > 0) regressions.push(key);
  }
  return { failed, regressions };
}

// ----- Per-control + cross-link extraction ---------------------------------

function readControlRows(workbook, sheetName) {
  const ws = workbook.Sheets[sheetName];
  const rows = xlsx.utils.sheet_to_json(ws, { header: 1, defval: '' });
  if (rows.length < 2) throw new Error('Main SCF sheet is empty');
  return rows;
}

async function ingestControlsAndRefs({ client, rows, columnClasses, dryRun, currentAttackVersion }) {
  const headers = rows[0];
  const numCols = headers.length;
  const refsBatch = []; // { scf_id, framework_key, ref_id }
  const attackBatch = []; // { scf_id, attack_id }
  const seenScfIds = new Set(); // every control present in THIS workbook
  let controlsUpserted = 0;
  let unresolvedAttackTotal = 0;

  // Cache the set of valid attack_ids in techniques for the is_unresolved
  // classifier. A read, so dry-run loads it too — otherwise every mapping
  // reports as unresolved and the preview number is meaningless.
  const validAttackIds = new Set();
  {
    const r = await client.query(`SELECT attack_id FROM techniques`);
    for (const row of r.rows) validAttackIds.add(row.attack_id);
  }

  for (let i = 1; i < rows.length; i++) {
    const row = rows[i];
    const scfDomain = String(row[0] ?? '').trim();
    const scfName = String(row[1] ?? '').trim();
    const scfId = String(row[2] ?? '').trim();
    const scfDesc = String(row[3] ?? '').trim();
    if (!scfId || !scfName) continue;
    seenScfIds.add(scfId);

    const threatCodes = [];
    const riskCodes = [];
    // Collect this row's attack IDs locally — scanning the growing attackBatch
    // retrospectively was both O(n²) and (with duplicate scf_id rows in the
    // workbook) liable to double-count.
    const rowAttackIds = new Set();

    for (let c = 0; c < numCols; c++) {
      const cell = row[c];
      if (cell == null || cell === '') continue;
      const cls = columnClasses[c];
      if (!cls || cls.kind === 'metadata') continue;
      if (cls.kind === 'risk')  { riskCodes.push(cls.code); continue; }
      if (cls.kind === 'threat'){ threatCodes.push(cls.code); continue; }
      if (cls.kind === 'attack') {
        for (const aid of extractAttackIds(cell)) {
          attackBatch.push({ scf_id: scfId, attack_id: aid });
          rowAttackIds.add(aid);
        }
        continue;
      }
      if (cls.kind === 'framework') {
        for (const ref of splitRefs(cell)) {
          refsBatch.push({ scf_id: scfId, framework_key: cls.framework_key, ref_id: ref });
        }
      }
    }

    let unresolvedForRow = 0;
    for (const aid of rowAttackIds) {
      if (!validAttackIds.has(aid)) unresolvedForRow++;
    }
    unresolvedAttackTotal += unresolvedForRow;

    if (!dryRun) {
      // Plain upsert, outside the swap transaction: it only ever adds or
      // re-describes controls, and scf_attack_mappings_new carries an FK to
      // this table, so the rows must exist before the shadow build. Removal
      // of controls the workbook dropped happens inside the swap (see
      // planControlPrune) so readers never see a control vanish before its
      // mappings do.
      await client.query(
        `INSERT INTO scf_controls (
           scf_id, domain, name, description, threat_codes, risk_codes,
           last_validated_attack_version, unresolved_attack_count, updated_at
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
         ON CONFLICT (scf_id) DO UPDATE SET
           domain=EXCLUDED.domain,
           name=EXCLUDED.name,
           description=EXCLUDED.description,
           threat_codes=EXCLUDED.threat_codes,
           risk_codes=EXCLUDED.risk_codes,
           last_validated_attack_version=EXCLUDED.last_validated_attack_version,
           unresolved_attack_count=EXCLUDED.unresolved_attack_count,
           updated_at=NOW()`,
        [
          scfId,
          scfDomain || 'Uncategorized',
          scfName,
          scfDesc,
          threatCodes.length ? [...new Set(threatCodes)] : null,
          riskCodes.length ? [...new Set(riskCodes)] : null,
          currentAttackVersion,
          unresolvedForRow,
        ],
      );
    }
    controlsUpserted++;
  }

  return { controlsUpserted, seenScfIds, refsBatch, attackBatch, unresolvedAttackTotal, validAttackIds };
}

// ----- Shadow-table build + atomic swap ------------------------------------
//
// All on the pinned client, in this order:
//   1. preflightShadow    refuse if anything (a view, an FK from elsewhere)
//                         depends on a derived table; drop `_new`/`_old`
//                         leftovers of a crashed run
//   2. buildShadowTables  CREATE `<t>_new` with explicit `_new`-suffixed
//                         constraint/index names, assert its columns match the
//                         live table exactly, then load it. Summary shadows
//                         are computed FROM the refs/mappings shadows, so the
//                         whole set describes one workbook.
//   3. shrinkGate         compare shadow counts with the live snapshot
//   4. swapShadowTables   ONE transaction: move live index names aside, rename
//                         tables, promote `_new` names, prune scf_controls,
//                         self-check, COMMIT
//   5. dropShadowTables   drop `_old` outside the transaction; a leftover here
//                         is harmless and re-dropped by the next preflight
//
// Why not one big transaction around TRUNCATE + INSERT? TRUNCATE takes ACCESS
// EXCLUSIVE for the whole transaction, so the API would block for the entire
// rebuild. Renames hold that lock only for a handful of catalog updates.

export const SFX_NEW = '_new';
export const SFX_OLD = '_old';

/** Refuse a swap when a table would lose more than this share of its rows. */
export const SHRINK_GATE = 0.30;

export const SHADOW_TABLES = Object.freeze([
  'scf_framework_refs',
  'scf_attack_mappings',
  'scf_framework_overlap',
  'scf_group_compliance_summary',
  'scf_software_compliance_summary',
  'scf_sector_compliance_summary',
  'scf_framework_coverage',
  'scf_technique_heat',
]);

// Explicit DDL, kept in lock-step with seed/migrations/2026-05-12-scf-compliance.sql.
// assertSameColumns() fails the run if prod ever drifts from what is written
// here. Every constraint and index is named `<canonical>${s}` so the swap can
// promote it by stripping the suffix — nothing is left to Postgres' auto-naming
// (which is how the live refs PK ended up called scf_framework_refs_new_pkey1).
const SHADOW_DDL = {
  scf_framework_refs: (t, s) => [
    `CREATE TABLE ${t} (
       scf_id        TEXT NOT NULL,
       framework_key TEXT NOT NULL,
       ref_id        TEXT NOT NULL,
       CONSTRAINT scf_framework_refs_pkey${s} PRIMARY KEY (scf_id, framework_key, ref_id)
     )`,
    `CREATE INDEX idx_scf_framework_refs_fw${s}     ON ${t}(framework_key)`,
    `CREATE INDEX idx_scf_framework_refs_scf_fw${s} ON ${t}(scf_id, framework_key)`,
  ],
  scf_attack_mappings: (t, s) => [
    `CREATE TABLE ${t} (
       scf_id        TEXT NOT NULL,
       attack_id     VARCHAR(20) NOT NULL,
       is_unresolved BOOLEAN NOT NULL DEFAULT false,
       CONSTRAINT scf_attack_mappings_pkey${s} PRIMARY KEY (scf_id, attack_id),
       CONSTRAINT scf_attack_mappings_scf_id_fkey${s}
         FOREIGN KEY (scf_id) REFERENCES scf_controls(scf_id) ON DELETE CASCADE
     )`,
    `CREATE INDEX idx_scf_attack_mappings_attack_covering${s} ON ${t}(attack_id) INCLUDE (scf_id)`,
    `CREATE INDEX idx_scf_attack_mappings_unresolved${s}      ON ${t}(attack_id) WHERE is_unresolved`,
  ],
  scf_framework_overlap: (t, s) => [
    `CREATE TABLE ${t} (
       fw_a              TEXT NOT NULL,
       fw_b              TEXT NOT NULL,
       technique_overlap INT  NOT NULL,
       CONSTRAINT scf_framework_overlap_pkey${s} PRIMARY KEY (fw_a, fw_b),
       CONSTRAINT scf_framework_overlap_check${s} CHECK (fw_a < fw_b),
       CONSTRAINT scf_framework_overlap_fw_a_fkey${s}
         FOREIGN KEY (fw_a) REFERENCES scf_frameworks(framework_key) ON DELETE CASCADE,
       CONSTRAINT scf_framework_overlap_fw_b_fkey${s}
         FOREIGN KEY (fw_b) REFERENCES scf_frameworks(framework_key) ON DELETE CASCADE
     )`,
    `CREATE INDEX idx_scf_framework_overlap_b${s} ON ${t}(fw_b)`,
  ],
  scf_group_compliance_summary: (t, s) => [
    `CREATE TABLE ${t} (
       group_id       UUID    NOT NULL,
       framework_key  TEXT    NOT NULL,
       controls       INTEGER NOT NULL,
       techniques_ref INTEGER NOT NULL,
       CONSTRAINT scf_group_compliance_summary_pkey${s} PRIMARY KEY (group_id, framework_key),
       CONSTRAINT scf_group_compliance_summary_group_id_fkey${s}
         FOREIGN KEY (group_id) REFERENCES threat_groups(id) ON DELETE CASCADE,
       CONSTRAINT scf_group_compliance_summary_framework_key_fkey${s}
         FOREIGN KEY (framework_key) REFERENCES scf_frameworks(framework_key) ON DELETE CASCADE
     )`,
    `CREATE INDEX idx_scf_group_summary_group${s} ON ${t}(group_id)`,
  ],
  scf_software_compliance_summary: (t, s) => [
    `CREATE TABLE ${t} (
       software_id    UUID    NOT NULL,
       framework_key  TEXT    NOT NULL,
       controls       INTEGER NOT NULL,
       techniques_ref INTEGER NOT NULL,
       CONSTRAINT scf_software_compliance_summary_pkey${s} PRIMARY KEY (software_id, framework_key),
       CONSTRAINT scf_software_compliance_summary_software_id_fkey${s}
         FOREIGN KEY (software_id) REFERENCES attack_software(id) ON DELETE CASCADE,
       CONSTRAINT scf_software_compliance_summary_framework_key_fkey${s}
         FOREIGN KEY (framework_key) REFERENCES scf_frameworks(framework_key) ON DELETE CASCADE
     )`,
    `CREATE INDEX idx_scf_software_summary${s} ON ${t}(software_id)`,
  ],
  scf_sector_compliance_summary: (t, s) => [
    `CREATE TABLE ${t} (
       sector_id      UUID    NOT NULL,
       framework_key  TEXT    NOT NULL,
       controls       INTEGER NOT NULL,
       techniques_ref INTEGER NOT NULL,
       CONSTRAINT scf_sector_compliance_summary_pkey${s} PRIMARY KEY (sector_id, framework_key),
       CONSTRAINT scf_sector_compliance_summary_sector_id_fkey${s}
         FOREIGN KEY (sector_id) REFERENCES sectors(id) ON DELETE CASCADE,
       CONSTRAINT scf_sector_compliance_summary_framework_key_fkey${s}
         FOREIGN KEY (framework_key) REFERENCES scf_frameworks(framework_key) ON DELETE CASCADE
     )`,
    `CREATE INDEX idx_scf_sector_summary${s} ON ${t}(sector_id)`,
  ],
  scf_framework_coverage: (t, s) => [
    `CREATE TABLE ${t} (
       framework_key       TEXT        NOT NULL,
       scf_controls        INTEGER     NOT NULL DEFAULT 0,
       techniques_total    INTEGER     NOT NULL DEFAULT 0,
       techniques_filtered INTEGER     NOT NULL DEFAULT 0,
       updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
       CONSTRAINT scf_framework_coverage_pkey${s} PRIMARY KEY (framework_key),
       CONSTRAINT scf_framework_coverage_framework_key_fkey${s}
         FOREIGN KEY (framework_key) REFERENCES scf_frameworks(framework_key) ON DELETE CASCADE
     )`,
  ],
  scf_technique_heat: (t, s) => [
    `CREATE TABLE ${t} (
       attack_id   VARCHAR(20)  NOT NULL,
       cve_count   INTEGER      NOT NULL DEFAULT 0,
       has_kev     BOOLEAN      NOT NULL DEFAULT false,
       max_epss    NUMERIC(6,5),
       ghsa_count  INTEGER      NOT NULL DEFAULT 0,
       group_count INTEGER      NOT NULL DEFAULT 0,
       updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
       CONSTRAINT scf_technique_heat_pkey${s} PRIMARY KEY (attack_id)
     )`,
  ],
};

const IDENT_RE = /^[a-z_][a-z0-9_]*$/;
/** Guard for identifiers interpolated into DDL. All of ours are constants. */
function ident(name) {
  if (!IDENT_RE.test(name) || name.length > 63) throw new Error(`refusing to interpolate identifier ${JSON.stringify(name)}`);
  return name;
}

/** `scf_framework_refs_pkey_new` → `scf_framework_refs_pkey`; also handles
 *  Postgres 18's auto-named NOT NULL constraints (`<table>_new_<col>_not_null`). */
export function stripShadowSuffix(name) {
  const out = name.replace(/_new(?=_|$)/, '');
  if (out === name) {
    throw new Error(
      `shadow object ${JSON.stringify(name)} does not carry the ${SFX_NEW} suffix — ` +
      `every constraint and index in SHADOW_DDL must be named explicitly`,
    );
  }
  return out;
}

/**
 * Pure part of the shrink gate. Returns human-readable violations for any
 * table that would lose more than SHRINK_GATE of its rows; [] when fine.
 * Tables that are empty before the run are never a violation.
 */
export function shrinkViolations(checks, gate = SHRINK_GATE) {
  return checks
    .filter(([, before, after]) => before > 0 && after < before * (1 - gate))
    .map(([table, before, after]) => `${table}: ${before} → ${after} (${Math.round((1 - after / before) * 100)}% fewer)`);
}

async function assertSameColumns(client, live, shadow) {
  const shape = async (rel) => (await client.query(
    `SELECT a.attname, format_type(a.atttypid, a.atttypmod) AS type, a.attnotnull,
            pg_get_expr(d.adbin, d.adrelid) AS dflt
       FROM pg_attribute a
       LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
      WHERE a.attrelid = $1::regclass AND a.attnum > 0 AND NOT a.attisdropped
      ORDER BY a.attnum`,
    [rel],
  )).rows;
  const [a, b] = [JSON.stringify(await shape(live)), JSON.stringify(await shape(shadow))];
  if (a !== b) {
    throw new Error(`column drift between ${live} and SHADOW_DDL — live: ${a} / shadow: ${b}. Update SHADOW_DDL to match the migration applied in prod.`);
  }
}

async function dropShadowTables(client, sfx) {
  // No CASCADE on purpose: if something has come to depend on one of these
  // tables, dropping it must fail loudly instead of taking the dependent along.
  for (const name of SHADOW_TABLES) {
    await client.query(`DROP TABLE IF EXISTS ${ident(name + sfx)}`);
  }
}

async function preflightShadow(client) {
  // Anything depending on a derived table (a view, a matview, an FK from a
  // table outside this set) would be carried along by RENAME and then killed
  // or blocked by the DROP of `_old`. Nothing does today; refuse if that changes.
  const deps = await client.query(
    `SELECT src.relname AS table_name, dep.relname AS dependent, dep.relkind::text AS kind
       FROM pg_depend d
       JOIN pg_rewrite rw ON rw.oid = d.objid
       JOIN pg_class dep ON dep.oid = rw.ev_class
       JOIN pg_class src ON src.oid = d.refobjid
      WHERE d.classid = 'pg_rewrite'::regclass AND d.refclassid = 'pg_class'::regclass
        AND src.relnamespace = 'public'::regnamespace
        AND src.relname = ANY($1) AND dep.oid <> src.oid
     UNION ALL
     SELECT confrelid::regclass::text, conrelid::regclass::text, 'fk'
       FROM pg_constraint
      WHERE contype = 'f'
        AND confrelid IN (SELECT oid FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relname = ANY($1))`,
    [[...SHADOW_TABLES]],
  );
  if (deps.rowCount > 0) {
    const list = deps.rows.map((r) => `${r.dependent} (${r.kind}) → ${r.table_name}`).join(', ');
    throw new Error(`refusing to swap: other objects depend on derived tables — ${list}. Extend SHADOW_TABLES or remove the dependency.`);
  }
  await dropShadowTables(client, SFX_NEW);
  await dropShadowTables(client, SFX_OLD);
}

async function loadRefs(client, target, refsBatch) {
  // Dedup first (PK violation on duplicates).
  const seen = new Set();
  const cleaned = [];
  for (const r of refsBatch) {
    const k = `${r.scf_id}|${r.framework_key}|${r.ref_id}`;
    if (seen.has(k)) continue;
    seen.add(k);
    cleaned.push(r);
  }
  // Not overridable by --allow-shrink: zero refs has never been a real SCF
  // release, only a parser that stopped seeing the columns.
  if (cleaned.length === 0) throw new Error('extracted 0 framework refs — refusing to build an empty scf_framework_refs');
  const CHUNK = 5000;
  for (let i = 0; i < cleaned.length; i += CHUNK) {
    const slice = cleaned.slice(i, i + CHUNK);
    await client.query(
      `INSERT INTO ${ident(target)} (scf_id, framework_key, ref_id)
       SELECT UNNEST($1::text[]), UNNEST($2::text[]), UNNEST($3::text[])`,
      [slice.map((r) => r.scf_id), slice.map((r) => r.framework_key), slice.map((r) => r.ref_id)],
    );
  }
  return cleaned.length;
}

async function loadAttackMappings(client, target, attackBatch, validAttackIds) {
  // SCF has never shipped a release with zero ATT&CK mappings; zero here means
  // the column moved or the T-code regex stopped matching. Not overridable.
  if (attackBatch.length === 0) throw new Error('extracted 0 ATT&CK mappings — refusing to build an empty scf_attack_mappings');
  const seen = new Set();
  const cleaned = [];
  let unresolved = 0;
  for (const m of attackBatch) {
    const k = `${m.scf_id}|${m.attack_id}`;
    if (seen.has(k)) continue;
    seen.add(k);
    const isUnresolved = !validAttackIds.has(m.attack_id);
    if (isUnresolved) unresolved++;
    cleaned.push({ ...m, is_unresolved: isUnresolved });
  }
  const CHUNK = 5000;
  for (let i = 0; i < cleaned.length; i += CHUNK) {
    const slice = cleaned.slice(i, i + CHUNK);
    await client.query(
      `INSERT INTO ${ident(target)} (scf_id, attack_id, is_unresolved)
       SELECT UNNEST($1::text[]), UNNEST($2::varchar(20)[]), UNNEST($3::bool[])`,
      [slice.map((r) => r.scf_id), slice.map((r) => r.attack_id), slice.map((r) => r.is_unresolved)],
    );
  }
  return { inserted: cleaned.length, unresolved };
}

// Summary builders. R = refs shadow, M = mappings shadow, T = target shadow.
// Each reads ONLY from shadows (plus the untouched base tables), so the whole
// derived set is computed from the same workbook before anything goes live.

async function buildOverlap(client, R, M, T) {
  const r = await client.query(`
    INSERT INTO ${ident(T)} (fw_a, fw_b, technique_overlap)
    SELECT LEAST(a.framework_key, b.framework_key) AS fw_a,
           GREATEST(a.framework_key, b.framework_key) AS fw_b,
           COUNT(DISTINCT a.attack_id) AS technique_overlap
    FROM (
      SELECT DISTINCT r.framework_key, m.attack_id
      FROM ${ident(R)} r
      JOIN ${ident(M)} m ON m.scf_id = r.scf_id
      WHERE NOT m.is_unresolved
    ) a
    JOIN (
      SELECT DISTINCT r.framework_key, m.attack_id
      FROM ${ident(R)} r
      JOIN ${ident(M)} m ON m.scf_id = r.scf_id
      WHERE NOT m.is_unresolved
    ) b ON a.attack_id = b.attack_id AND a.framework_key < b.framework_key
    GROUP BY 1, 2
  `);
  return r.rowCount ?? 0;
}

async function buildGroupSummary(client, R, M, T) {
  const r = await client.query(`
    INSERT INTO ${ident(T)} (group_id, framework_key, controls, techniques_ref)
    SELECT gt.group_id,
           fr.framework_key,
           COUNT(DISTINCT fr.scf_id) AS controls,
           COUNT(DISTINCT t.attack_id) AS techniques_ref
    FROM group_techniques gt
    JOIN techniques t   ON t.id = gt.technique_id
    JOIN ${ident(M)} m  ON m.attack_id = t.attack_id AND NOT m.is_unresolved
    JOIN ${ident(R)} fr ON fr.scf_id = m.scf_id
    GROUP BY gt.group_id, fr.framework_key
  `);
  return r.rowCount ?? 0;
}

async function buildSoftwareSummary(client, R, M, T) {
  const exists = await client.query(`SELECT to_regclass('software_techniques') AS r`);
  if (!exists.rows[0].r) return 0; // shadow stays empty
  const r = await client.query(`
    INSERT INTO ${ident(T)} (software_id, framework_key, controls, techniques_ref)
    SELECT st.software_id,
           fr.framework_key,
           COUNT(DISTINCT fr.scf_id) AS controls,
           COUNT(DISTINCT t.attack_id) AS techniques_ref
    FROM software_techniques st
    JOIN techniques t   ON t.id = st.technique_id
    JOIN ${ident(M)} m  ON m.attack_id = t.attack_id AND NOT m.is_unresolved
    JOIN ${ident(R)} fr ON fr.scf_id = m.scf_id
    GROUP BY st.software_id, fr.framework_key
  `);
  return r.rowCount ?? 0;
}

async function buildSectorSummary(client, R, M, T) {
  const exists = await client.query(`SELECT to_regclass('group_sectors') AS r`);
  if (!exists.rows[0].r) return 0;
  const r = await client.query(`
    INSERT INTO ${ident(T)} (sector_id, framework_key, controls, techniques_ref)
    SELECT gs.sector_id,
           fr.framework_key,
           COUNT(DISTINCT fr.scf_id) AS controls,
           COUNT(DISTINCT t.attack_id) AS techniques_ref
    FROM group_sectors gs
    JOIN group_techniques gt ON gt.group_id = gs.group_id
    JOIN techniques t        ON t.id = gt.technique_id
    JOIN ${ident(M)} m       ON m.attack_id = t.attack_id AND NOT m.is_unresolved
    JOIN ${ident(R)} fr      ON fr.scf_id = m.scf_id
    GROUP BY gs.sector_id, fr.framework_key
  `);
  return r.rowCount ?? 0;
}

async function buildFrameworkCoverage(client, R, M, T) {
  const r = await client.query(`
    WITH pfac AS (
      SELECT fr.framework_key, m.attack_id, COUNT(DISTINCT fr.scf_id) AS controls_for_tech
      FROM ${ident(R)} fr
      JOIN ${ident(M)} m ON m.scf_id = fr.scf_id AND NOT m.is_unresolved
      GROUP BY fr.framework_key, m.attack_id
    ),
    fw_tech AS (
      SELECT framework_key, COUNT(*)::int AS techniques_total,
             COUNT(*) FILTER (WHERE controls_for_tech >= 2)::int AS techniques_filtered
      FROM pfac GROUP BY framework_key
    ),
    fw_ctl AS (
      SELECT framework_key, COUNT(DISTINCT scf_id)::int AS scf_controls
      FROM ${ident(R)} GROUP BY framework_key
    )
    INSERT INTO ${ident(T)} (framework_key, scf_controls, techniques_total, techniques_filtered)
    SELECT f.framework_key,
           COALESCE(c.scf_controls, 0),
           COALESCE(t.techniques_total, 0),
           COALESCE(t.techniques_filtered, 0)
    FROM scf_frameworks f
    LEFT JOIN fw_tech t USING (framework_key)
    LEFT JOIN fw_ctl  c USING (framework_key)
  `);
  return r.rowCount ?? 0;
}

async function buildTechniqueHeat(client, T) {
  const r = await client.query(`
    WITH cve_tech AS (
      -- CURATED CVE->technique links only (capec_id='CTID-DIRECT', the
      -- analyst hand-mapped edges from sync-ctid-cve-mappings.mjs). The
      -- inferred CWE->CAPEC path fans catch-all CWEs (CWE-200/284/285/20)
      -- onto unrelated techniques and inverts the heat map (niche techniques
      -- showed thousands of CVEs while T1190/T1059 showed zero). CTID-direct
      -- is precise + KEV-backed. No publish-date window: the curated set is
      -- small and intentionally includes notable older exploited CVEs.
      SELECT cm.attack_technique_id AS attack_id,
             COUNT(DISTINCT cw.cve_id) AS cves,
             BOOL_OR(c.is_kev) AS has_kev
      FROM cve_weaknesses cw
      JOIN cve_details    c  ON c.cve_id = cw.cve_id
      JOIN capec_mappings cm ON cm.cwe_id = cw.cwe_id
                            AND cm.capec_id = 'CTID-DIRECT'
                            AND cm.attack_technique_id IS NOT NULL
      GROUP BY cm.attack_technique_id
    ),
    group_tech AS (
      SELECT t.attack_id, COUNT(DISTINCT gt.group_id) AS groups
      FROM techniques t JOIN group_techniques gt ON gt.technique_id = t.id
      GROUP BY t.attack_id
    )
    INSERT INTO ${ident(T)} (attack_id, cve_count, has_kev, max_epss, ghsa_count, group_count)
    SELECT t.attack_id,
           COALESCE(ct.cves, 0),
           COALESCE(ct.has_kev, false),
           NULL::numeric,   -- max_epss retired: EPSS-max pins ~0.94 over any KEV-containing set, never differentiates
           0,               -- ghsa_count retired: no curated GHSA->technique grounding
           COALESCE(gtc.groups, 0)
    FROM techniques t
    LEFT JOIN cve_tech   ct  ON ct.attack_id  = t.attack_id
    LEFT JOIN group_tech gtc ON gtc.attack_id = t.attack_id
  `);
  return r.rowCount ?? 0;
}

async function buildShadowTables(client, { refsBatch, attackBatch, validAttackIds }) {
  for (const name of SHADOW_TABLES) {
    const t = ident(name + SFX_NEW);
    for (const stmt of SHADOW_DDL[name](t, SFX_NEW)) await client.query(stmt);
    await assertSameColumns(client, name, t);
  }
  const R = 'scf_framework_refs' + SFX_NEW;
  const M = 'scf_attack_mappings' + SFX_NEW;
  const counts = {};
  counts.refs = await loadRefs(client, R, refsBatch);
  const m = await loadAttackMappings(client, M, attackBatch, validAttackIds);
  counts.attackMappings = m.inserted;
  counts.attackMappingsUnresolved = m.unresolved;
  // Fresh tables have no statistics; the summary joins below plan far better with them.
  await client.query(`ANALYZE ${ident(R)}`);
  await client.query(`ANALYZE ${ident(M)}`);
  counts.overlap = await buildOverlap(client, R, M, 'scf_framework_overlap' + SFX_NEW);
  counts.groupSummary = await buildGroupSummary(client, R, M, 'scf_group_compliance_summary' + SFX_NEW);
  counts.softwareSummary = await buildSoftwareSummary(client, R, M, 'scf_software_compliance_summary' + SFX_NEW);
  counts.sectorSummary = await buildSectorSummary(client, R, M, 'scf_sector_compliance_summary' + SFX_NEW);
  counts.coverage = await buildFrameworkCoverage(client, R, M, 'scf_framework_coverage' + SFX_NEW);
  counts.heat = await buildTechniqueHeat(client, 'scf_technique_heat' + SFX_NEW);
  for (const name of SHADOW_TABLES.slice(2)) await client.query(`ANALYZE ${ident(name + SFX_NEW)}`);
  return counts;
}

/** scf_controls rows present in prod but absent from this workbook. */
async function planControlPrune(client, seenScfIds) {
  const r = await client.query(
    `SELECT scf_id FROM scf_controls WHERE NOT (scf_id = ANY($1::text[])) ORDER BY scf_id`,
    [[...seenScfIds]],
  );
  return r.rows.map((x) => x.scf_id);
}

function shrinkGate({ pre, built, pruneCount, allowShrink }) {
  const violations = shrinkViolations([
    ['scf_framework_refs', pre.refs, built.refs],
    ['scf_attack_mappings', pre.attackMappings, built.attackMappings],
    ['scf_controls (after prune)', pre.controls, pre.controls - pruneCount],
  ]);
  if (violations.length === 0) return;
  const msg = `rebuilt tables are more than ${Math.round(SHRINK_GATE * 100)}% smaller than live — ${violations.join('; ')}`;
  if (!allowShrink) {
    throw new Error(`${msg}. A drop this size is how the 2026.2 sheet rename destroyed 44k refs; re-run with --allow-shrink only if it is genuine.`);
  }
  console.warn(`[sync-scf] WARNING (--allow-shrink): ${msg}`);
}

/**
 * ONE transaction that makes every shadow live and prunes stale controls.
 * Readers see either the entire previous state or the entire new one.
 */
async function swapShadowTables(client, { pruneScfIds }) {
  const q = (name) => client.escapeIdentifier(name);
  const idx = async (table) => (await client.query(
    `SELECT indexname FROM pg_indexes WHERE schemaname = 'public' AND tablename = $1 ORDER BY indexname`, [table],
  )).rows.map((r) => r.indexname);

  await client.query('BEGIN');
  try {
    // ALTER TABLE RENAME takes ACCESS EXCLUSIVE. Fail rather than queue the
    // API's readers behind a lock we cannot get.
    await client.query(`SET LOCAL lock_timeout = '30s'`);

    for (const name of SHADOW_TABLES) {
      const live = name, fresh = name + SFX_NEW, old = name + SFX_OLD;

      // 1. Index names are schema-unique: move the live table's aside so the
      //    canonical names are free. ALTER INDEX RENAME also renames the
      //    PK/UNIQUE constraint the index backs (documented behaviour).
      for (const i of await idx(live)) {
        await client.query(`ALTER INDEX ${q(i)} RENAME TO ${q(i + SFX_OLD)}`);
      }

      // 2. Swap the relations.
      await client.query(`ALTER TABLE ${q(live)} RENAME TO ${q(old)}`);
      await client.query(`ALTER TABLE ${q(fresh)} RENAME TO ${q(live)}`);

      // 3. Promote the shadow's `_new` names to canonical: indexes (incl. the
      //    PK's) and every non-index constraint (FK, CHECK, PG18 NOT NULL).
      for (const i of await idx(live)) {
        await client.query(`ALTER INDEX ${q(i)} RENAME TO ${q(stripShadowSuffix(i))}`);
      }
      const cons = await client.query(
        `SELECT conname FROM pg_constraint
          WHERE conrelid = $1::regclass AND contype NOT IN ('p', 'u', 'x')
          ORDER BY conname`,
        [live],
      );
      for (const { conname } of cons.rows) {
        await client.query(`ALTER TABLE ${q(live)} RENAME CONSTRAINT ${q(conname)} TO ${q(stripShadowSuffix(conname))}`);
      }
    }

    // 4. Self-check: no canonical table may still carry a shadow-suffixed
    //    object. Throwing here rolls the whole swap back.
    const leftovers = await client.query(
      `SELECT tablename, indexname AS name
         FROM pg_indexes
        WHERE schemaname = 'public' AND tablename = ANY($1) AND indexname ~ '_(new|old)(_|$)'
       UNION ALL
       SELECT conrelid::regclass::text, conname
         FROM pg_constraint
        WHERE conrelid IN (SELECT oid FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relname = ANY($1))
          AND conname ~ '_(new|old)(_|$)'`,
      [[...SHADOW_TABLES]],
    );
    if (leftovers.rowCount > 0) {
      throw new Error(`swap self-check failed: ${leftovers.rows.map((r) => `${r.tablename}.${r.name}`).join(', ')}`);
    }

    // 5. Prune controls the workbook dropped. The new scf_attack_mappings
    //    only references controls seen in this workbook, so the ON DELETE
    //    CASCADE cannot reach it; it only empties rows in `_old`, which is
    //    dropped right after COMMIT.
    let pruned = 0;
    if (pruneScfIds.length > 0) {
      const r = await client.query(`DELETE FROM scf_controls WHERE scf_id = ANY($1::text[])`, [pruneScfIds]);
      pruned = r.rowCount ?? 0;
      if (pruned !== pruneScfIds.length) {
        throw new Error(`prune deleted ${pruned} rows but ${pruneScfIds.length} were planned — scf_controls changed under us`);
      }
    }

    await client.query('COMMIT');
    return { pruned };
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  }
}

// ----- Pre/post snapshot ---------------------------------------------------

async function snapshot(client) {
  const n = async (sql) => Number((await client.query(sql)).rows[0].n);
  return {
    controls: await n(`SELECT COUNT(*)::int AS n FROM scf_controls`),
    frameworks: await n(`SELECT COUNT(*)::int AS n FROM scf_frameworks`),
    refs: await n(`SELECT COUNT(*)::int AS n FROM scf_framework_refs`),
    attackMappings: await n(`SELECT COUNT(*)::int AS n FROM scf_attack_mappings`),
    unresolvedMappings: await n(`SELECT COUNT(*)::int AS n FROM scf_attack_mappings WHERE is_unresolved`),
    overlap: await n(`SELECT COUNT(*)::int AS n FROM scf_framework_overlap`),
    groupSummary: await n(`SELECT COUNT(*)::int AS n FROM scf_group_compliance_summary`),
    softwareSummary: await n(`SELECT COUNT(*)::int AS n FROM scf_software_compliance_summary`),
    sectorSummary: await n(`SELECT COUNT(*)::int AS n FROM scf_sector_compliance_summary`),
    coverage: await n(`SELECT COUNT(*)::int AS n FROM scf_framework_coverage`),
    heat: await n(`SELECT COUNT(*)::int AS n FROM scf_technique_heat`),
  };
}

// ----- main -----------------------------------------------------------------

async function main() {
  const args = parseArgs();
  const DATABASE_URL = process.env.DATABASE_URL;
  if (!DATABASE_URL) { console.error('DATABASE_URL required'); process.exit(1); }

  // We use a pool for connection management, but pin a SINGLE client for the
  // entire ingest. pg_try_advisory_lock is session-scoped, so leasing different
  // pool connections per query would silently leak the lock + break atomicity
  // of the shadow-table swap (RENAME on connection A, COMMIT on connection B).
  const pool = new pg.Pool({ connectionString: DATABASE_URL, keepAlive: true, max: 2 });
  let client = null;
  let logId = null;
  let lockAcquired = false;
  const counters = { recordsInserted: 0, recordsSkipped: 0 };
  const meta = { dryRun: args.dryRun };

  try {
    client = await pool.connect();
    logId = await insertLogStart(client);
    if (!(await acquireAdvisoryLock(client))) {
      throw new Error('Another sync-scf run is in progress (advisory lock held).');
    }
    lockAcquired = true;

    const registry = await loadRegistry();

    // Resolve version + download
    let versionTag = args.version;
    let xlsxPath = args.xlsx;
    if (!xlsxPath) {
      const rel = await resolveRelease(versionTag);
      versionTag = rel.tag;
      const tmp = path.join(os.tmpdir(), `scf-${versionTag}.xlsx`);
      const bytes = await downloadXlsx(rel.assetUrl, tmp);
      console.log(`[sync-scf] downloaded ${bytes} bytes (${rel.assetName}) → ${tmp}`);
      xlsxPath = tmp;
    } else if (!versionTag) {
      // Infer version tag from file when possible.
      const m = path.basename(xlsxPath).match(/(\d{4}\.\d+\.\d+|\d{4}\.\d+)/);
      versionTag = m ? m[1] : 'unknown';
    }
    meta.scfVersion = versionTag;
    meta.xlsxSha256 = xlsxHash(xlsxPath);

    if (!args.force) {
      const last = await getLastVersion(client);
      if (!isStrictlyGreater(versionTag, last)) {
        console.log(`[sync-scf] skipping — last ingested ${last}, current ${versionTag}. Use --force to override.`);
        await updateLogDone(client, logId, 'success', counters, { ...meta, skipped: true }, null);
        return;
      }
    }

    // Parse workbook
    const wb = xlsx.readFile(xlsxPath);
    const mainSheet = findMainSheetName(wb);
    console.log(`[sync-scf] main sheet: ${mainSheet}`);

    // SCF renamed this sheet from 'Authoritative Sources' to 'Focal Documents'
    // in 2026.2. The old lookup silently resolved to undefined, parsed to zero
    // frameworks, and the run CONTINUED -- which dropped every non-curated
    // framework's refs in one pass. Resolve by name with a fallback, and treat
    // zero as fatal: an empty auth source is never a legitimate outcome.
    const AUTH_SHEETS = ['Focal Documents', 'Authoritative Sources'];
    const authSheetName = AUTH_SHEETS.find((n) => wb.Sheets[n]);
    if (!authSheetName) {
      throw new Error(
        `no authoritative-source sheet found; looked for ${AUTH_SHEETS.join(' / ')}. Sheets present: ${wb.SheetNames.join(', ')}`,
      );
    }
    const authRows = xlsx.utils.sheet_to_json(wb.Sheets[authSheetName], { header: 1, defval: '' });
    // Columns are located by header name (2026.2 dropped one, shifting the rest);
    // this throws on a missing or ambiguous column. Log the mapping so a future
    // shape change is visible in the run output.
    const authColumns = locateAuthColumns(authRows[0]);
    meta.authColumns = authColumns;
    console.log(`[sync-scf] auth-source columns (${authSheetName}):`, authColumns);
    const frameworkRows = parseAuthSources(authRows);
    console.log(`[sync-scf] auth sources: ${frameworkRows.length} frameworks`);
    if (frameworkRows.length === 0) {
      throw new Error(`sheet '${authSheetName}' parsed to 0 frameworks — refusing to rebuild with no mappings`);
    }

    const headerToFdi = new Map();
    for (const f of frameworkRows) headerToFdi.set(f.column_header, f.fdi);

    const rows = readControlRows(wb, mainSheet);
    const headers = rows[0];
    const attackColIndex = findAttackColumn(headers);
    console.log(`[sync-scf] ATT&CK column index = ${attackColIndex}`);

    // Classify columns once + capture observed header → key map.
    const columnClasses = new Array(headers.length);
    const observedHeaders = []; // for scf_framework_aliases
    const fdiToCurated = new Map();
    for (const fr of frameworkRows) {
      const norm = normHeader(fr.column_header);
      for (const ali of registry.aliasLookup) {
        if (norm.includes(ali.alias)) {
          fdiToCurated.set(fr.fdi, ali.framework_key);
          break;
        }
      }
    }
    // Build a headerToFdi map already exists; for classify we still pass it.
    // After classifyColumn returns a framework_key, normalize curated keys.
    for (let c = 0; c < headers.length; c++) {
      const cls = classifyColumn({
        header: headers[c],
        colIndex: c,
        headerToFdi,
        aliasLookup: registry.aliasLookup,
        attackColIndex,
      });
      if (cls.kind === 'framework') {
        // classifyColumn may return either curated key (alias-matched) or FDI.
        // Normalize FDI to its mapped curated key when one exists.
        const fdi = headerToFdi.get(cls.source_header);
        if (fdi && fdiToCurated.has(fdi)) {
          cls.framework_key = fdiToCurated.get(fdi);
        } else if (fdi && !registry.entries.find((e) => e.framework_key === cls.framework_key)) {
          // Uncurated FDI → derive Tier-3 key.
          cls.framework_key = fdiToKey(fdi);
        }
        observedHeaders.push({ framework_key: cls.framework_key, source_header: cls.source_header });
      }
      columnClasses[c] = cls;
    }

    const pre = await snapshot(client);
    console.log('[sync-scf] PRE:', pre);

    if (args.dryRun) {
      console.log('[sync-scf] DRY-RUN: skipping writes');
    }

    // Reset aliases observed THIS run so a removed Tier-1 column is detected.
    // last_seen_at on existing aliases is bumped only when the ingester re-sees
    // the header in the current XLSX (see upsertFrameworks). The Tier-1 guard
    // below compares last_seen_at against this timestamp.
    const runStart = new Date();
    await upsertFrameworks(client, frameworkRows, registry, observedHeaders, args.dryRun);

    // Tier-1 alias guard. Compare to runStart so stale aliases from prior
    // ingests don't mask a vanished column.
    //
    // This runs BEFORE ingestControlsAndRefs and the shadow build, and
    // upsertFrameworks above performs only idempotent UPSERTs, so throwing
    // here aborts the run without having touched scf_framework_refs,
    // scf_attack_mappings or any summary table. That placement is deliberate
    // -- it is what would have stopped the 2026.2 run before it destroyed data.
    if (!args.dryRun) {
      const { failed, regressions } = await tier1AliasCheck(client, registry, runStart);
      if (failed.length > 0) {
        meta.tier1WithoutAliases = failed;
        meta.tier1AliasRegressions = regressions;
        console.warn('[sync-scf] Tier-1 keys without current-run aliases:', failed.join(', '));
      }
      if (regressions.length > 0) {
        // A key that matched a column at the last successful run and matches
        // nothing now means SCF renamed or removed that column. Continuing
        // would rebuild the framework with zero refs -- exactly how
        // iso-27002-2022 silently emptied on 2026.2. Abort and let a human
        // add the new header to the registry aliases.
        throw new Error(
          `Tier-1 alias regression: ${regressions.join(', ')} had SCF columns at the last successful run and match none now. ` +
          `Check the workbook headers and update aliases in src/lib/scf-framework-registry.ts.`,
        );
      }
    }

    let currentAttackVersion = process.env.ATTACK_VERSION || null;
    if (!currentAttackVersion) {
      // Read from feed_sync_log — seed_metadata may not exist in this schema.
      try {
        const r = await client.query(
          `SELECT metadata->>'attackVersion' AS v
           FROM feed_sync_log
           WHERE source='attack_update' AND status='success'
           ORDER BY completed_at DESC NULLS LAST LIMIT 1`,
        );
        currentAttackVersion = r.rows[0]?.v ?? null;
      } catch { /* ignore */ }
    }

    const { controlsUpserted, seenScfIds, refsBatch, attackBatch, unresolvedAttackTotal, validAttackIds } =
      await ingestControlsAndRefs({
        client, rows, columnClasses,
        dryRun: args.dryRun, currentAttackVersion: currentAttackVersion || 'v19',
      });
    console.log(`[sync-scf] controls: ${controlsUpserted}, refs: ${refsBatch.length}, attack-mappings: ${attackBatch.length}, unresolved: ${unresolvedAttackTotal}`);
    counters.recordsInserted += controlsUpserted;
    meta.controlsUpserted = controlsUpserted;
    meta.unresolvedTotal = unresolvedAttackTotal;

    let built = {
      refs: 0, attackMappings: 0, attackMappingsUnresolved: 0, overlap: 0,
      groupSummary: 0, softwareSummary: 0, sectorSummary: 0, coverage: 0, heat: 0,
    };
    let pruned = 0;
    if (!args.dryRun) {
      await preflightShadow(client);
      try {
        built = await buildShadowTables(client, { refsBatch, attackBatch, validAttackIds });
        console.log('[sync-scf] shadow tables built:', built);
        const pruneIds = await planControlPrune(client, seenScfIds);
        shrinkGate({ pre, built, pruneCount: pruneIds.length, allowShrink: args.allowShrink });
        if (pruneIds.length > 0) {
          console.log(`[sync-scf] pruning ${pruneIds.length} scf_controls absent from this workbook: ${pruneIds.slice(0, 20).join(', ')}${pruneIds.length > 20 ? ', …' : ''}`);
          meta.prunedScfIds = pruneIds.slice(0, 200);
        }
        ({ pruned } = await swapShadowTables(client, { pruneScfIds: pruneIds }));
        console.log(`[sync-scf] swap committed (${SHADOW_TABLES.length} tables, ${pruned} controls pruned)`);
      } catch (e) {
        // The swap is all-or-nothing, so nothing live has changed. Just don't
        // leave half-built shadows behind (a leftover is harmless; preflight
        // drops it next run).
        await dropShadowTables(client, SFX_NEW).catch((err) => console.error('[sync-scf] shadow cleanup failed:', err.message));
        throw e;
      }
      await dropShadowTables(client, SFX_OLD);
    }
    meta.refsInserted = built.refs;
    meta.attackMappingsInserted = built.attackMappings;
    meta.attackMappingsUnresolved = built.attackMappingsUnresolved;
    meta.overlapRows = built.overlap;
    meta.groupSummaryRows = built.groupSummary;
    meta.softwareSummaryRows = built.softwareSummary;
    meta.sectorSummaryRows = built.sectorSummary;
    meta.coverageRows = built.coverage;
    meta.heatRows = built.heat;
    meta.controlsPruned = pruned;
    counters.recordsInserted += built.refs + built.attackMappings;

    const post = await snapshot(client);
    console.log('[sync-scf] POST:', post);
    meta.snapshot = { pre, post };

    await updateLogDone(client, logId, 'success', counters, meta, null);
    console.log(`[sync-scf] DONE — SCF ${versionTag}`);
  } catch (e) {
    console.error('[sync-scf] FAILED:', e);
    // Best-effort log write — wrap separately so a pool failure doesn't mask
    // the original error.
    if (logId && client) {
      try {
        await updateLogDone(client, logId, 'error', counters, meta, e?.message ?? String(e));
      } catch (logErr) {
        console.error('[sync-scf] also failed writing to feed_sync_log:', logErr);
      }
    }
    process.exitCode = 1;
  } finally {
    if (client && lockAcquired) {
      try { await releaseAdvisoryLock(client); } catch (e) { console.error('[sync-scf] release lock failed:', e); }
    }
    if (client) client.release();
    await pool.end();
  }
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1].endsWith('sync-scf.mjs')) {
  main();
}
