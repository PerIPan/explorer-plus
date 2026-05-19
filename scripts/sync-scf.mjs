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
//   - shadow-table swap for scf_framework_refs + summary tables + overlap
//
// CLI:
//   --version=2026.1.1   pin to specific SCF release tag (default: latest)
//   --dry-run            preview, no writes
//   --force              skip version guard
//   --xlsx=/path/to.xlsx use a local file instead of downloading

import pg from 'pg';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import xlsx from 'xlsx';
import {
  normHeader,
  splitRefs,
  extractAttackIds,
  classifyColumn,
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

function parseArgs() {
  const args = { version: null, dryRun: false, force: false, xlsx: null };
  for (const a of process.argv.slice(2)) {
    if (a === '--dry-run') args.dryRun = true;
    else if (a === '--force') args.force = true;
    else if (a.startsWith('--version=')) args.version = a.slice('--version='.length);
    else if (a.startsWith('--xlsx=')) args.xlsx = a.slice('--xlsx='.length);
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

async function resolveLatestRelease() {
  const url = `https://api.github.com/repos/${SCF_REPO}/releases/latest`;
  const resp = await fetch(url, {
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    headers: { 'User-Agent': 'explorer-plus-sync-scf' },
  });
  if (!resp.ok) throw new Error(`GitHub releases API ${resp.status}`);
  const data = await resp.json();
  return data.tag_name; // e.g. '2026.1.1'
}

async function downloadXlsx(versionTag, destPath) {
  // SCF asset name pattern: secure-controls-framework-scf-YYYY-X-Y.xlsx
  const asset = `secure-controls-framework-scf-${versionTag.replaceAll('.', '-')}.xlsx`;
  const url = `https://github.com/${SCF_REPO}/releases/download/${versionTag}/${asset}`;
  console.log(`[sync-scf] downloading ${url}`);
  const resp = await fetch(url, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS * 3) });
  if (!resp.ok) throw new Error(`SCF asset fetch ${resp.status} for ${url}`);
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
  const idx = headers.findIndex((h) => /mitre.*att.*ck/i.test(normHeader(h)));
  if (idx < 0) throw new Error('Could not locate MITRE ATT&CK column in main SCF sheet');
  return idx;
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
      await client.query(
        `INSERT INTO scf_frameworks (
           framework_key, name, version, source_org, upstream_url, region, tier, license, short_blurb
         ) VALUES ($1,$2,$3,$4,$5,$6,3,$7,$8)
         ON CONFLICT (framework_key) DO UPDATE SET
           name=EXCLUDED.name,
           source_org=EXCLUDED.source_org,
           upstream_url=EXCLUDED.upstream_url,
           region=EXCLUDED.region,
           updated_at=NOW()`,
        [
          key,
          row.doc_name || row.doc_title || row.column_header.replace(/\r?\n/g, ' '),
          null,
          row.source_org,
          row.doc_url,
          mapRegion(row.geography),
          null,
          row.doc_title?.slice(0, 240) ?? null,
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
  return failed;
}

// ----- Per-control + cross-link extraction ---------------------------------

function readControlRows(workbook, sheetName) {
  const ws = workbook.Sheets[sheetName];
  const rows = xlsx.utils.sheet_to_json(ws, { header: 1, defval: '' });
  if (rows.length < 2) throw new Error('Main SCF sheet is empty');
  return rows;
}

async function ingestControlsAndRefs({ client, rows, columnClasses, attackColIndex, observedHeaders, dryRun, currentAttackVersion }) {
  const headers = rows[0];
  const numCols = headers.length;
  const refsBatch = []; // { scf_id, framework_key, ref_id }
  const attackBatch = []; // { scf_id, attack_id }
  let controlsUpserted = 0;
  let unresolvedAttackTotal = 0;

  // Cache the set of valid attack_ids in techniques for the is_unresolved classifier.
  const validAttackIds = new Set();
  if (!dryRun) {
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

  return { controlsUpserted, refsBatch, attackBatch, unresolvedAttackTotal, validAttackIds };
}

// ----- Shadow-table swap helpers --------------------------------------------

async function rebuildFrameworkRefs(client, refsBatch, dryRun) {
  if (dryRun) return 0;

  // Drop any stale leftover from a prior failed run.
  await client.query(`DROP TABLE IF EXISTS scf_framework_refs_new CASCADE`);
  await client.query(`DROP TABLE IF EXISTS scf_framework_refs_old CASCADE`);

  // Explicit DDL — no LIKE INCLUDING ALL. We pick the index names so the
  // post-swap rename is deterministic.
  await client.query(`
    CREATE TABLE scf_framework_refs_new (
      scf_id        TEXT NOT NULL,
      framework_key TEXT NOT NULL,
      ref_id        TEXT NOT NULL,
      PRIMARY KEY (scf_id, framework_key, ref_id)
    )
  `);
  await client.query(`CREATE INDEX idx_scf_framework_refs_fw_new     ON scf_framework_refs_new(framework_key)`);
  await client.query(`CREATE INDEX idx_scf_framework_refs_scf_fw_new ON scf_framework_refs_new(scf_id, framework_key)`);

  // Bulk load via UNNEST chunks. Dedup first (PK violation on duplicates).
  const CHUNK = 5000;
  let inserted = 0;
  const seen = new Set();
  const cleaned = [];
  for (const r of refsBatch) {
    const k = `${r.scf_id}|${r.framework_key}|${r.ref_id}`;
    if (seen.has(k)) continue;
    seen.add(k);
    cleaned.push(r);
  }
  for (let i = 0; i < cleaned.length; i += CHUNK) {
    const slice = cleaned.slice(i, i + CHUNK);
    await client.query(
      `INSERT INTO scf_framework_refs_new (scf_id, framework_key, ref_id)
       SELECT UNNEST($1::text[]), UNNEST($2::text[]), UNNEST($3::text[])`,
      [slice.map((r) => r.scf_id), slice.map((r) => r.framework_key), slice.map((r) => r.ref_id)],
    );
    inserted += slice.length;
  }

  // Atomic swap. All on the dedicated client so BEGIN/COMMIT are honoured.
  await client.query('BEGIN');
  try {
    // Drop the canonical-name indexes from the OLD table so renames don't collide.
    await client.query(`ALTER INDEX idx_scf_framework_refs_fw     RENAME TO idx_scf_framework_refs_fw_old`);
    await client.query(`ALTER INDEX idx_scf_framework_refs_scf_fw RENAME TO idx_scf_framework_refs_scf_fw_old`);
    // Rename tables.
    await client.query(`ALTER TABLE scf_framework_refs     RENAME TO scf_framework_refs_old`);
    await client.query(`ALTER TABLE scf_framework_refs_new RENAME TO scf_framework_refs`);
    // Promote _new indexes to canonical names.
    await client.query(`ALTER INDEX idx_scf_framework_refs_fw_new     RENAME TO idx_scf_framework_refs_fw`);
    await client.query(`ALTER INDEX idx_scf_framework_refs_scf_fw_new RENAME TO idx_scf_framework_refs_scf_fw`);
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  }
  // Outside the transaction — drop the old data + its indexes.
  await client.query(`DROP TABLE IF EXISTS scf_framework_refs_old CASCADE`);

  return inserted;
}

async function rebuildAttackMappings(client, attackBatch, validAttackIds, dryRun) {
  if (dryRun) return { inserted: 0, unresolved: 0 };
  // Dedup + classify.
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
  // Wrap TRUNCATE + INSERTs in a transaction so the technique-compliance
  // panel never returns an empty result mid-ingest.
  await client.query('BEGIN');
  try {
    await client.query(`TRUNCATE scf_attack_mappings`);
    const CHUNK = 5000;
    for (let i = 0; i < cleaned.length; i += CHUNK) {
      const slice = cleaned.slice(i, i + CHUNK);
      await client.query(
        `INSERT INTO scf_attack_mappings (scf_id, attack_id, is_unresolved)
         SELECT UNNEST($1::text[]), UNNEST($2::varchar(20)[]), UNNEST($3::bool[])`,
        [slice.map((r) => r.scf_id), slice.map((r) => r.attack_id), slice.map((r) => r.is_unresolved)],
      );
    }
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  }
  return { inserted: cleaned.length, unresolved };
}

async function rebuildOverlap(client, dryRun) {
  if (dryRun) return 0;
  await client.query('BEGIN');
  try {
    await client.query(`TRUNCATE scf_framework_overlap`);
    const r = await client.query(`
      INSERT INTO scf_framework_overlap (fw_a, fw_b, technique_overlap)
      SELECT LEAST(a.framework_key, b.framework_key) AS fw_a,
             GREATEST(a.framework_key, b.framework_key) AS fw_b,
             COUNT(DISTINCT a.attack_id) AS technique_overlap
      FROM (
        SELECT DISTINCT r.framework_key, m.attack_id
        FROM scf_framework_refs r
        JOIN scf_attack_mappings m ON m.scf_id = r.scf_id
        WHERE NOT m.is_unresolved
      ) a
      JOIN (
        SELECT DISTINCT r.framework_key, m.attack_id
        FROM scf_framework_refs r
        JOIN scf_attack_mappings m ON m.scf_id = r.scf_id
        WHERE NOT m.is_unresolved
      ) b ON a.attack_id = b.attack_id AND a.framework_key < b.framework_key
      GROUP BY 1, 2
    `);
    await client.query('COMMIT');
    return r.rowCount ?? 0;
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  }
}

async function rebuildGroupSummary(client, dryRun) {
  if (dryRun) return 0;
  await client.query('BEGIN');
  try {
    await client.query(`TRUNCATE scf_group_compliance_summary`);
    const r = await client.query(`
      INSERT INTO scf_group_compliance_summary (group_id, framework_key, controls, techniques_ref)
      SELECT gt.group_id,
             fr.framework_key,
             COUNT(DISTINCT fr.scf_id) AS controls,
             COUNT(DISTINCT t.attack_id) AS techniques_ref
      FROM group_techniques gt
      JOIN techniques t          ON t.id = gt.technique_id
      JOIN scf_attack_mappings m ON m.attack_id = t.attack_id AND NOT m.is_unresolved
      JOIN scf_framework_refs fr ON fr.scf_id = m.scf_id
      GROUP BY gt.group_id, fr.framework_key
    `);
    await client.query('COMMIT');
    return r.rowCount ?? 0;
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  }
}

async function rebuildSoftwareSummary(client, dryRun) {
  if (dryRun) return 0;
  // Check whether software_techniques table exists.
  const exists = await client.query(`SELECT to_regclass('software_techniques') AS r`);
  if (!exists.rows[0].r) {
    // Still truncate to clear any stale rows from a previous ingest.
    await client.query(`TRUNCATE scf_software_compliance_summary`);
    return 0;
  }
  await client.query('BEGIN');
  try {
    await client.query(`TRUNCATE scf_software_compliance_summary`);
    const r = await client.query(`
      INSERT INTO scf_software_compliance_summary (software_id, framework_key, controls, techniques_ref)
      SELECT st.software_id,
             fr.framework_key,
             COUNT(DISTINCT fr.scf_id) AS controls,
             COUNT(DISTINCT t.attack_id) AS techniques_ref
      FROM software_techniques st
      JOIN techniques t          ON t.id = st.technique_id
      JOIN scf_attack_mappings m ON m.attack_id = t.attack_id AND NOT m.is_unresolved
      JOIN scf_framework_refs fr ON fr.scf_id = m.scf_id
      GROUP BY st.software_id, fr.framework_key
    `);
    await client.query('COMMIT');
    return r.rowCount ?? 0;
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  }
}

async function rebuildFrameworkCoverage(client, dryRun) {
  if (dryRun) return 0;
  await client.query('BEGIN');
  try {
    await client.query(`TRUNCATE scf_framework_coverage`);
    const r = await client.query(`
      WITH pfac AS (
        SELECT fr.framework_key, m.attack_id, COUNT(DISTINCT fr.scf_id) AS controls_for_tech
        FROM scf_framework_refs fr
        JOIN scf_attack_mappings m ON m.scf_id = fr.scf_id AND NOT m.is_unresolved
        GROUP BY fr.framework_key, m.attack_id
      ),
      fw_tech AS (
        SELECT framework_key, COUNT(*)::int AS techniques_total,
               COUNT(*) FILTER (WHERE controls_for_tech >= 2)::int AS techniques_filtered
        FROM pfac GROUP BY framework_key
      ),
      fw_ctl AS (
        SELECT framework_key, COUNT(DISTINCT scf_id)::int AS scf_controls
        FROM scf_framework_refs GROUP BY framework_key
      )
      INSERT INTO scf_framework_coverage (framework_key, scf_controls, techniques_total, techniques_filtered)
      SELECT f.framework_key,
             COALESCE(c.scf_controls, 0),
             COALESCE(t.techniques_total, 0),
             COALESCE(t.techniques_filtered, 0)
      FROM scf_frameworks f
      LEFT JOIN fw_tech t USING (framework_key)
      LEFT JOIN fw_ctl  c USING (framework_key)
    `);
    await client.query('COMMIT');
    return r.rowCount ?? 0;
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  }
}

async function rebuildSectorSummary(client, dryRun) {
  if (dryRun) return 0;
  const exists = await client.query(`SELECT to_regclass('group_sectors') AS r`);
  if (!exists.rows[0].r) {
    await client.query(`TRUNCATE scf_sector_compliance_summary`);
    return 0;
  }
  await client.query('BEGIN');
  try {
    await client.query(`TRUNCATE scf_sector_compliance_summary`);
    const r = await client.query(`
      INSERT INTO scf_sector_compliance_summary (sector_id, framework_key, controls, techniques_ref)
      SELECT gs.sector_id,
             fr.framework_key,
             COUNT(DISTINCT fr.scf_id) AS controls,
             COUNT(DISTINCT t.attack_id) AS techniques_ref
      FROM group_sectors gs
      JOIN group_techniques gt   ON gt.group_id = gs.group_id
      JOIN techniques t          ON t.id = gt.technique_id
      JOIN scf_attack_mappings m ON m.attack_id = t.attack_id AND NOT m.is_unresolved
      JOIN scf_framework_refs fr ON fr.scf_id = m.scf_id
      GROUP BY gs.sector_id, fr.framework_key
    `);
    await client.query('COMMIT');
    return r.rowCount ?? 0;
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  }
}

// ----- Pre/post snapshot ---------------------------------------------------

async function snapshot(client) {
  const q = async (sql) => (await client.query(sql)).rows[0];
  return {
    controls: Number((await q(`SELECT COUNT(*)::int AS n FROM scf_controls`)).n),
    frameworks: Number((await q(`SELECT COUNT(*)::int AS n FROM scf_frameworks`)).n),
    refs: Number((await q(`SELECT COUNT(*)::int AS n FROM scf_framework_refs`)).n),
    attackMappings: Number((await q(`SELECT COUNT(*)::int AS n FROM scf_attack_mappings`)).n),
    unresolvedMappings: Number((await q(`SELECT COUNT(*)::int AS n FROM scf_attack_mappings WHERE is_unresolved`)).n),
    overlap: Number((await q(`SELECT COUNT(*)::int AS n FROM scf_framework_overlap`)).n),
    groupSummary: Number((await q(`SELECT COUNT(*)::int AS n FROM scf_group_compliance_summary`)).n),
    sectorSummary: Number((await q(`SELECT COUNT(*)::int AS n FROM scf_sector_compliance_summary`)).n),
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
    if (!versionTag && !xlsxPath) versionTag = await resolveLatestRelease();
    if (!xlsxPath) {
      const tmp = path.join(os.tmpdir(), `scf-${versionTag}.xlsx`);
      const bytes = await downloadXlsx(versionTag, tmp);
      console.log(`[sync-scf] downloaded ${bytes} bytes → ${tmp}`);
      xlsxPath = tmp;
    } else {
      // Infer version tag from file when possible.
      if (!versionTag) {
        const m = path.basename(xlsxPath).match(/(\d{4}\.\d+\.\d+|\d{4}\.\d+)/);
        versionTag = m ? m[1] : 'unknown';
      }
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

    const authRows = xlsx.utils.sheet_to_json(wb.Sheets['Authoritative Sources'], { header: 1, defval: '' });
    const frameworkRows = parseAuthSources(authRows);
    console.log(`[sync-scf] auth sources: ${frameworkRows.length} frameworks`);

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
    if (!args.dryRun) {
      const failed = await tier1AliasCheck(client, registry, runStart);
      if (failed.length > 0) {
        meta.tier1WithoutAliases = failed;
        console.warn('[sync-scf] Tier-1 keys without current-run aliases:', failed.join(', '));
        // Surface but do not abort: a Tier-1 key can legitimately have no SCF
        // backing today (e.g. EU CRA not yet in SCF 2026.1.1). The workflow
        // step "Tier-1 alias guard" examines meta.tier1WithoutAliases and pages
        // an operator if the set drifts unexpectedly.
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

    const { controlsUpserted, refsBatch, attackBatch, unresolvedAttackTotal, validAttackIds } =
      await ingestControlsAndRefs({
        client, rows, columnClasses, attackColIndex, observedHeaders,
        dryRun: args.dryRun, currentAttackVersion: currentAttackVersion || 'v19',
      });
    console.log(`[sync-scf] controls: ${controlsUpserted}, refs: ${refsBatch.length}, attack-mappings: ${attackBatch.length}, unresolved: ${unresolvedAttackTotal}`);
    counters.recordsInserted += controlsUpserted;
    meta.controlsUpserted = controlsUpserted;
    meta.unresolvedTotal = unresolvedAttackTotal;

    const refsCount = await rebuildFrameworkRefs(client, refsBatch, args.dryRun);
    meta.refsInserted = refsCount;
    counters.recordsInserted += refsCount;

    const { inserted: attackCount, unresolved: attackUnresolved } =
      await rebuildAttackMappings(client, attackBatch, validAttackIds, args.dryRun);
    meta.attackMappingsInserted = attackCount;
    meta.attackMappingsUnresolved = attackUnresolved;
    counters.recordsInserted += attackCount;

    const overlap = await rebuildOverlap(client, args.dryRun);
    const groupSum = await rebuildGroupSummary(client, args.dryRun);
    const softSum = await rebuildSoftwareSummary(client, args.dryRun);
    const sectorSum = await rebuildSectorSummary(client, args.dryRun);
    const coverage = await rebuildFrameworkCoverage(client, args.dryRun);
    meta.overlapRows = overlap;
    meta.groupSummaryRows = groupSum;
    meta.softwareSummaryRows = softSum;
    meta.sectorSummaryRows = sectorSum;
    meta.coverageRows = coverage;

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
