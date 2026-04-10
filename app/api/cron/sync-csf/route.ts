import { NextRequest, NextResponse } from 'next/server';
import { query } from '../../v1/lib/db';
import { verifyCronAuth } from '../lib/auth';

export const maxDuration = 300;

/**
 * CTID publishes CRI Profile v2.1 → ATT&CK mappings. CRI Profile extends NIST CSF v2
 * with diagnostic-level IDs like 'PR.AA-01.01'. We strip the trailing diagnostic
 * suffix to aggregate mappings back up to the base CSF subcategory level (e.g., 'PR.AA-01').
 *
 * Source: https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/mappings/cri_profile/attack-16.1/cri_profile-v2.1/enterprise/cri_profile-v2.1_attack-16.1-enterprise.json
 */
const CTID_URL =
  'https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/mappings/cri_profile/attack-16.1/cri_profile-v2.1/enterprise/cri_profile-v2.1_attack-16.1-enterprise.json';

interface CtidMappingObject {
  capability_id: string;        // e.g., 'PR.AA-01.01'
  attack_object_id: string;     // e.g., 'T1078.001'
  mapping_type?: string;
  status?: string;
}

interface CtidMappingFile {
  metadata?: unknown;
  mapping_objects?: CtidMappingObject[];
}

const CSF_SUBCATEGORY_RE = /^(GV|ID|PR|DE|RS|RC)\.[A-Z]{2}-\d{2}$/;
const ATTACK_ID_RE = /^T\d{4}(\.\d{3})?$/;

export async function GET(req: NextRequest) {
  const authError = verifyCronAuth(req);
  if (authError) return authError;

  // Clean up stale "running" entries
  await query(
    `UPDATE feed_sync_log
     SET status = 'error', completed_at = NOW(), error_message = 'Timed out (auto-cleaned)'
     WHERE source = 'csf' AND status = 'running' AND started_at < NOW() - INTERVAL '15 minutes'`,
  );

  const logResult = await query<{ id: string }>(
    `INSERT INTO feed_sync_log (source, status, started_at)
     VALUES ('csf', 'running', NOW())
     RETURNING id`,
  );
  const logId = logResult.rows[0].id;

  try {
    // ── 1. Fetch OUTSIDE transaction ───────────────────────────────────────
    const resp = await fetch(CTID_URL, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(30_000),
    });

    if (!resp.ok) {
      throw new Error(`CTID fetch failed: HTTP ${resp.status}`);
    }

    const data = (await resp.json()) as CtidMappingFile;
    const mappings = data.mapping_objects ?? [];

    if (mappings.length === 0) {
      throw new Error('CTID response has no mapping_objects (schema drift?)');
    }

    // ── 2. Normalize + dedupe in memory ─────────────────────────────────────
    // Strip trailing .NN diagnostic from capability_id to get base CSF subcategory.
    const seen = new Set<string>();
    const validMappings: Array<{ subcategory_id: string; attack_technique_id: string }> = [];

    for (const m of mappings) {
      const capId = m.capability_id;
      const attackId = m.attack_object_id;
      if (!capId || !attackId) continue;

      // Strip diagnostic suffix: 'PR.AA-01.01' → 'PR.AA-01'
      const baseSubId = capId.replace(/\.\d+$/, '').toUpperCase();

      if (!CSF_SUBCATEGORY_RE.test(baseSubId)) continue;
      if (!ATTACK_ID_RE.test(attackId)) continue;

      const key = `${baseSubId}|${attackId}`;
      if (seen.has(key)) continue;
      seen.add(key);

      validMappings.push({ subcategory_id: baseSubId, attack_technique_id: attackId });
    }

    if (validMappings.length === 0) {
      throw new Error('No valid mappings after normalization (schema drift?)');
    }

    // Lookup maps for FK resolution
    const subResult = await query<{ id: string; subcategory_id: string }>(
      `SELECT id, subcategory_id FROM csf_subcategories WHERE version = '2.0'`,
    );
    const subUuidMap = new Map(subResult.rows.map((r) => [r.subcategory_id, r.id]));

    const techResult = await query<{ id: string; attack_id: string }>(
      `SELECT id, attack_id FROM techniques`,
    );
    const techUuidMap = new Map(techResult.rows.map((r) => [r.attack_id, r.id]));

    // ── 3. Transaction: DELETE + bulk INSERT ───────────────────────────────
    await query('BEGIN');
    try {
      await query(`DELETE FROM csf_technique_mappings WHERE mapping_source = 'ctid'`);

      let inserted = 0;
      let skippedUnknownSub = 0;
      const CHUNK_SIZE = 500;

      for (let i = 0; i < validMappings.length; i += CHUNK_SIZE) {
        const chunk = validMappings.slice(i, i + CHUNK_SIZE);
        const rows: unknown[] = [];
        const placeholders: string[] = [];

        for (const m of chunk) {
          const subUuid = subUuidMap.get(m.subcategory_id);
          if (!subUuid) {
            skippedUnknownSub++;
            continue; // subcategory not in our seed (shouldn't happen after seed)
          }
          const techUuid = techUuidMap.get(m.attack_technique_id) ?? null;

          const base = rows.length;
          rows.push(subUuid, m.subcategory_id, techUuid, m.attack_technique_id, 'ctid', false);
          placeholders.push(
            `($${base + 1}::uuid, $${base + 2}, $${base + 3}::uuid, $${base + 4}, $${base + 5}, $${base + 6})`,
          );
        }

        if (placeholders.length === 0) continue;

        const res = await query(
          `INSERT INTO csf_technique_mappings
             (csf_subcategory_uuid, subcategory_id, technique_id, attack_technique_id, mapping_source, is_draft)
           VALUES ${placeholders.join(',')}
           ON CONFLICT (subcategory_id, attack_technique_id) DO NOTHING`,
          rows,
        );
        inserted += res.rowCount ?? 0;
      }

      await query('COMMIT');

      await query(
        `UPDATE feed_sync_log
         SET status = 'success', completed_at = NOW(),
             records_inserted = $1, records_skipped = $2,
             metadata = $3
         WHERE id = $4`,
        [
          inserted,
          skippedUnknownSub,
          JSON.stringify({
            totalRawMappings: mappings.length,
            totalValidMappings: validMappings.length,
            source: 'cri_profile-v2.1',
          }),
          logId,
        ],
      );

      return NextResponse.json({
        ok: true,
        source: 'csf',
        recordsInserted: inserted,
        recordsSkipped: skippedUnknownSub,
        totalValidated: validMappings.length,
        totalRaw: mappings.length,
      });
    } catch (txErr) {
      await query('ROLLBACK');
      throw txErr;
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('CSF sync error:', err);

    await query(
      `UPDATE feed_sync_log
       SET status = 'error', completed_at = NOW(), error_message = $1
       WHERE id = $2`,
      [msg, logId],
    );

    return NextResponse.json({ ok: false, error: 'Feed sync failed' }, { status: 500 });
  }
}
