import { NextRequest, NextResponse } from 'next/server';
import { query } from '../../v1/lib/db.js';
import { verifyCronAuth } from '../lib/auth';

export const maxDuration = 300;

const VT_BASE = 'https://www.virustotal.com/api/v3';

// Free tier: 4 requests/min, 500 requests/day
// Each hash = 2 calls (file + behavior) -> process ~2 hashes per run to stay safe
const BATCH_SIZE = 2;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function GET(req: NextRequest) {
  const authError = verifyCronAuth(req);
  if (authError) return authError;

  const apiKey = process.env.VT_API_KEY;
  if (!apiKey) {
    return NextResponse.json({ error: 'VT_API_KEY not configured' }, { status: 500 });
  }

  // Clean up stale "running" entries (timed-out previous runs)
  await query(
    `UPDATE feed_sync_log
     SET status = 'error', completed_at = NOW(), error_message = 'Timed out (auto-cleaned)'
     WHERE source = 'virustotal' AND status = 'running' AND started_at < NOW() - INTERVAL '15 minutes'`,
  );

  const logResult = await query<{ id: string }>(
    `INSERT INTO feed_sync_log (source, status, started_at)
     VALUES ('virustotal', 'running', NOW())
     RETURNING id`,
  );
  const logId = logResult.rows[0].id;

  let recordsInserted = 0;
  let recordsSkipped = 0;
  let techniquesLinked = 0;

  try {
    // Find hashes not yet enriched by VT
    const pending = await query<{ id: string; value: string }>(
      `SELECT id, value FROM ioc_entries
       WHERE type = 'hash' AND vt_enriched_at IS NULL
       ORDER BY first_seen DESC NULLS LAST
       LIMIT $1`,
      [BATCH_SIZE],
    );

    const headers = { 'x-apikey': apiKey, 'User-Agent': 'mitre-explorer/1.0' };

    for (const row of pending.rows) {
      try {
        // 1. Get file verdict
        const fileResp = await fetch(`${VT_BASE}/files/${row.value}`, { headers });

        if (!fileResp.ok) {
          if (fileResp.status === 404) {
            // Not in VT -- mark as enriched to skip next time
            await query(
              `UPDATE ioc_entries SET vt_enriched_at = NOW(), vt_verdict = 'not_found' WHERE id = $1`,
              [row.id],
            );
            recordsSkipped++;
            await sleep(15000); // rate limit
            continue;
          }
          if (fileResp.status === 429) {
            console.warn('VT rate limit hit, stopping batch');
            break;
          }
          throw new Error(`VT file API: ${fileResp.status}`);
        }

        const fileData = await fileResp.json();
        const attrs = fileData.data?.attributes ?? {};
        const stats = attrs.last_analysis_stats ?? {};
        const malicious = stats.malicious ?? 0;
        const total = Object.values(stats).reduce((a: number, b) => a + (b as number), 0);
        const verdict = malicious > 0 ? 'malicious' : 'clean';
        const fileType = attrs.type_description ?? null;

        // Update ioc_entries with VT verdict
        await query(
          `UPDATE ioc_entries
           SET vt_malicious = $1, vt_total = $2, vt_verdict = $3, vt_file_type = $4, vt_enriched_at = NOW()
           WHERE id = $5`,
          [malicious, total, verdict, fileType, row.id],
        );

        await sleep(15000); // 4 req/min -> 15s between requests

        // 2. Get behavior summary for ATT&CK techniques
        const behavResp = await fetch(`${VT_BASE}/files/${row.value}/behaviour_summary`, { headers });

        if (behavResp.ok) {
          const behavData = await behavResp.json();
          const techniques = behavData.data?.mitre_attack_techniques ?? [];

          // Dedupe by technique ID, keep highest severity
          const severityOrder: Record<string, number> = {
            IMPACT_SEVERITY_HIGH: 4,
            IMPACT_SEVERITY_MEDIUM: 3,
            IMPACT_SEVERITY_LOW: 2,
            IMPACT_SEVERITY_INFO: 1,
          };
          const techMap = new Map<string, string>();
          for (const t of techniques) {
            const id = t.id;
            if (!id) continue;
            const existing = techMap.get(id);
            if (!existing || (severityOrder[t.severity] ?? 0) > (severityOrder[existing] ?? 0)) {
              techMap.set(id, t.severity);
            }
          }

          // Link each technique to this IOC
          for (const [techId] of techMap) {
            // Normalize: VT returns IDs like "T1055" or "1055" -- ensure T prefix
            const attackId = techId.startsWith('T') ? techId : `T${techId}`;

            // Look up technique by attack_id
            const techResult = await query<{ id: string }>(
              `SELECT id FROM techniques WHERE attack_id = $1 LIMIT 1`,
              [attackId],
            );

            if (!techResult.rows[0]) continue;

            await query(
              `INSERT INTO technique_iocs (technique_id, ioc_id, confidence)
               VALUES ($1, $2, 'sandbox_verified')
               ON CONFLICT (technique_id, ioc_id) DO UPDATE SET confidence = 'sandbox_verified'`,
              [techResult.rows[0].id, row.id],
            );
            techniquesLinked++;
          }
        }

        recordsInserted++;
        await sleep(15000); // rate limit before next hash
      } catch (hashErr) {
        console.error(`VT enrich failed for ${row.value}:`, hashErr);
        recordsSkipped++;
      }
    }

    await query(
      `UPDATE feed_sync_log
       SET status = 'success', completed_at = NOW(),
           records_inserted = $1, records_skipped = $2,
           metadata = $3
       WHERE id = $4`,
      [recordsInserted, recordsSkipped, JSON.stringify({ techniquesLinked }), logId],
    );

    return NextResponse.json({
      ok: true,
      source: 'virustotal',
      recordsInserted,
      recordsSkipped,
      techniquesLinked,
      pending: pending.rows.length,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('VT enrich error:', err);

    await query(
      `UPDATE feed_sync_log
       SET status = 'error', completed_at = NOW(), error_message = $1
       WHERE id = $2`,
      [msg, logId],
    );

    return NextResponse.json({ ok: false, error: 'VT enrichment failed' }, { status: 500 });
  }
}
