import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../v1/lib/db.js';

const D3FEND_API = 'https://d3fend.mitre.org/api/offensive-technique/attack';
const RATE_LIMIT_MS = 200;
const BATCH_SIZE = 15;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

interface SparqlValue {
  type: string;
  value: string;
}

interface D3fendBinding {
  def_tech_id?: SparqlValue;
  def_tech_label?: SparqlValue;
  def_tactic_label?: SparqlValue;
  [key: string]: SparqlValue | undefined;
}

interface D3fendApiResponse {
  off_to_def?: {
    results?: {
      bindings?: D3fendBinding[];
    };
  };
  // Legacy format (pre-2025)
  'off-tech'?: {
    def_to_off_map?: Array<{ def_techs?: Array<{ def_tech_id: string; def_tech_label: string; def_tactic_label?: string }> }>;
  };
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== 'GET' && req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }

  const logResult = await query<{ id: string }>(
    `INSERT INTO feed_sync_log (source, status, started_at)
     VALUES ('d3fend', 'running', NOW())
     RETURNING id`,
  );
  const logId = logResult.rows[0].id;

  let recordsInserted = 0;
  let recordsSkipped = 0;
  let techniquesProcessed = 0;

  try {
    // Resume from last processed attack_id stored in metadata
    const lastLogResult = await query<{ metadata: Record<string, unknown> | null }>(
      `SELECT metadata FROM feed_sync_log
       WHERE source = 'd3fend' AND status = 'success'
       ORDER BY completed_at DESC LIMIT 1`,
    );
    const lastAttackId = (lastLogResult.rows[0]?.metadata?.lastAttackId as string) ?? null;

    const techResult = await query<{ id: string; attack_id: string }>(
      `SELECT id, attack_id FROM techniques
       WHERE is_revoked = false AND is_deprecated = false
       ORDER BY attack_id ASC`,
    );

    const allTechniques = techResult.rows;
    // Resume after lastAttackId; if cycled through all, restart from beginning
    let startIndex = 0;
    if (lastAttackId) {
      const idx = allTechniques.findIndex((t) => t.attack_id > lastAttackId);
      startIndex = idx === -1 ? 0 : idx; // restart if we reached the end last time
    }

    const batch = allTechniques.slice(startIndex, startIndex + BATCH_SIZE);
    let finalAttackId: string | null = null;

    for (const tech of batch) {
      try {
        const resp = await fetch(`${D3FEND_API}/${tech.attack_id}.json`, {
          headers: { Accept: 'application/json' },
          signal: AbortSignal.timeout(10_000),
        });

        if (resp.status === 404) {
          techniquesProcessed++;
          finalAttackId = tech.attack_id;
          await sleep(RATE_LIMIT_MS);
          continue;
        }

        if (!resp.ok) {
          console.warn(`D3FEND API error for ${tech.attack_id}: ${resp.status}`);
          await sleep(RATE_LIMIT_MS);
          continue;
        }

        const data = (await resp.json()) as D3fendApiResponse;

        // Parse SPARQL bindings (current format) or legacy format
        const bindings = data.off_to_def?.results?.bindings ?? [];
        const seen = new Set<string>(); // dedup within same technique

        if (bindings.length > 0) {
          for (const b of bindings) {
            const defId = b.def_tech_id?.value;
            const defLabel = b.def_tech_label?.value;
            if (!defId || seen.has(defId)) continue;
            seen.add(defId);

            const result = await query(
              `INSERT INTO defensive_mappings
                 (technique_id, attack_technique_id, d3fend_id, d3fend_name, d3fend_tactic)
               VALUES ($1, $2, $3, $4, $5)
               ON CONFLICT (technique_id, d3fend_id) DO NOTHING
               RETURNING id`,
              [tech.id, tech.attack_id, defId, defLabel ?? null, b.def_tactic_label?.value ?? null],
            );
            if (result.rows.length > 0) recordsInserted++; else recordsSkipped++;
          }
        } else {
          // Legacy format fallback
          const defMap = data['off-tech']?.def_to_off_map ?? [];
          for (const mapping of defMap) {
            for (const defTech of mapping.def_techs ?? []) {
              if (!defTech.def_tech_id) continue;
              const result = await query(
                `INSERT INTO defensive_mappings
                   (technique_id, attack_technique_id, d3fend_id, d3fend_name, d3fend_tactic)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (technique_id, d3fend_id) DO NOTHING
                 RETURNING id`,
                [tech.id, tech.attack_id, defTech.def_tech_id, defTech.def_tech_label, defTech.def_tactic_label ?? null],
              );
              if (result.rows.length > 0) recordsInserted++; else recordsSkipped++;
            }
          }
        }

        techniquesProcessed++;
        finalAttackId = tech.attack_id;
      } catch (techErr) {
        console.error(`D3FEND error for ${tech.attack_id}:`, techErr);
      }

      await sleep(RATE_LIMIT_MS);
    }

    await query(
      `UPDATE feed_sync_log
       SET status = 'success', completed_at = NOW(),
           records_inserted = $1, records_skipped = $2,
           metadata = $3
       WHERE id = $4`,
      [
        recordsInserted,
        recordsSkipped,
        JSON.stringify({ lastAttackId: finalAttackId }),
        logId,
      ],
    );

    res.status(200).json({
      ok: true,
      source: 'd3fend',
      recordsInserted,
      recordsSkipped,
      techniquesProcessed,
      resumedFrom: lastAttackId,
      lastProcessed: finalAttackId,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('D3FEND sync error:', err);

    await query(
      `UPDATE feed_sync_log
       SET status = 'error', completed_at = NOW(), error_message = $1
       WHERE id = $2`,
      [msg, logId],
    );

    res.status(500).json({ ok: false, error: msg });
  }
}
