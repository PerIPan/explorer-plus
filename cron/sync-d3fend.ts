import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../api/v1/_lib/db';

const D3FEND_API = 'https://d3fend.mitre.org/api/offensive-technique/attack';
const RATE_LIMIT_MS = 300;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

interface D3fendDefTech {
  def_tech_label: string;
  def_tech_id: string;
  def_tactic_label?: string;
}

interface D3fendApiResponse {
  'off-tech': {
    label: string;
    def_to_off_map?: Array<{ def_techs?: D3fendDefTech[] }>;
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
    const techResult = await query<{ id: string; attack_id: string }>(
      `SELECT id, attack_id FROM techniques
       WHERE is_revoked = false AND is_deprecated = false
       ORDER BY attack_id ASC`,
    );

    const techniques = techResult.rows;

    for (const tech of techniques) {
      try {
        const resp = await fetch(`${D3FEND_API}/${tech.attack_id}.json`, {
          headers: { Accept: 'application/json' },
          signal: AbortSignal.timeout(10_000),
        });

        if (resp.status === 404) {
          techniquesProcessed++;
          await sleep(RATE_LIMIT_MS);
          continue;
        }

        if (!resp.ok) {
          console.warn(`D3FEND API error for ${tech.attack_id}: ${resp.status}`);
          await sleep(RATE_LIMIT_MS);
          continue;
        }

        const data = (await resp.json()) as D3fendApiResponse;
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
              [
                tech.id,
                tech.attack_id,
                defTech.def_tech_id,
                defTech.def_tech_label,
                defTech.def_tactic_label ?? null,
              ],
            );

            if (result.rows.length > 0) recordsInserted++; else recordsSkipped++;
          }
        }

        techniquesProcessed++;
      } catch (techErr) {
        console.error(`D3FEND error for ${tech.attack_id}:`, techErr);
      }

      await sleep(RATE_LIMIT_MS);
    }

    await query(
      `UPDATE feed_sync_log
       SET status = 'success', completed_at = NOW(),
           records_inserted = $1, records_skipped = $2
       WHERE id = $3`,
      [recordsInserted, recordsSkipped, logId],
    );

    res.status(200).json({
      ok: true,
      source: 'd3fend',
      recordsInserted,
      recordsSkipped,
      techniquesProcessed,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('D3FEND sync error:', err);

    // Never delete existing mappings on failure
    await query(
      `UPDATE feed_sync_log
       SET status = 'error', completed_at = NOW(), error_message = $1
       WHERE id = $2`,
      [msg, logId],
    );

    res.status(500).json({ ok: false, error: msg });
  }
}
