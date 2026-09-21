import { NextRequest, NextResponse } from 'next/server';
import { query } from '../../v1/lib/db';
import { verifyCronAuth } from '../lib/auth';
import { withSoftTimeout, DEFAULT_SOFT_TIMEOUT_MS } from '../lib/softTimeout';

export const maxDuration = 300;

const D3FEND_API = 'https://d3fend.mitre.org/api/offensive-technique/attack';
const RATE_LIMIT_MS = 200;

/**
 * Techniques per run.
 *
 * Was 15. With a monthly cron and ~1,073 live techniques that is a SIX YEAR
 * cycle, and it showed: of the 5,037 rows in production, 5,036 came from a
 * single backfill and the cron added one row in six months. Worse, the cursor
 * swept the ICS range (T0800-T0895) in April 2026, three months before D3FEND
 * 1.5.0 published ICS mappings, found nothing, and moved on -- so ICS sat at
 * zero coverage with no prospect of a retry until about 2032.
 *
 * Measured cost is ~160ms of API latency plus the 200ms rate limit per
 * technique, so 300 costs roughly 110s against a 270s soft timeout. Paired
 * with a weekly schedule this refreshes the whole corpus about every 3 weeks.
 */
const BATCH_SIZE = 300;

/**
 * D3FEND only maps Enterprise and ICS ATT&CK. Sampling the live API found zero
 * countermeasures for every Mobile and ATLAS technique tried, and the ontology
 * confirms it: its offensive classes cover enterprise and ICS, while ATLAS
 * techniques carry no counters relationships. Requesting those 279 techniques
 * spent a third of every cycle to import nothing.
 */
const D3FEND_DOMAINS = ['enterprise-attack', 'ics-attack'];

/** off_to_def is D3FEND's countermeasure relation; the backfill labelled it this way. */
const RELATIONSHIP = 'counters';

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

export async function GET(req: NextRequest) {
  const authError = verifyCronAuth(req);
  if (authError) return authError;

  // Operational overrides, auth-gated like everything else here.
  //
  //   ?domain=ics-attack   scan only that ATT&CK domain
  //   ?from=T0800          start at this attack_id instead of the saved cursor
  //   ?batch=120           override BATCH_SIZE (capped, see below)
  //
  // These exist because the cursor is the whole problem: when D3FEND published
  // ICS mappings in July 2026 the cursor had already swept past T0800-T0895 and
  // would not have returned for years. Waiting for a cursor is not an incident
  // response. `from` is not persisted -- the run still saves its own end
  // position -- so a targeted rescan does not corrupt the normal rotation.
  const url = new URL(req.url);
  const domainParam = url.searchParams.get('domain');
  const fromParam = url.searchParams.get('from');
  const batchParam = Number(url.searchParams.get('batch'));
  const domains = domainParam
    ? domainParam.split(',').map((d) => d.trim()).filter((d) => D3FEND_DOMAINS.includes(d))
    : D3FEND_DOMAINS;
  if (domains.length === 0) {
    return NextResponse.json({ ok: false, error: `domain must be one of ${D3FEND_DOMAINS.join(', ')}` }, { status: 400 });
  }
  // Capped at 600: ~215s of API time against a 270s soft timeout.
  const batchSize = Number.isFinite(batchParam) && batchParam > 0 ? Math.min(Math.trunc(batchParam), 600) : BATCH_SIZE;

  // Clean up stale "running" entries (timed-out previous runs)
  await query(
    `UPDATE feed_sync_log
     SET status = 'error', completed_at = NOW(), error_message = 'Timed out (auto-cleaned)'
     WHERE source = 'd3fend' AND status = 'running' AND started_at < NOW() - INTERVAL '15 minutes'`,
  );

  const logResult = await query<{ id: string }>(
    `INSERT INTO feed_sync_log (source, status, started_at)
     VALUES ('d3fend', 'running', NOW())
     RETURNING id`,
  );
  const logId = logResult.rows[0].id;

  let recordsInserted = 0;
  let recordsSkipped = 0;
  let recordsPruned = 0;
  let techniquesProcessed = 0;
  let techniquesWithMappings = 0;

  try {
    return await withSoftTimeout(async () => {
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
         AND domain = ANY($1)
       ORDER BY attack_id ASC`,
      [domains],
    );

    const allTechniques = techResult.rows;
    // Resume after lastAttackId; if cycled through all, restart from beginning
    let startIndex = 0;
    if (fromParam) {
      const idx = allTechniques.findIndex((t) => t.attack_id >= fromParam);
      startIndex = idx === -1 ? 0 : idx;
    } else if (lastAttackId) {
      const idx = allTechniques.findIndex((t) => t.attack_id > lastAttackId);
      startIndex = idx === -1 ? 0 : idx; // restart if we reached the end last time
    }

    const batch = allTechniques.slice(startIndex, startIndex + batchSize);
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

            // d3fend_url and relationship are written here too. The backfill
            // populated them and the cron did not, so every row the cron added
            // was missing its link and its relation while looking identical
            // otherwise. DO UPDATE rather than DO NOTHING so a name, tactic or
            // URL corrected upstream actually reaches us.
            const result = await query(
              `INSERT INTO defensive_mappings
                 (technique_id, attack_technique_id, d3fend_id, d3fend_name, d3fend_tactic, relationship, d3fend_url)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               ON CONFLICT (technique_id, d3fend_id) DO UPDATE SET
                 attack_technique_id = EXCLUDED.attack_technique_id,
                 d3fend_name         = COALESCE(EXCLUDED.d3fend_name, defensive_mappings.d3fend_name),
                 d3fend_tactic       = COALESCE(EXCLUDED.d3fend_tactic, defensive_mappings.d3fend_tactic),
                 relationship        = COALESCE(EXCLUDED.relationship, defensive_mappings.relationship),
                 d3fend_url          = COALESCE(EXCLUDED.d3fend_url, defensive_mappings.d3fend_url)
               RETURNING (xmax = 0) AS inserted`,
              [
                tech.id, tech.attack_id, defId, defLabel ?? null,
                b.def_tactic_label?.value ?? null, RELATIONSHIP, b.def_tech?.value ?? null,
              ],
            );
            if (result.rows[0]?.inserted) recordsInserted++; else recordsSkipped++;
          }
          // Only prune when the fetch succeeded AND returned mappings. A
          // technique that legitimately has none takes the empty-bindings path
          // below, which does NOT prune -- otherwise one flaky response would
          // silently delete a technique's whole countermeasure set.
          const pruned = await query(
            `DELETE FROM defensive_mappings
              WHERE technique_id = $1 AND NOT (d3fend_id = ANY($2::text[]))`,
            [tech.id, [...seen]],
          );
          recordsPruned += pruned.rowCount ?? 0;
        } else {
          // Legacy format fallback
          const defMap = data['off-tech']?.def_to_off_map ?? [];
          for (const mapping of defMap) {
            for (const defTech of mapping.def_techs ?? []) {
              if (!defTech.def_tech_id) continue;
              const result = await query(
                `INSERT INTO defensive_mappings
                   (technique_id, attack_technique_id, d3fend_id, d3fend_name, d3fend_tactic, relationship)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (technique_id, d3fend_id) DO NOTHING
                 RETURNING id`,
                [tech.id, tech.attack_id, defTech.def_tech_id, defTech.def_tech_label, defTech.def_tactic_label ?? null, RELATIONSHIP],
              );
              if (result.rows.length > 0) recordsInserted++; else recordsSkipped++;
            }
          }
        }

        techniquesProcessed++;
        if (bindings.length > 0) techniquesWithMappings++;
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
       WHERE id = $4 AND status = 'running'`,
      [
        recordsInserted,
        recordsSkipped,
        JSON.stringify({
          lastAttackId: finalAttackId,
          techniquesProcessed,
          techniquesWithMappings,
          recordsPruned,
          batchSize,
          domains,
          ...(fromParam ? { forcedFrom: fromParam } : {}),
          // How far through one full pass this run got, so a stalled cursor is
          // visible in the feed status page instead of needing arithmetic.
          cursorPosition: `${startIndex + batch.length}/${allTechniques.length}`,
        }),
        logId,
      ],
    );

    return NextResponse.json({
      ok: true,
      source: 'd3fend',
      recordsInserted,
      recordsSkipped,
      recordsPruned,
      techniquesProcessed,
      techniquesWithMappings,
      cursorPosition: `${startIndex + batch.length}/${allTechniques.length}`,
      resumedFrom: lastAttackId,
      lastProcessed: finalAttackId,
    });
    }, DEFAULT_SOFT_TIMEOUT_MS);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('D3FEND sync error:', err);

    await query(
      `UPDATE feed_sync_log
       SET status = 'error', completed_at = NOW(), error_message = $1
       WHERE id = $2 AND status = 'running'`,
      [msg.slice(0, 500), logId],
    );

    console.error('[cron] error:', msg);
    return NextResponse.json({ ok: false, error: 'Feed sync failed' }, { status: 500 });
  }
}
