/**
 * sync-d3fend.mjs — D3FEND countermeasure mappings, whole corpus in one pass.
 *
 * Moved off Vercel cron for the same reason OSV was: Vercel caps a cron
 * invocation at 300s whatever `maxDuration` says, and a full sweep of the 794
 * live Enterprise + ICS techniques costs about 5 minutes at D3FEND's one-call-
 * per-technique API plus a 200ms courtesy delay. It did not fit, so the route
 * carried a 300-technique cursor and swept the corpus across several runs --
 * and when it overran anyway it logged `Soft timeout: exceeded 270000ms`.
 *
 * A cursor is only worth its complexity while the budget forces it. Here there
 * is no budget, so every run is a complete refresh and the cadence can simply
 * match how often D3FEND publishes. That also retires the failure mode the
 * route's own comments describe: a cursor that swept the ICS range three months
 * before D3FEND published ICS mappings, found nothing, and would not have
 * returned for years.
 *
 * `app/api/cron/sync-d3fend/route.ts` stays for manual, auth-gated runs, as
 * `sync-osv` did. It is no longer scheduled.
 *
 * Usage:
 *   node scripts/sync-d3fend.mjs
 *   node scripts/sync-d3fend.mjs --domain=ics-attack
 *   node scripts/sync-d3fend.mjs --from=T0800 --limit=20
 *   node scripts/sync-d3fend.mjs --limit=5 --dry-run     # no writes at all
 *
 * Requires: DATABASE_URL, and `pg`.
 */

import pkg from 'pg';

const { Pool } = pkg;

const D3FEND_API = 'https://d3fend.mitre.org/api/offensive-technique/attack';
const RATE_LIMIT_MS = 200;
/** D3FEND's ontology covers Enterprise and ICS only; Mobile and ATLAS carry no counters. */
const D3FEND_DOMAINS = ['enterprise-attack', 'ics-attack'];
const RELATIONSHIP = 'counters';

const arg = (name) => {
  const hit = process.argv.find((a) => a.startsWith(`--${name}=`));
  return hit ? hit.slice(name.length + 3) : null;
};
const flag = (name) => process.argv.includes(`--${name}`);

const DRY_RUN = flag('dry-run');
const FROM = arg('from');
const LIMIT = Number(arg('limit')) > 0 ? Math.trunc(Number(arg('limit'))) : null;
const DOMAINS = arg('domain')
  ? arg('domain').split(',').map((d) => d.trim()).filter((d) => D3FEND_DOMAINS.includes(d))
  : D3FEND_DOMAINS;

if (DOMAINS.length === 0) {
  console.error(`--domain must be one or more of ${D3FEND_DOMAINS.join(', ')}`);
  process.exit(1);
}

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const query = (text, params) => pool.query(text, params);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function main() {
  if (!process.env.DATABASE_URL) {
    console.error('DATABASE_URL is not set.');
    process.exit(1);
  }

  const techResult = await query(
    `SELECT id, attack_id FROM techniques
      WHERE is_revoked = false AND is_deprecated = false
        AND domain = ANY($1)
      ORDER BY attack_id ASC`,
    [DOMAINS],
  );

  let techniques = techResult.rows;
  if (FROM) {
    const idx = techniques.findIndex((t) => t.attack_id >= FROM);
    techniques = idx === -1 ? [] : techniques.slice(idx);
  }
  if (LIMIT) techniques = techniques.slice(0, LIMIT);

  const total = techniques.length;
  console.log(
    `D3FEND sync: ${total} techniques (${DOMAINS.join(', ')})` +
      `${FROM ? ` from ${FROM}` : ''}${LIMIT ? ` limit ${LIMIT}` : ''}${DRY_RUN ? ' — DRY RUN, no writes' : ''}`,
  );
  const started = Date.now();

  let logId = null;
  if (!DRY_RUN) {
    // Sweep any run stranded in `running` by an earlier hard kill.
    await query(
      `UPDATE feed_sync_log
          SET status = 'error', completed_at = NOW(), error_message = 'Timed out (auto-cleaned)'
        WHERE source = 'd3fend' AND status = 'running' AND started_at < NOW() - INTERVAL '15 minutes'`,
    );
    const logResult = await query(
      `INSERT INTO feed_sync_log (source, status, started_at)
       VALUES ('d3fend', 'running', NOW()) RETURNING id`,
    );
    logId = logResult.rows[0].id;
  }

  let recordsInserted = 0;
  let recordsSkipped = 0;
  let recordsPruned = 0;
  let techniquesProcessed = 0;
  let techniquesWithMappings = 0;
  let fetchFailures = 0;
  let lastAttackId = null;

  try {
    for (const [i, tech] of techniques.entries()) {
      try {
        const resp = await fetch(`${D3FEND_API}/${tech.attack_id}.json`, {
          headers: { Accept: 'application/json' },
          signal: AbortSignal.timeout(10_000),
        });

        if (resp.status === 404) {
          techniquesProcessed++;
          lastAttackId = tech.attack_id;
          await sleep(RATE_LIMIT_MS);
          continue;
        }
        if (!resp.ok) {
          console.warn(`  ${tech.attack_id}: HTTP ${resp.status}`);
          fetchFailures++;
          await sleep(RATE_LIMIT_MS);
          continue;
        }

        const data = await resp.json();
        const bindings = data.off_to_def?.results?.bindings ?? [];
        const seen = new Set();

        if (bindings.length > 0) {
          for (const b of bindings) {
            const defId = b.def_tech_id?.value;
            if (!defId || seen.has(defId)) continue;
            seen.add(defId);
            if (DRY_RUN) { recordsSkipped++; continue; }

            // DO UPDATE, not DO NOTHING: a name, tactic or URL corrected
            // upstream has to reach us, and the cron once wrote rows with no
            // url and no relationship that looked identical otherwise.
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
                tech.id, tech.attack_id, defId, b.def_tech_label?.value ?? null,
                b.def_tactic_label?.value ?? null, RELATIONSHIP, b.def_tech?.value ?? null,
              ],
            );
            if (result.rows[0]?.inserted) recordsInserted++; else recordsSkipped++;
          }

          // Prune ONLY when the fetch succeeded and returned mappings. A
          // technique that genuinely has none takes the branch below and prunes
          // nothing, so one flaky response cannot delete a whole set.
          if (!DRY_RUN) {
            const pruned = await query(
              `DELETE FROM defensive_mappings
                WHERE technique_id = $1 AND NOT (d3fend_id = ANY($2::text[]))`,
              [tech.id, [...seen]],
            );
            recordsPruned += pruned.rowCount ?? 0;
          }
        } else {
          // Pre-2025 shape, still served for some techniques.
          for (const mapping of data['off-tech']?.def_to_off_map ?? []) {
            for (const defTech of mapping.def_techs ?? []) {
              if (!defTech.def_tech_id) continue;
              if (DRY_RUN) { recordsSkipped++; continue; }
              const result = await query(
                `INSERT INTO defensive_mappings
                   (technique_id, attack_technique_id, d3fend_id, d3fend_name, d3fend_tactic, relationship)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (technique_id, d3fend_id) DO NOTHING
                 RETURNING id`,
                [tech.id, tech.attack_id, defTech.def_tech_id, defTech.def_tech_label,
                 defTech.def_tactic_label ?? null, RELATIONSHIP],
              );
              if (result.rows.length > 0) recordsInserted++; else recordsSkipped++;
            }
          }
        }

        techniquesProcessed++;
        if (bindings.length > 0) techniquesWithMappings++;
        lastAttackId = tech.attack_id;
      } catch (techErr) {
        fetchFailures++;
        console.error(`  ${tech.attack_id}: ${techErr instanceof Error ? techErr.message : techErr}`);
      }

      if ((i + 1) % 100 === 0) {
        console.log(`  ${i + 1}/${total} — ${recordsInserted} new, ${recordsSkipped} unchanged, ${recordsPruned} pruned`);
      }
      await sleep(RATE_LIMIT_MS);
    }

    const elapsed = Math.round((Date.now() - started) / 1000);
    const summary = {
      lastAttackId,
      techniquesProcessed,
      techniquesWithMappings,
      recordsPruned,
      fetchFailures,
      domains: DOMAINS,
      mode: LIMIT || FROM ? 'partial' : 'full-sweep',
      cursorPosition: `${techniquesProcessed}/${total}`,
      elapsedSeconds: elapsed,
    };

    if (!DRY_RUN) {
      await query(
        `UPDATE feed_sync_log
            SET status = 'success', completed_at = NOW(),
                records_inserted = $1, records_skipped = $2, metadata = $3
          WHERE id = $4 AND status = 'running'`,
        [recordsInserted, recordsSkipped, JSON.stringify(summary), logId],
      );
    }

    console.log(`Done in ${elapsed}s:`, JSON.stringify(summary));
    // A sweep where nothing reached the API is a failed sweep, not an empty one.
    if (total > 0 && techniquesProcessed === 0) {
      throw new Error(`no technique was processed (${fetchFailures} fetch failures) — treating as failure`);
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('D3FEND sync failed:', msg);
    if (!DRY_RUN && logId) {
      await query(
        `UPDATE feed_sync_log
            SET status = 'error', completed_at = NOW(), error_message = $1
          WHERE id = $2 AND status = 'running'`,
        [msg.slice(0, 500), logId],
      );
    }
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
}

main();
