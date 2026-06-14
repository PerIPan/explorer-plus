#!/usr/bin/env node
// scripts/refresh-cti-heat.mjs
//
// Standalone refresh for scf_technique_heat. CVE / GHSA / KEV / EPSS update
// daily; this script picks up the deltas so heat badges on /compliance/<key>
// stay current without waiting for the twice-yearly SCF sync.
//
// Triggered by .github/workflows/refresh-cti-heat.yml (1st of each month +
// workflow_dispatch). ~1-2 seconds for ~700 rows.

import pg from 'pg';

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) { console.error('DATABASE_URL required'); process.exit(1); }

async function main() {
  const pool = new pg.Pool({ connectionString: DATABASE_URL, keepAlive: true, max: 2 });
  const client = await pool.connect();
  const started = new Date();
  let logId = null;
  try {
    // feed_sync_log start
    const r = await client.query(
      `INSERT INTO feed_sync_log (source, status, started_at)
       VALUES ('cti_heat_refresh', 'running', NOW()) RETURNING id`,
    );
    logId = r.rows[0].id;

    await client.query('BEGIN');
    await client.query(`TRUNCATE scf_technique_heat`);
    const inserted = await client.query(`
      INSERT INTO scf_technique_heat (attack_id, cve_count, has_kev, max_epss, ghsa_count, group_count)
      WITH cve_tech AS (
        -- CURATED CVE->technique links only (capec_id='CTID-DIRECT', the
        -- analyst hand-mapped edges from sync-ctid-cve-mappings.mjs). The
        -- inferred CWE->CAPEC path fans catch-all CWEs (CWE-200/284/285/20)
        -- onto unrelated techniques, inverting the heat map; CTID-direct is
        -- precise and KEV-backed. No publish-date window: the curated set is
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
      SELECT t.attack_id,
             COALESCE(ct.cves, 0),
             COALESCE(ct.has_kev, false),
             NULL::numeric,   -- max_epss retired: EPSS-max pins ~0.94 over any KEV-containing set, so it never differentiates
             0,               -- ghsa_count retired: no curated GHSA->technique grounding (CTID maps CVEs, not GHSA)
             COALESCE(gtc.groups, 0)
      FROM techniques t
      LEFT JOIN cve_tech   ct  ON ct.attack_id  = t.attack_id
      LEFT JOIN group_tech gtc ON gtc.attack_id = t.attack_id
    `);
    await client.query('COMMIT');

    const elapsed = Date.now() - started.getTime();
    console.log(`[refresh-cti-heat] inserted ${inserted.rowCount} rows in ${elapsed}ms`);

    await client.query(
      `UPDATE feed_sync_log
       SET status='success', completed_at=NOW(),
           records_inserted=$1, metadata=$2
       WHERE id=$3`,
      [inserted.rowCount ?? 0, JSON.stringify({ trigger: 'github-actions', elapsedMs: elapsed }), logId],
    );
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch {}
    console.error('[refresh-cti-heat] FAILED:', e);
    if (logId) {
      try {
        await client.query(
          `UPDATE feed_sync_log SET status='error', completed_at=NOW(), error_message=$1 WHERE id=$2`,
          [(e?.message ?? String(e)).slice(0, 1000), logId],
        );
      } catch {}
    }
    process.exitCode = 1;
  } finally {
    client.release();
    await pool.end();
  }
}

main();
