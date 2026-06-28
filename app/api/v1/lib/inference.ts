/**
 * Single source of truth for the "catch-all CWE" exclusion.
 *
 * CVE/CWE → ATT&CK technique links derived through the CWE→CAPEC→technique
 * bridge are statistical INFERENCE, not curated fact. A handful of "catch-all"
 * CWEs (e.g. CWE-200 Information Exposure, CWE-284 Improper Access Control,
 * CWE-20 Improper Input Validation) map to dozens of unrelated techniques;
 * without excluding them a single generic CWE fans a CVE out across the whole
 * matrix — an info-disclosure CVE would imply "OS Credential Dumping".
 *
 * Every query that joins `capec_mappings` on a CWE id for DISPLAY or COUNT must
 * apply this, so the numbers stay consistent across the CVE list, CVE detail,
 * GHSA, packages, OWASP coverage, sectors, feed-intelligence and the heat
 * tables. Curated edges (capec_id = 'CTID-DIRECT') and CAPEC-entity lookups
 * (joined on attack_technique_id / capec_id) are NOT inference and must be left
 * untouched.
 *
 * The threshold mirrors the inline clause already proven in production in
 * app/api/v1/cves/[cveId]/route.ts and the app_technique_groups matview.
 * Build-time copies that cannot import this module (scripts/*.mjs, *.sql, and
 * the in-memory bridge in app/api/cron/lib/capec-bridge.ts) keep an inline copy
 * documented to match CATCHALL_CWE_THRESHOLD.
 */
export const CATCHALL_CWE_THRESHOLD = 10;

/**
 * SQL predicate fragment: true when `col` (a CWE id column, e.g. `cm.cwe_id`)
 * is NOT a catch-all CWE. Inline-safe — no bound params, no user input — so it
 * composes into any ON/WHERE clause. The subquery is the exact, prod-proven
 * clause; it only ever REMOVES fan-out rows, never adds any.
 */
export function notCatchallCwe(col: string): string {
  return `${col} NOT IN (
    SELECT cwe_id FROM capec_mappings
    WHERE technique_id IS NOT NULL
    GROUP BY cwe_id HAVING COUNT(DISTINCT technique_id) > ${CATCHALL_CWE_THRESHOLD}
  )`;
}
