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
 * composes into any ON/WHERE clause. It only ever REMOVES fan-out rows.
 *
 * Reads the `catchall_cwes` materialized view (a ~10-row lookup refreshed by
 * the refresh-matviews cron) instead of recomputing the GROUP BY/HAVING over
 * capec_mappings on every request — far cheaper, NULL-safe (the view's cwe_id
 * is never NULL), and a single source of truth. The view's definition mirrors
 * CATCHALL_CWE_THRESHOLD (see scripts/migrate-applications.sql).
 */
export function notCatchallCwe(col: string): string {
  return `${col} NOT IN (SELECT cwe_id FROM catchall_cwes)`;
}

/**
 * The (technique_id, cve_id) relation — every way this project links a CVE to
 * an ATT&CK technique, as one SQL fragment.
 *
 * Exists because the Threat Profile's evidence section COUNTS these links while
 * /api/v1/cves LISTS them, and the section's numbers link straight to that
 * list. When the two were written separately they disagreed: the section
 * reported 8 KEV CVEs for T1027 and the list it linked to showed 54, because
 * the section used only the weakness arm. A count that does not equal the page
 * it navigates to is the worst defect this pairing can have, so the definition
 * is written once, here.
 *
 * TWO ARMS, deliberately:
 *   1. the weakness chain, CVE -> CWE -> CAPEC -> technique, with catch-all
 *      CWEs removed (a CWE mapping to >10 techniques fans one CVE across
 *      dozens and is excluded project-wide — see notCatchallCwe above);
 *   2. `technique_iocs` rows of type 'cve'. For CVEs this is NOT the malware
 *      cross-product that makes IOC counts untrustworthy elsewhere: measured
 *      2026-10-03, CVE-type links are 5,874 `inferred` (the same CAPEC bridge)
 *      plus 349 `confirmed`, which is better evidence than arm 1 carries.
 *
 * KNOWN DEFECT, recorded rather than worked around: arm 2 currently holds
 * links derived from catch-all CWEs that arm 1 excludes by design, so the union
 * is slightly wider than the catch-all rule intends. Fixing it belongs in the
 * bridge that writes `technique_iocs`, and fixing it there corrects every
 * consumer of this fragment at once.
 */
export const TECHNIQUE_CVE_LINKS_SQL = `
  SELECT cm.technique_id, cw.cve_id
    FROM cve_weaknesses cw
    JOIN capec_mappings cm ON cm.cwe_id = cw.cwe_id AND ${notCatchallCwe('cm.cwe_id')}
   WHERE cm.technique_id IS NOT NULL
  UNION
  SELECT ti.technique_id, i.value AS cve_id
    FROM ioc_entries i
    JOIN technique_iocs ti ON ti.ioc_id = i.id
   WHERE i.type = 'cve'
`;

/**
 * SQL predicate fragment: the technique row aliased `alias` is live (not
 * revoked or deprecated in ATT&CK). The dashboard already filters this; every
 * path that COUNTS or LISTS mapping-derived techniques must use it too, or a
 * list's count diverges from the detail page's rendered set. Composes into any
 * JOIN ON / WHERE clause.
 */
export function liveTechnique(alias: string): string {
  return `${alias}.is_revoked = false AND ${alias}.is_deprecated = false`;
}
