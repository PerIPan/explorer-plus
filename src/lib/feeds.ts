/**
 * The ingestion sources /cti/feed-status renders, in display order.
 *
 * Lifted out of the view because the sidebar quotes the COUNT: a number in the
 * nav that disagrees with the number of cards on the page is the same drift the
 * API catalogue guard exists to stop, and here it is avoidable outright by
 * having one array. `FeedStatus` maps over it; the sidebar takes `.length`.
 *
 * Its own module rather than `site.ts`: that one is imported by `middleware.ts`
 * and runs on the edge for every request, and it deliberately has no imports and
 * nothing in it but scalars.
 *
 * NOT derived from `feed_sync_log` on purpose — the page lists the feeds that are
 * SUPPOSED to run, so a source that has never logged a sync still shows up as
 * pending instead of silently vanishing from the list.
 */
/**
 * Sources with no schedule — run by hand, on purpose.
 *
 * `attack_update` rotates the ATT&CK corpus underneath every page on the site,
 * so its workflow is dispatch-only with a version guard and a snapshot diff for
 * a human to read. `ics_assets` is a backfill. Neither is late when it is old,
 * and without saying so a reader has to assume every row here is a cron that
 * has stopped firing.
 *
 * They stay in THIS list rather than moving to the manual table section below,
 * because that section shows row counts for tables, and these are sync runs:
 * moving them would drop the status, the last run and the error text, which is
 * the only reason they are worth showing at all.
 */
export const MANUAL_SOURCES: ReadonlySet<string> = new Set(['attack_update', 'ics_assets']);

export const FEED_SOURCES = [
  // The ATT&CK corpus itself and the ICS asset catalogue. Both log to
  // feed_sync_log and neither was listed here, so neither could ever show a
  // failure on the page that exists to surface failures — attack_update logged
  // five errors before succeeding on 2026-09-25 and none of it was visible.
  'attack_update', 'ics_assets',
  'otx', 'abuse_ch', 'cisa_kev', 'rss',
  'nvd', 'virustotal',
  'cve_delta', 'cve_products',
  'epss', 'osv', 'csf',
  'ghsa', 'ghsa_delta', 'sigma', 'atomic',
  'matview_refresh', 'd3fend',
  'site_health', 'scf', 'cti_heat_refresh',
] as const;

/**
 * The framework/reference tables the same page lists under the feed cards.
 *
 * Here with FEED_SOURCES because the sidebar quotes the page's TOTAL row count,
 * and a count assembled from arrays in two files is a count that drifts. The
 * strings cost about a kilobyte gzipped in the shell chunk, which is the price
 * of the number being right by construction instead of by a guard.
 */
export interface FrameworkTable {
  key: string;
  label: string;
  description: string;
  /** If true, empty state is intentional — source data pending, not a sync failure */
  expectedEmpty?: boolean;
}

export const AUTOMATED_TABLES: FrameworkTable[] = [
  { key: 'cve_details', label: 'CVE Details', description: 'CVElistV5 corpus with CVSS, CWE, KEV flag, EPSS enrichment' },
  { key: 'cve_weaknesses', label: 'CVE Weaknesses', description: 'CWE weakness categorisation per CVE' },
  { key: 'affected_products', label: 'Affected Products', description: 'CVE ↔ application edges with version ranges' },
  { key: 'applications', label: 'Applications (CVElistV5)', description: 'Vendor/product rows extracted from CVE CPE data' },
  { key: 'ghsa_advisories', label: 'GitHub Security Advisories', description: 'Reviewed OSS package advisories — npm, PyPI, Maven, Go, …' },
  { key: 'ghsa_weaknesses', label: 'GHSA CWE Mappings', description: 'CWE weakness categorisation per GHSA advisory' },
  { key: 'ghsa_packages', label: 'GHSA Affected Packages', description: 'Per-package vulnerable/fixed version ranges' },
  { key: 'packages', label: 'Packages (derived from GHSA)', description: 'Unique (ecosystem, package) pairs across 8 OSS ecosystems' },
  { key: 'osv_advisories', label: 'OSV Advisories (OS, distro, kernel)', description: 'Non-GHSA ecosystems — Linux, Debian, Ubuntu, Alpine, Android, OSS-Fuzz, …' },
  { key: 'osv_affected', label: 'OSV Affected Packages', description: 'Per-package version ranges for OSV advisories' },
  { key: 'csf_technique_mappings', label: 'NIST CSF v2 → ATT&CK', description: 'CRI Profile crosswalk: CSF subcategory → ATT&CK technique' },
  { key: 'defensive_mappings', label: 'D3FEND', description: 'Defensive countermeasures from the MITRE D3FEND knowledge graph' },
  { key: 'sigma_rules', label: 'Sigma Rules', description: '3,100+ detection rules from SigmaHQ with ATT&CK mappings' },
  { key: 'atomic_tests', label: 'Atomic Red Team', description: '1,770+ adversary-emulation tests (PowerShell/bash/batch)' },
];

export const REFERENCE_TABLES: FrameworkTable[] = [
  { key: 'csf_subcategories', label: 'NIST CSF v2 Subcategories', description: 'GV/ID/PR/DE/RS/RC functions — 23 subcategories from the 2024 release' },
  { key: 'csf_implementation_examples', label: 'NIST CSF v2 Examples', description: 'One-line implementation examples per CSF subcategory' },
  { key: 'csf_informative_references', label: 'NIST CSF v2 References', description: 'Informative references into NIST 800-53 r5 and ISO 27001:2022' },
  { key: 'owasp_top10', label: 'OWASP Top 10 (Web, ML, LLM)', description: '30 categories across 3 frameworks — CWEs, ATT&CK techniques, ATLAS techniques' },
  { key: 'nist_controls', label: 'NIST 800-53', description: '5,200+ security controls from NIST 800-53 r5 mapped to ATT&CK' },
  { key: 'engage_mappings', label: 'MITRE Engage', description: 'Adversary engagement activities — deception and engagement mappings' },
  { key: 'react_actions', label: 'RE&CT', description: 'ATC incident-response playbook actions — Identification, Containment, …' },
  { key: 'veris_mappings', label: 'VERIS', description: 'Verizon DBIR incident classification (Actor/Action/Asset/Attribute)' },
  { key: 'cloud_control_mappings', label: 'Cloud Controls (AWS + Azure + GCP)', description: 'Cloud provider security controls mapped to ATT&CK techniques' },
  { key: 'capec_mappings', label: 'CAPEC → ATT&CK Bridge', description: 'CWE → CAPEC → ATT&CK pivot, powers CVE→technique chain' },
  { key: 'capec_patterns', label: 'CAPEC Patterns (full taxonomy)', description: '615 attack patterns with prerequisites, skills, consequences, related patterns' },
  { key: 'capec_mitigations', label: 'CAPEC Mitigations', description: 'Per-pattern mitigation guidance from the CAPEC taxonomy' },
  { key: 'detection_strategies', label: 'Detection Strategies', description: 'ATT&CK v18 detection strategies — high-level detection intent' },
  { key: 'detection_analytics', label: 'Detection Analytics', description: 'Concrete analytics (pseudo-code / query logic) per detection strategy' },
  { key: 'external_actors', label: 'ETDA / ThaiCERT Actors', description: '514 external threat actors — country, motivation, MITRE group mapping' },
  { key: 'atlas_xrefs', label: 'ATLAS Cross-References', description: 'ATT&CK ↔ ATLAS technique cross-walks (AI/ML adversary TTPs)' },
  { key: 'ctid_mappings', label: 'CTID CVE → Technique', description: 'Hand-curated CVE to ATT&CK technique mappings from MITRE CTID' },
];

/** Every row /cti/feed-status renders: feed cards, then both table sections. */
export const FEED_STATUS_ROW_COUNT =
  FEED_SOURCES.length + AUTOMATED_TABLES.length + REFERENCE_TABLES.length;
