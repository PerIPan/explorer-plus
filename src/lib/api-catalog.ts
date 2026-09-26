/**
 * The open-API catalogue — ONE description of the public surface, read by three
 * consumers.
 *
 *   1. the top-bar "APIs / MCP" modal (src/components/api/ApiCatalogPanel.tsx)
 *   2. /open-apis  — the full REST reference, with live calls
 *   3. /open-mcp   — the MCP + A2A reference
 *
 * It replaced `API_GROUPS`, a hand-maintained array inside AppShell.tsx that had
 * drifted to 55 documented paths against 86 real routes with nothing to notice.
 * `scripts/check-api-catalog.mjs` now walks `app/api/v1/**` and fails the build
 * on a route that is in neither this catalogue nor the guard's `EXCLUDED` map,
 * and on an entry with no route. So adding a route to /api/v1 forces a decision
 * in review — document it for outside callers, or record why it is internal.
 *
 * WHAT BELONGS HERE: an endpoint an outside caller could use to get information
 * for their own project. Not an inventory of every route. Endpoints that exist
 * to run this site — a feed sync, the VirusTotal quota probe, a telemetry write,
 * the bulk CSV export — are absent by decision, and the reason is recorded in
 * the guard's `EXCLUDED` map rather than shown to visitors here.
 *
 * TOOL DESCRIPTIONS DO NOT LIVE HERE. `src/lib/tools/declarations.ts` is their
 * only home — that text is serialised into every MCP client's context and into
 * the Gemini function declarations, so a second copy written for humans would
 * both drift and cost tokens on every agent turn. This file keys tools by NAME
 * and adds only grouping plus the `/api/v1` path each one bottoms out in
 * (from src/lib/tools/execute.ts). No description string crosses the seam, so
 * the seam cannot drift.
 *
 * Client-safe: imports `./site` only. Do NOT add a zod, `next/server` or
 * `app/api/**` import — every consumer below is a `'use client'` component.
 */

import { DOCS_PROBE_HEADER, SITE_URL } from './site';

/* ───────────────────────────── types ───────────────────────────── */

export type ApiGroupKey =
  | 'attack'
  | 'actors'
  | 'cti'
  | 'vulns'
  | 'supply'
  | 'frameworks'
  | 'compliance'
  | 'ics'
  | 'profile';

export interface ApiGroupMeta {
  key: ApiGroupKey;
  label: string;
  blurb: string;
}

export interface ApiParam {
  name: string;
  type: 'string' | 'number' | 'boolean';
  /** Omitted means optional. */
  required?: boolean;
  /** Closed vocabulary, where the route enforces one. */
  values?: readonly string[];
  note?: string;
}

export interface ApiEntry {
  /** Relative to the base URL. `{name}` marks a dynamic segment. */
  path: string;
  method: 'GET' | 'POST';
  group: ApiGroupKey;
  /** One line, present tense, no marketing. */
  summary: string;
  params?: readonly ApiParam[];
  /** True adds the shared `page`/`limit`/`sort`/`order` set + the envelope. */
  paginated?: boolean;
  /**
   * The relative path the live-Run button calls, with real ids and a small
   * `limit` baked in. Absent for every non-executable entry.
   */
  example?: string;
  /** False → no Run button, and `why` is shown in its place. */
  executable: boolean;
  why?: string;
}

/* ─────────────────────── connection facts ─────────────────────── */

/**
 * Everything a caller needs before the first request. Single copy: the same
 * three surfaces state these, and `AppShell` used to hardcode the origin six
 * times over.
 */
export const API_FACTS = {
  baseUrl: `${SITE_URL}/api/v1`,
  mcpUrl: `${SITE_URL}/api/mcp`,
  a2aUrl: `${SITE_URL}/api/a2a`,
  agentCardPath: '/.well-known/agent-card.json',
  llmsTxtPath: '/llms.txt',
  auth: 'none — no key, no sign-up, no account, no header',
  cors: "Access-Control-Allow-Origin: * — browser dashboards can read it directly",
  /**
   * Corrected 2026-09-26. The modal claimed "heavy automated traffic is
   * rate-limited per IP at the edge". No such limit exists on /api/v1: only
   * /api/a2a (50/day per IP) and /api/v1/profile/submit (a write) are metered.
   * Do not reintroduce a limit in copy before one exists in code.
   */
  rateLimit: 'none on /api/v1. Only POST /api/a2a (50 requests/day per IP) and POST /api/v1/profile/submit are metered.',
  cache: 'Some routes set s-maxage and are served from the CDN; the rest reach the origin on every request.',
  pagination: {
    envelope: '{ data: [...], pagination: { page, limit, total, totalPages } }',
    page: '1-based, max 100',
    limit: 'max 5000, default 50',
    /** Was missing from llms.txt until 2026-09-25; an external caller guessed. */
    noOffset: 'There is no ?offset=. An unknown query parameter is IGNORED, so ?offset=50 silently returns page 1.',
  },
  /** Wording kept consistent with public/llms.txt on purpose. */
  versionFilter:
    'Add ?version= to /cves, /cves/{cveId}, /applications, /applications/{vendor}/{product}, /packages, /packages/{ecosystem}/{name} and /ghsa/{ghsaId}. It is a SUBSTRING/TEXT match on the affected-version range, not a semantic "is this version vulnerable" verdict. On the LIST endpoints it REQUIRES product context (app for /cves; search or vendor for /applications; ecosystem or q for /packages), else HTTP 400.',
  errors: '{ error, code } with a 4xx status. An unusable filter value fails loudly rather than being dropped.',
} as const;

/** Re-exported so the docs components import one module. See site.ts for why. */
export { DOCS_PROBE_HEADER };

export const API_GROUP_META: readonly ApiGroupMeta[] = [
  { key: 'attack', label: 'ATT&CK core', blurb: 'Techniques, tactics, malware, mitigations, data sources, the matrix and cross-domain search.' },
  { key: 'actors', label: 'Threat actors', blurb: 'ATT&CK groups and campaigns, the ThaiCERT/ETDA actor set, and the sectors they target.' },
  { key: 'cti', label: 'CTI feeds', blurb: 'Reports, IOCs, Sigma rules, Atomic tests and the per-technique intelligence rollup.' },
  { key: 'vulns', label: 'Vulnerabilities', blurb: 'CVEs with CVSS, EPSS and KEV, CAPEC patterns, and the vendor products they affect.' },
  { key: 'supply', label: 'Supply chain', blurb: 'GHSA + OSV advisories, packages and per-ecosystem dashboards.' },
  { key: 'frameworks', label: 'Frameworks', blurb: 'OWASP, NIST CSF and 800-53, ISO 27001, D3FEND, Engage, RE&CT, VERIS and cloud controls.' },
  { key: 'compliance', label: 'Compliance', blurb: 'Regulatory regimes bridged to ATT&CK through the Secure Controls Framework.' },
  { key: 'ics', label: 'ICS / OT', blurb: 'ATT&CK for ICS assets and the Purdue model they are placed on.' },
  { key: 'profile', label: 'Threat profile', blurb: 'The ranked briefing the /profile page renders, as data.' },
];

/* ───────────────────── shared parameter sets ───────────────────── */

export const PAGINATION_PARAMS: readonly ApiParam[] = [
  { name: 'page', type: 'number', note: '1-based, max 100. Default 1.' },
  { name: 'limit', type: 'number', note: 'Max 5000. Default 50.' },
  { name: 'sort', type: 'string', note: 'Route-specific sort key.' },
  { name: 'order', type: 'string', values: ['asc', 'desc'], note: 'Default asc.' },
];

const DOMAINS = ['enterprise-attack', 'ics-attack', 'mobile-attack', 'atlas-attack'] as const;

const SECTORS = [
  'defense', 'education', 'energy', 'financial', 'government', 'healthcare',
  'manufacturing', 'media', 'retail', 'technology', 'telecommunications', 'transportation',
] as const;

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;

const P = {
  domain: { name: 'domain', type: 'string', values: DOMAINS } as ApiParam,
  sector: { name: 'sector', type: 'string', values: SECTORS } as ApiParam,
  search: { name: 'search', type: 'string', note: 'Full-text over name and description, 3-character minimum. Not a substring match.' } as ApiParam,
  q: { name: 'q', type: 'string' } as ApiParam,
  severity: { name: 'severity', type: 'string', values: SEVERITIES } as ApiParam,
  since: { name: 'since', type: 'string', note: 'ISO-8601 date. Only rows published after it.' } as ApiParam,
  version: { name: 'version', type: 'string', note: 'Text match on an affected-version range — not a vulnerability verdict. Needs product context on list routes.' } as ApiParam,
  includeAll: { name: 'include_all', type: 'boolean', note: 'Adds the Tier 3 long tail (~250 frameworks). Default false — the curated 21.' } as ApiParam,
  includeDeprecated: { name: 'include_deprecated', type: 'boolean', note: 'Revoked and deprecated ATT&CK entries are excluded by default.' } as ApiParam,
  hasCve: { name: 'has_cve', type: 'string', values: ['true', 'false'], note: 'Filter on CVE-alias presence.' } as ApiParam,
} as const;

/* ─────────────────────────── the catalogue ─────────────────────────── */

/**
 * Reasons the Run button is withheld. Only one exists: two routes are keyed by
 * a feed UUID that rotates, so no example can be baked in and still resolve.
 * Every endpoint that would have COST something to run — the VirusTotal probe, a
 * feed sync, the telemetry write, the CSV export — is absent from the catalogue
 * altogether rather than listed as un-runnable (see the guard's `EXCLUDED` map).
 */
const WHY = {
  rotatingId: 'No baked example: the id is a UUID from the list route above and rotates as the feed moves. Copy one from that response.',
} as const;

export const API_CATALOG: readonly ApiEntry[] = [
  /* ── ATT&CK core ── */
  {
    path: '/techniques', method: 'GET', group: 'attack', paginated: true, executable: true,
    summary: 'Technique summaries across every ATT&CK domain plus ATLAS.',
    params: [P.search, { name: 'tactic', type: 'string', note: 'Tactic ATT&CK ID, e.g. TA0001.' }, { name: 'platform', type: 'string' }, P.sector, P.domain, P.includeDeprecated, { name: 'include_subtechniques', type: 'boolean' }],
    example: '/techniques?limit=3',
  },
  {
    path: '/techniques/{attackId}', method: 'GET', group: 'attack', executable: true,
    summary: 'One technique in full — tactics, platforms, sub-techniques, groups, malware, mitigations, CAPEC, ICS assets.',
    params: [P.domain, P.sector],
    example: '/techniques/T1059',
  },
  {
    path: '/techniques/{attackId}/packages', method: 'GET', group: 'attack', executable: true,
    summary: 'Packages reachable from a technique through the CWE→CAPEC bridge.',
    example: '/techniques/T1059/packages',
  },
  {
    path: '/tactics', method: 'GET', group: 'attack', executable: true,
    summary: 'Kill-chain tactics, in ATT&CK order.',
    params: [P.sector, P.domain],
    example: '/tactics',
  },
  {
    path: '/tactics/{attackId}', method: 'GET', group: 'attack', executable: true,
    summary: 'One tactic and every technique under it.',
    example: '/tactics/TA0001',
  },
  {
    path: '/software', method: 'GET', group: 'attack', paginated: true, executable: true,
    summary: 'Malware and tool summaries, each tagged malware or tool.',
    params: [P.search, { name: 'type', type: 'string', values: ['malware', 'tool'] }, { name: 'platform', type: 'string' }, P.sector, P.domain, P.includeDeprecated],
    example: '/software?limit=3',
  },
  {
    path: '/software/{attackId}', method: 'GET', group: 'attack', executable: true,
    summary: 'One malware or tool — aliases, platforms, techniques used, groups, campaigns.',
    example: '/software/S0154',
  },
  {
    path: '/mitigations', method: 'GET', group: 'attack', paginated: true, executable: true,
    summary: 'Countermeasure summaries.',
    params: [P.search, P.domain, P.includeDeprecated],
    example: '/mitigations?limit=3',
  },
  {
    path: '/mitigations/{attackId}', method: 'GET', group: 'attack', executable: true,
    summary: 'One mitigation and every technique it addresses.',
    example: '/mitigations/M1036',
  },
  {
    path: '/data-sources', method: 'GET', group: 'attack', executable: true,
    summary: 'Detection data sources and their components.',
    params: [P.search, P.domain],
    example: '/data-sources',
  },
  {
    path: '/data-sources/{attackId}', method: 'GET', group: 'attack', executable: true,
    summary: 'One data source — its components and the techniques they detect.',
    example: '/data-sources/DS0009',
  },
  {
    path: '/matrix', method: 'GET', group: 'attack', executable: true,
    summary: 'The tactic × technique matrix, ready to render.',
    params: [P.domain, P.sector],
    example: '/matrix',
  },
  {
    path: '/relationships/{attackId}', method: 'GET', group: 'attack', executable: true,
    summary: 'Graph neighbours of any ATT&CK entity, for the 360 views.',
    params: [{ name: 'limit', type: 'number', note: 'Caps neighbours per relation type.' }],
    example: '/relationships/T1059?limit=3',
  },
  {
    path: '/entities', method: 'GET', group: 'attack', executable: true,
    summary: 'Every entity id and name in one payload — the search index the client builds Fuse.js over.',
    params: [P.domain],
    example: '/entities',
  },
  {
    path: '/procedures', method: 'GET', group: 'attack', paginated: true, executable: true,
    summary: 'Procedure examples — the free text describing how a group, malware or campaign used a technique.',
    params: [{ ...P.q, required: true, note: 'Full-text over the procedure description, 3-character minimum. Required.' }],
    example: '/procedures?q=powershell&limit=3',
  },
  {
    path: '/search', method: 'GET', group: 'attack', executable: true,
    summary: 'Cross-domain keyword search over ATT&CK entities, OWASP categories and CSF subcategories.',
    params: [{ ...P.q, required: true, note: 'Minimum 3 characters.' }, P.domain],
    example: '/search?q=lazarus',
  },
  {
    path: '/dashboard', method: 'GET', group: 'attack', executable: true,
    summary: 'Corpus overview — entity counts, top groups, most-targeted techniques, ingested ATT&CK version.',
    params: [P.sector, P.domain],
    example: '/dashboard',
  },

  /* ── Threat actors ── */
  {
    path: '/groups', method: 'GET', group: 'actors', paginated: true, executable: true,
    summary: 'ATT&CK threat group summaries.',
    params: [P.search, P.sector, P.domain, P.includeDeprecated],
    example: '/groups?limit=3',
  },
  {
    path: '/groups/{attackId}', method: 'GET', group: 'actors', executable: true,
    summary: 'One group in full — techniques, malware, campaigns, targeted sectors, affected applications.',
    params: [P.domain],
    example: '/groups/G0016',
  },
  {
    path: '/campaigns', method: 'GET', group: 'actors', paginated: true, executable: true,
    summary: 'Named intrusion campaigns with first/last-seen dates.',
    params: [P.search, P.sector, P.domain, P.includeDeprecated],
    example: '/campaigns?limit=3',
  },
  {
    path: '/campaigns/{attackId}', method: 'GET', group: 'actors', executable: true,
    summary: 'One campaign — techniques, malware deployed, groups involved.',
    example: '/campaigns/C0028',
  },
  {
    path: '/external-actors', method: 'GET', group: 'actors', paginated: true, executable: true,
    summary: 'ThaiCERT / ETDA actors — 500+ names beyond the ATT&CK set, with country and motivation.',
    params: [P.search, { name: 'country', type: 'string' }, { name: 'category', type: 'string' }, { name: 'source', type: 'string' }, { name: 'mitre_group', type: 'string' }],
    example: '/external-actors?limit=3',
  },
  {
    path: '/external-actors/{name}', method: 'GET', group: 'actors', executable: true,
    summary: 'One external actor by exact name — reference metadata only, no TTPs.',
    example: '/external-actors/8220%20Gang',
  },
  {
    path: '/sectors', method: 'GET', group: 'actors', executable: true,
    summary: 'Industry sectors with the count of groups targeting each.',
    example: '/sectors',
  },
  {
    path: '/sectors/{slug}', method: 'GET', group: 'actors', executable: true,
    summary: 'One sector and the groups that target it.',
    example: '/sectors/financial',
  },
  {
    path: '/sectors/{slug}/relationships', method: 'GET', group: 'actors', executable: true,
    summary: 'A sector threat landscape — groups, campaigns, malware, top techniques, vulnerable applications.',
    example: '/sectors/financial/relationships',
  },

  /* ── CTI feeds ── */
  {
    path: '/feed/reports', method: 'GET', group: 'cti', paginated: true, executable: true,
    summary: 'Threat-intelligence reports from OTX, Unit 42, DFIR and other RSS sources, newest first.',
    params: [{ name: 'source', type: 'string' }, P.since, P.q, { name: 'sortBy', type: 'string' }, P.sector],
    example: '/feed/reports?limit=3',
  },
  {
    path: '/feed/reports/{reportId}/techniques', method: 'GET', group: 'cti', executable: false, why: WHY.rotatingId,
    summary: 'ATT&CK techniques extracted from one report.',
  },
  {
    path: '/feed/iocs', method: 'GET', group: 'cti', paginated: true, executable: true,
    summary: 'IOCs from OTX, ThreatFox, MalwareBazaar and CISA KEV, newest first.',
    params: [{ name: 'type', type: 'string', values: ['ip', 'domain', 'url', 'hash', 'cve', 'email'] }, { name: 'source', type: 'string', values: ['otx', 'threatfox', 'malwarebazaar', 'cisa_kev'] }, { name: 'malware', type: 'string' }, P.q, P.since, P.sector],
    example: '/feed/iocs?limit=3',
  },
  {
    path: '/feed/iocs/{iocId}/techniques', method: 'GET', group: 'cti', executable: false, why: WHY.rotatingId,
    summary: 'Techniques associated with one IOC, via sandbox reports.',
  },
  {
    path: '/feed/sigma', method: 'GET', group: 'cti', paginated: true, executable: true,
    summary: 'SigmaHQ detection rules with log source and mapped technique.',
    params: [{ name: 'technique', type: 'string' }, { name: 'level', type: 'string', values: ['critical', 'high', 'medium', 'low', 'informational'] }, P.q],
    example: '/feed/sigma?limit=3',
  },
  {
    path: '/feed/atomic', method: 'GET', group: 'cti', paginated: true, executable: true,
    summary: 'Atomic Red Team tests with executor, run command and cleanup.',
    params: [{ name: 'technique', type: 'string' }, { name: 'platform', type: 'string', values: ['windows', 'linux', 'macos'] }, P.q],
    example: '/feed/atomic?limit=3',
  },
  {
    path: '/feed/intelligence/{attackId}', method: 'GET', group: 'cti', executable: true,
    summary: 'Per-technique CTI rollup — reports, IOCs, CVEs, Sigma, Atomic, D3FEND, detection strategies.',
    example: '/feed/intelligence/T1059',
  },
  {
    path: '/feed/status', method: 'GET', group: 'cti', executable: true,
    summary: 'Ingestion health per feed — last run, row counts, errors.',
    example: '/feed/status',
  },

  /* ── Vulnerabilities ── */
  {
    path: '/cves', method: 'GET', group: 'vulns', paginated: true, executable: true,
    summary: 'CVE summaries with CVSS, EPSS, KEV, CWE and linked techniques — newest first, not worst first.',
    params: [P.severity, { name: 'source', type: 'string' }, P.q, P.sector, P.since, { name: 'technique', type: 'string' }, { name: 'app', type: 'string', note: 'Vendor/product substring.' }, P.version],
    example: '/cves?severity=CRITICAL&limit=3',
  },
  {
    path: '/cves/{cveId}', method: 'GET', group: 'vulns', executable: true,
    summary: 'One CVE in full — CWEs, EPSS, KEV, OWASP, affected apps, GHSA alias, aliasing OSV advisories.',
    params: [P.version],
    example: '/cves/CVE-2021-44228',
  },
  {
    path: '/cves/{cveId}/packages', method: 'GET', group: 'vulns', executable: true,
    summary: 'Open-source packages affected by one CVE, via its GHSA alias.',
    example: '/cves/CVE-2021-44228/packages',
  },
  {
    path: '/applications', method: 'GET', group: 'vulns', paginated: true, executable: true,
    summary: 'Affected vendor products with CVE, technique and group counts.',
    params: [P.search, { name: 'vendor', type: 'string' }, P.version],
    example: '/applications?limit=3',
  },
  {
    path: '/applications/{vendor}/{product}', method: 'GET', group: 'vulns', executable: true,
    summary: 'Product 360 — CVEs, CWE profile, reachable techniques and threat groups.',
    params: [{ name: 'page', type: 'number' }, { name: 'limit', type: 'number' }, P.version],
    example: '/applications/microsoft/windows',
  },
  {
    path: '/capec', method: 'GET', group: 'vulns', paginated: true, executable: true,
    summary: 'CAPEC attack-pattern summaries with CWE refs and mapped technique counts.',
    params: [{ ...P.q, note: 'Matches name and ID only, never description text. Minimum 2 characters.' }, { name: 'abstraction', type: 'string', values: ['Meta', 'Standard', 'Detailed'] }, { name: 'severity', type: 'string', values: ['Very Low', 'Low', 'Medium', 'High', 'Very High'] }, { name: 'likelihood', type: 'string', values: ['Low', 'Medium', 'High'] }],
    example: '/capec?limit=3',
  },
  {
    path: '/capec/{id}', method: 'GET', group: 'vulns', executable: true,
    summary: 'One CAPEC pattern — prerequisites, skills, consequences, CWEs, techniques, mitigations.',
    example: '/capec/CAPEC-66',
  },
  {
    path: '/home/recent-affected', method: 'GET', group: 'vulns', executable: true,
    summary: 'Applications and packages hit by a new advisory recently. Refreshed daily.',
    params: [{ name: 'days', type: 'number', note: 'Lookback window. Default 10.' }],
    example: '/home/recent-affected',
  },

  /* ── Supply chain ── */
  {
    path: '/advisories', method: 'GET', group: 'supply', paginated: true, executable: true,
    summary: 'Unified GHSA + OSV advisory rows, each tagged with its source. Severity-ranked, then newest.',
    params: [P.q, { name: 'source', type: 'string', values: ['GHSA', 'OSV'] }, P.severity, { name: 'ecosystem', type: 'string', note: 'GHSA names are lowercase; OSV keeps its own capitalisation (Debian, Ubuntu, Alpine).' }, P.since, P.hasCve],
    example: '/advisories?limit=3',
  },
  {
    path: '/ghsa', method: 'GET', group: 'supply', paginated: true, executable: true,
    summary: 'GHSA-only rows, with technique counts and withdrawal status the unified view omits.',
    params: [P.severity, { name: 'ecosystem', type: 'string' }, P.since, P.q, P.hasCve, { name: 'package', type: 'string' }, { name: 'include_withdrawn', type: 'boolean' }],
    example: '/ghsa?limit=3',
  },
  {
    path: '/ghsa/{ghsaId}', method: 'GET', group: 'supply', executable: true,
    summary: 'One GitHub Security Advisory — CVSS v3 and v4, CWEs, affected packages with vulnerable and fixed ranges.',
    params: [P.version],
    example: '/ghsa/GHSA-jfh8-c2jp-5v3q',
  },
  {
    path: '/osv/{osvId}', method: 'GET', group: 'supply', executable: true,
    summary: 'One OSV advisory by native id (DSA-, USN-, RLSA-, ALAS-) — distro, kernel and OS ecosystems.',
    example: '/osv/DSA-5678-1',
  },
  {
    path: '/packages', method: 'GET', group: 'supply', paginated: true, executable: true,
    summary: 'Package rows with advisory counts, severities and technique counts.',
    params: [{ name: 'ecosystem', type: 'string' }, P.q, P.version],
    example: '/packages?limit=3',
  },
  {
    path: '/packages/{ecosystem}/{name}', method: 'GET', group: 'supply', executable: true,
    summary: 'One package — every advisory affecting it, with ranges where the ecosystem models them.',
    params: [P.version, { name: 'include_withdrawn', type: 'boolean' }],
    example: '/packages/npm/lodash',
  },
  {
    path: '/ecosystems', method: 'GET', group: 'supply', executable: true,
    summary: 'Per-ecosystem advisory dashboards — totals, 14-day counts, severity split, top packages.',
    example: '/ecosystems',
  },
  {
    path: '/ecosystems/{slug}', method: 'GET', group: 'supply', executable: true,
    summary: 'One ecosystem in detail.',
    example: '/ecosystems/npm',
  },

  /* ── Frameworks ── */
  {
    path: '/frameworks/owasp', method: 'GET', group: 'frameworks', executable: true,
    summary: 'OWASP Top 10 categories for Web 2021, ML 2023 and LLM 2025, with per-category counts.',
    params: [{ name: 'framework', type: 'string', values: ['web-2021', 'ml-2023', 'llm-2025'] }],
    example: '/frameworks/owasp?framework=web-2021',
  },
  {
    path: '/frameworks/owasp/{categoryId}', method: 'GET', group: 'frameworks', executable: true,
    summary: 'One OWASP category — CWEs, techniques, ATLAS, top CVEs, affected applications.',
    example: '/frameworks/owasp/A01',
  },
  {
    path: '/frameworks/owasp/{categoryId}/packages', method: 'GET', group: 'frameworks', executable: true,
    summary: 'Packages whose advisories carry a CWE in one OWASP category.',
    example: '/frameworks/owasp/A01/packages',
  },
  {
    path: '/frameworks/csf', method: 'GET', group: 'frameworks', executable: true,
    summary: 'NIST CSF v2 functions and subcategories with technique counts.',
    example: '/frameworks/csf',
  },
  {
    path: '/frameworks/csf/{subcategoryId}', method: 'GET', group: 'frameworks', executable: true,
    summary: 'One CSF v2 subcategory, with its CRI Profile crosswalk.',
    example: '/frameworks/csf/GV.OC-01',
  },
  {
    path: '/frameworks/csf/{subcategoryId}/techniques', method: 'GET', group: 'frameworks', executable: true,
    summary: 'Techniques mapped to one CSF v2 subcategory.',
    example: '/frameworks/csf/GV.OC-01/techniques',
  },
  {
    path: '/frameworks/nist', method: 'GET', group: 'frameworks', executable: true,
    summary: 'NIST 800-53 r5 controls.',
    params: [P.search, { name: 'family', type: 'string', note: 'Control family, e.g. AC, SI.' }, { name: 'page', type: 'number' }, { name: 'limit', type: 'number' }],
    example: '/frameworks/nist?limit=3',
  },
  {
    path: '/frameworks/nist/{controlId}/techniques', method: 'GET', group: 'frameworks', executable: true,
    summary: 'Techniques one 800-53 control mitigates.',
    example: '/frameworks/nist/AC-2/techniques',
  },
  {
    path: '/frameworks/iso27001', method: 'GET', group: 'frameworks', executable: true,
    summary: 'ISO/IEC 27001:2022 Annex A controls and clauses, reached via the CSF v2 crosswalk.',
    example: '/frameworks/iso27001',
  },
  {
    path: '/frameworks/d3fend', method: 'GET', group: 'frameworks', executable: true,
    summary: 'D3FEND countermeasures grouped by defensive tactic.',
    example: '/frameworks/d3fend',
  },
  {
    path: '/frameworks/d3fend/{d3fendId}', method: 'GET', group: 'frameworks', executable: true,
    summary: 'One countermeasure — every technique it counters, plus overlapping countermeasures.',
    example: '/frameworks/d3fend/D3-AM',
  },
  {
    path: '/frameworks/engage', method: 'GET', group: 'frameworks', executable: true,
    summary: 'MITRE Engage adversary-engagement activities by goal and approach.',
    params: [P.search, { name: 'goal', type: 'string' }, { name: 'page', type: 'number' }, { name: 'limit', type: 'number' }],
    example: '/frameworks/engage?limit=3',
  },
  {
    path: '/frameworks/engage/{engageId}/techniques', method: 'GET', group: 'frameworks', executable: true,
    summary: 'Techniques one Engage activity applies to.',
    example: '/frameworks/engage/EAC0001/techniques',
  },
  {
    path: '/frameworks/react', method: 'GET', group: 'frameworks', executable: true,
    summary: 'RE&CT incident-response actions by response stage.',
    params: [P.search, { name: 'stage', type: 'string' }, { name: 'page', type: 'number' }, { name: 'limit', type: 'number' }],
    example: '/frameworks/react?limit=3',
  },
  {
    path: '/frameworks/veris', method: 'GET', group: 'frameworks', executable: true,
    summary: 'VERIS enumerations (the Verizon DBIR taxonomy) mapped to techniques.',
    params: [P.q, { name: 'category', type: 'string' }],
    example: '/frameworks/veris',
  },
  {
    path: '/frameworks/cloud-controls', method: 'GET', group: 'frameworks', executable: true,
    summary: 'AWS, Azure and GCP security controls mapped to techniques.',
    params: [{ name: 'provider', type: 'string', values: ['aws', 'azure', 'gcp'] }, P.q],
    example: '/frameworks/cloud-controls?provider=aws',
  },
  {
    path: '/frameworks/detection', method: 'GET', group: 'frameworks', executable: true,
    summary: 'ATT&CK Detection Strategies and Analytics.',
    params: [P.search, { name: 'technique', type: 'string' }, { name: 'page', type: 'number' }, { name: 'limit', type: 'number' }],
    example: '/frameworks/detection?limit=3',
  },
  {
    path: '/frameworks/technique/{attackId}', method: 'GET', group: 'frameworks', executable: true,
    summary: 'Every direct control mapping for one technique — 800-53, CSF, Engage, VERIS, cloud, OWASP.',
    example: '/frameworks/technique/T1059',
  },
  {
    path: '/frameworks/by-techniques', method: 'GET', group: 'frameworks', executable: true,
    summary: 'Framework coverage for a set of techniques at once — the bulk form of the route above.',
    params: [{ name: 'ids', type: 'string', required: true, note: 'Comma-separated ATT&CK IDs.' }],
    example: '/frameworks/by-techniques?ids=T1059',
  },
  {
    path: '/frameworks/status', method: 'GET', group: 'frameworks', executable: true,
    summary: 'Per-framework ingest state — row counts and last sync.',
    example: '/frameworks/status',
  },

  /* ── Compliance ── */
  {
    path: '/compliance/frameworks', method: 'GET', group: 'compliance', executable: true,
    summary: 'Regulatory frameworks bridged to ATT&CK through the SCF, with coverage counts.',
    params: [P.includeAll],
    example: '/compliance/frameworks',
  },
  {
    path: '/compliance/frameworks/{key}', method: 'GET', group: 'compliance', executable: true,
    summary: 'One framework — every technique it references, grouped by article, with the citing ref_id.',
    example: '/compliance/frameworks/eu-nis2',
  },
  {
    path: '/compliance/techniques/{attackId}', method: 'GET', group: 'compliance', executable: true,
    summary: 'Which frameworks reference one technique, with per-framework control counts.',
    params: [P.includeAll],
    example: '/compliance/techniques/T1059',
  },
  {
    path: '/compliance/tactics/{attackId}', method: 'GET', group: 'compliance', executable: true,
    summary: 'Framework coverage rolled up over one tactic.',
    params: [P.includeAll],
    example: '/compliance/tactics/TA0001',
  },
  {
    path: '/compliance/groups/{attackId}', method: 'GET', group: 'compliance', executable: true,
    summary: 'Framework coverage of the techniques one threat group uses.',
    params: [P.includeAll],
    example: '/compliance/groups/G0016',
  },
  {
    path: '/compliance/software/{attackId}', method: 'GET', group: 'compliance', executable: true,
    summary: 'Framework coverage of the techniques one malware or tool uses.',
    params: [P.includeAll],
    example: '/compliance/software/S0154',
  },
  {
    path: '/compliance/sectors/{slug}', method: 'GET', group: 'compliance', executable: true,
    summary: 'Framework coverage of the techniques aimed at one sector.',
    params: [P.includeAll],
    example: '/compliance/sectors/financial',
  },

  /* ── ICS / OT ── */
  {
    path: '/assets', method: 'GET', group: 'ics', paginated: true, executable: true,
    summary: 'ATT&CK for ICS assets — PLCs, RTUs, HMIs, historians, safety controllers, field I/O.',
    params: [P.search, { name: 'level', type: 'string', values: ['l0', 'l1', 'l2', 'l3', 'l3_5', 'l4', 'l5'], note: 'Levels the asset is PRESENT at, not only primary at.' }, { name: 'zone', type: 'string', values: ['ot', 'dmz', 'it'] }, { name: 'sector', type: 'string', note: 'The label MITRE puts on the asset — Electric, General, Water and Wastewater. Not the threat-group sector slug.' }, { name: 'boundary', type: 'boolean', note: 'True returns only assets present in the industrial DMZ.' }],
    example: '/assets?limit=3',
  },
  {
    path: '/assets/{attackId}', method: 'GET', group: 'ics', executable: true,
    summary: 'One ICS asset — ICS techniques targeting it, D3FEND countermeasures, Purdue placement.',
    example: '/assets/A0001',
  },
  {
    path: '/frameworks/purdue', method: 'GET', group: 'ics', executable: true,
    summary: 'The Purdue model as data — seven levels, placed assets, and the 42-pair flow matrix.',
    example: '/frameworks/purdue',
  },

  /* ── Threat profile ── */
  {
    path: '/profile', method: 'GET', group: 'profile', executable: true,
    summary: 'The ranked threat briefing — techniques, actors and controls scored for a stated environment.',
    params: [P.sector, { name: 'platforms', type: 'string', note: 'Comma-separated platform list.' }, { name: 'assets', type: 'string', note: 'Comma-separated ICS asset ids, for the OT briefing.' }, { name: 'levels', type: 'string', note: 'Comma-separated Purdue levels.' }, { name: 'sort', type: 'string' }, { name: 'domain', type: 'string', values: [...DOMAINS, 'all'], note: "Defaults to enterprise-attack. 'all' mixes domains and sets meta.mixedDomain." }],
    example: '/profile?sector=financial',
  },
];

/* ─────────────────────── tool grouping (names only) ─────────────────────── */

export interface ToolGroup {
  key: string;
  label: string;
  tools: readonly string[];
}

/**
 * Grouping for /open-mcp. Names ONLY — the description and parameter schema are
 * read from `TOOL_DECLARATIONS` at render time. The guard asserts this covers
 * every declared tool exactly once, so a new tool cannot ship ungrouped.
 */
export const TOOL_GROUPS: readonly ToolGroup[] = [
  { key: 'attack', label: 'ATT&CK', tools: ['get_technique_detail', 'get_technique_intelligence', 'get_tactic_detail', 'get_software_detail', 'search_software', 'get_mitigation_detail', 'search_mitigations', 'get_data_source_detail', 'search_entities', 'get_dashboard_stats'] },
  { key: 'actors', label: 'Threat actors', tools: ['get_group_profile', 'search_groups', 'get_campaign_detail', 'search_campaigns', 'get_external_actor', 'search_external_actors', 'get_sector_threats'] },
  { key: 'cti', label: 'CTI & detection', tools: ['get_threat_reports', 'search_iocs', 'search_sigma_rules', 'search_atomic_tests'] },
  { key: 'vulns', label: 'Vulnerabilities', tools: ['search_cves', 'get_cve_detail', 'get_cve_packages', 'search_capec', 'get_capec_detail', 'get_application_security', 'search_applications'] },
  { key: 'supply', label: 'Supply chain', tools: ['search_advisories', 'search_ghsa', 'get_ghsa_detail', 'get_osv_detail', 'get_package_vulnerabilities'] },
  { key: 'frameworks', label: 'Frameworks & compliance', tools: ['get_framework_mappings', 'get_owasp_top10', 'get_owasp_category', 'list_compliance_frameworks', 'get_compliance_framework', 'get_technique_compliance'] },
  { key: 'ics', label: 'ICS / OT', tools: ['search_assets', 'get_asset_detail', 'get_purdue_model'] },
  { key: 'meta', label: 'Server meta', tools: ['get_usage_guide'] },
];

/**
 * The `/api/v1` path each tool bottoms out in (src/lib/tools/execute.ts). Shown
 * on /open-mcp so a reader can see the REST route behind a tool — every tool
 * call is an HTTP hop to the same public API, which is why MCP results and curl
 * results are identical. `get_usage_guide` is the one tool that answers locally.
 */
export const TOOL_ENDPOINTS: Readonly<Record<string, string>> = {
  search_cves: '/cves',
  get_cve_detail: '/cves/{cveId}',
  get_cve_packages: '/cves/{cveId}/packages',
  get_technique_intelligence: '/feed/intelligence/{attackId}',
  get_technique_detail: '/techniques/{attackId}',
  get_group_profile: '/groups/{attackId}',
  search_groups: '/groups',
  get_application_security: '/applications/{vendor}/{product}',
  search_applications: '/applications',
  get_sector_threats: '/sectors/{slug}/relationships',
  search_entities: '/search',
  get_dashboard_stats: '/dashboard',
  get_framework_mappings: '/frameworks/technique/{attackId}',
  get_threat_reports: '/feed/reports',
  get_software_detail: '/software/{attackId}',
  search_software: '/software',
  get_campaign_detail: '/campaigns/{attackId}',
  search_campaigns: '/campaigns',
  get_mitigation_detail: '/mitigations/{attackId}',
  search_mitigations: '/mitigations',
  search_iocs: '/feed/iocs',
  search_sigma_rules: '/feed/sigma',
  search_atomic_tests: '/feed/atomic',
  get_external_actor: '/external-actors/{name}',
  search_external_actors: '/external-actors',
  get_tactic_detail: '/tactics/{attackId}',
  get_data_source_detail: '/data-sources/{attackId}',
  get_owasp_top10: '/frameworks/owasp',
  get_owasp_category: '/frameworks/owasp/{categoryId}',
  get_ghsa_detail: '/ghsa/{ghsaId}',
  get_package_vulnerabilities: '/packages/{ecosystem}/{name}',
  search_ghsa: '/ghsa',
  get_capec_detail: '/capec/{id}',
  search_capec: '/capec',
  search_advisories: '/advisories',
  get_osv_detail: '/osv/{osvId}',
  list_compliance_frameworks: '/compliance/frameworks',
  get_compliance_framework: '/compliance/frameworks/{key}',
  get_technique_compliance: '/compliance/techniques/{attackId}',
  search_assets: '/assets',
  get_asset_detail: '/assets/{attackId}',
  get_purdue_model: '/frameworks/purdue',
  get_usage_guide: '—  answered from src/lib/tools/guide.ts, no HTTP hop',
};

/* ───────────────────────────── helpers ───────────────────────────── */

/** Entries in one group, in catalogue order. */
export function entriesInGroup(key: ApiGroupKey): ApiEntry[] {
  return API_CATALOG.filter((e) => e.group === key);
}

/** A stable DOM/react key for an entry — `path` alone collides across methods. */
export function entryKey(entry: ApiEntry): string {
  return `${entry.method} ${entry.path}`;
}

/** Absolute URL for display and copy. The live Run always uses the relative path. */
export function absoluteUrl(pathOrExample: string): string {
  return `${API_FACTS.baseUrl}${pathOrExample}`;
}

export const EXECUTABLE_COUNT = API_CATALOG.filter((e) => e.executable).length;
