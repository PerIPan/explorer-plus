import { NextRequest, NextResponse } from 'next/server';
import { createHash } from 'node:crypto';
import { GoogleGenAI } from '@google/genai';
import { query } from '../v1/lib/db';
import { withCorsRestricted, corsOptionsRestricted } from '../lib/cors';

// A2A uses restricted CORS (origin allowlist) to prevent cross-origin browser
// pages from silently consuming a victim user's 50-req/day quota.
export async function OPTIONS(req: NextRequest) { return corsOptionsRestricted(req); }

/**
 * A2A (Agent-to-Agent) endpoint -- JSON-RPC 2.0 over HTTPS.
 * Accepts natural language queries, uses Gemini 3.1 Flash-Lite to interpret,
 * calls internal APIs, returns structured results.
 *
 * Rate limit: 50 req/day per IP, no auth required.
 */

const DAILY_LIMIT = 50;
const MODEL = 'gemini-3.1-flash-lite-preview';
const MAX_INPUT_LENGTH = 2000;
const BASE_URL = process.env.NEXT_PUBLIC_SITE_URL
  || (process.env.VERCEL_PROJECT_PRODUCTION_URL ? `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}` : null)
  || (process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : 'http://localhost:3000');

// -- Input validation --------------------------------------------------------

const CVE_RE = /^CVE-\d{4}-\d{4,}$/;
const ATTACK_ID_RE = /^(AML\.)?(TA|T|G|S|M|C|CS|DS)\d{4}(\.\d{3})?$/;
const CAPEC_ID_RE = /^CAPEC-\d+$/;
// OSV IDs are highly heterogeneous — DSA-5678-1, USN-6543-1, LBSEC-2024-0001,
// ALAS-2024-0017, RLSA-2024-1234, SUSE-SU-2024:0123-1, KERN-*, etc. Accept
// anything that starts alnum and stays within a safe punctuation set.
const OSV_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._\-/~:]{1,127}$/;
const SECTOR_RE = /^[a-z][a-z0-9-]{1,28}[a-z0-9]$/;
const DOMAIN_RE = /^(enterprise|ics|mobile|atlas)-attack$/;
const SEVERITY_VALUES = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);
const CAPEC_SEVERITY_VALUES = new Set(['Very Low', 'Low', 'Medium', 'High', 'Very High']);
const CAPEC_LIKELIHOOD_VALUES = new Set(['Low', 'Medium', 'High']);
const CAPEC_ABSTRACTION_VALUES = new Set(['Meta', 'Standard', 'Detailed']);
const ADVISORY_SOURCE_VALUES = new Set(['GHSA', 'OSV']);
// Ecosystem whitelist — union of GHSA (lowercase) + OSV (mixed case, preserved).
// Values here match what the /api/v1/advisories endpoint expects; it internally
// lowercases the GHSA side and case-matches the OSV side.
const ADVISORY_ECOSYSTEM_RE = /^[A-Za-z][A-Za-z0-9._\s-]{0,49}$/;

function validateCveId(id: unknown): string | null {
  const s = String(id ?? '').trim();
  return CVE_RE.test(s) ? s : null;
}

function validateAttackId(id: unknown): string | null {
  const s = String(id ?? '').trim();
  return ATTACK_ID_RE.test(s) ? s : null;
}

function validateCapecId(id: unknown): string | null {
  const s = String(id ?? '').trim().toUpperCase();
  return CAPEC_ID_RE.test(s) ? s : null;
}

function validateOsvId(id: unknown): string | null {
  const s = String(id ?? '').trim();
  return OSV_ID_RE.test(s) ? s : null;
}

function validateAdvisoryEcosystem(eco: unknown): string | null {
  const s = String(eco ?? '').trim();
  return ADVISORY_ECOSYSTEM_RE.test(s) ? s : null;
}

function validateSector(slug: unknown): string | null {
  const s = String(slug ?? '').trim().toLowerCase();
  return SECTOR_RE.test(s) ? s : null;
}

function validateDomain(d: unknown): string | null {
  const s = String(d ?? '').trim();
  return DOMAIN_RE.test(s) ? s : null;
}

function sanitizeSearch(q: unknown): string {
  return String(q ?? '').trim().slice(0, 200);
}

// -- Gemini function declarations for our API --------------------------------

const TOOL_DECLARATIONS = [
  {
    name: 'search_cves',
    description: 'Search CVE vulnerabilities by keyword, severity, or date range. Returns CVE ID, CVSS score, severity, description, linked ATT&CK technique IDs, and affected applications. Use get_cve_detail for EPSS exploit-probability score and CAPEC attack patterns.',
    parameters: {
      type: "OBJECT",
      properties: {
        q: { type: "STRING", description: 'Search query (CVE ID, keyword, CWE)' },
        severity: { type: "STRING", description: 'Filter by severity: CRITICAL, HIGH, MEDIUM, LOW' },
        since: { type: "STRING", description: 'ISO date string -- only CVEs published after this date' },
        limit: { type: "NUMBER", description: 'Max results (default 10, max 50)' },
      },
    },
  },
  {
    name: 'get_cve_detail',
    description: 'Get full details for a specific CVE including all CWEs, CVSS breakdown, EPSS score + percentile (First.org exploit-probability, 0..1), CAPEC attack patterns (via CWE overlap), affected applications, linked ATT&CK techniques (via CAPEC + CTID), OWASP Top 10 categories, GHSA alias, threat reports, CISA KEV status, and `osvAdvisories` — OS / distro / kernel advisories (Debian DSA, Ubuntu USN, Linux, Alpine, Android, Rocky, Alma, SUSE, OSS-Fuzz) that alias this CVE. The `epssScore` field is the probability a CVE will be exploited in the next 30 days; `epssPercentile` is its rank vs all scored CVEs. The `capecPatterns` array contains mapped attack patterns with severity/likelihood/abstraction. The `osvAdvisories` array carries distro/kernel advisory IDs with their ecosystem and CVSS — surface these to users asking "which distros are affected".',
    parameters: {
      type: "OBJECT",
      properties: {
        cve_id: { type: "STRING", description: 'CVE identifier, e.g. CVE-2024-3400' },
      },
      required: ['cve_id'],
    },
  },
  {
    name: 'get_technique_intelligence',
    description: 'Get intelligence for an ATT&CK or ATLAS technique: threat groups, Sigma rules, Atomic tests, D3FEND countermeasures, affected applications, detection strategies. For regulatory/compliance frameworks (NIS2, DORA, PCI DSS, ISO 27002, HIPAA, GDPR, NIST 800-53, CMMC, EU CRA, EU AI Act) referencing this technique, use get_technique_compliance instead — they are NOT returned by this tool.',
    parameters: {
      type: "OBJECT",
      properties: {
        attack_id: { type: "STRING", description: 'ATT&CK ID (e.g. T1059, T1190) or ATLAS ID (e.g. AML.T0051)' },
      },
      required: ['attack_id'],
    },
  },
  {
    name: 'get_technique_detail',
    description: 'Get detailed technique information: description, tactics, platforms, sub-techniques, procedures, mitigations, data sources, ATLAS cross-references, and CAPEC attack patterns mapped to this technique (via capec_mappings). The `capecPatterns` array contains CAPEC ID, name, severity, likelihood, and abstraction.',
    parameters: {
      type: "OBJECT",
      properties: {
        attack_id: { type: "STRING", description: 'ATT&CK or ATLAS technique ID' },
      },
      required: ['attack_id'],
    },
  },
  {
    name: 'get_group_profile',
    description: 'Get FULL threat group profile by ATT&CK ID -- returns ALL techniques, ALL software/malware, campaigns, targeted sectors, applications. Use when asked about a specific group. If you only have the name, call search_groups first to get the ID, then call this.',
    parameters: {
      type: "OBJECT",
      properties: {
        attack_id: { type: "STRING", description: 'Group ATT&CK ID, e.g. G0032 for Lazarus Group, G0016 for APT29' },
      },
      required: ['attack_id'],
    },
  },
  {
    name: 'search_groups',
    description: 'Search/list threat groups by name. Returns summary only (ID, name, technique count) -- NOT the full profile. Use to find a group ID, then call get_group_profile for details.',
    parameters: {
      type: "OBJECT",
      properties: {
        search: { type: "STRING", description: 'Search keyword (minimum 3 characters)' },
        sector: { type: "STRING", description: 'Filter by sector slug (e.g. financial, healthcare, government)' },
        domain: { type: "STRING", description: 'ATT&CK domain: enterprise-attack, ics-attack, mobile-attack, atlas-attack' },
        limit: { type: "NUMBER", description: 'Max results (default 10)' },
      },
    },
  },
  {
    name: 'get_application_security',
    description: 'Get security posture for a vendor/product: CVEs, CWE weakness profile, reachable techniques, associated threat groups.',
    parameters: {
      type: "OBJECT",
      properties: {
        vendor: { type: "STRING", description: 'Vendor name, e.g. microsoft, apache, litellm' },
        product: { type: "STRING", description: 'Product name, e.g. windows_server_2022, http_server, litellm' },
      },
      required: ['vendor', 'product'],
    },
  },
  {
    name: 'search_applications',
    description: 'Search applications by name. Returns vendor, product, CVE count.',
    parameters: {
      type: "OBJECT",
      properties: {
        search: { type: "STRING", description: 'Search keyword' },
        limit: { type: "NUMBER", description: 'Max results (default 10)' },
      },
    },
  },
  {
    name: 'get_sector_threats',
    description: 'Get threat landscape for an industry sector: groups, techniques, campaigns, vulnerable applications.',
    parameters: {
      type: "OBJECT",
      properties: {
        sector: { type: "STRING", description: 'Sector slug: financial, healthcare, government, energy, telecom, defense, technology, education, media, retail, transportation, manufacturing' },
      },
      required: ['sector'],
    },
  },
  {
    name: 'search_entities',
    description: 'Cross-domain search across all entity types: techniques, groups, software, campaigns, mitigations, data sources, applications. Minimum 3 characters.',
    parameters: {
      type: "OBJECT",
      properties: {
        q: { type: "STRING", description: 'Search query (minimum 3 characters)' },
      },
      required: ['q'],
    },
  },
  {
    name: 'get_dashboard_stats',
    description: 'Get knowledge base overview: entity counts, top groups, most targeted techniques, sector breakdown.',
    parameters: {
      type: "OBJECT",
      properties: {
        domain: { type: "STRING", description: 'Optional domain filter' },
        sector: { type: "STRING", description: 'Optional sector filter' },
      },
    },
  },
  {
    name: 'get_framework_mappings',
    description: 'Get compliance/framework mappings for a technique: NIST 800-53 controls, MITRE Engage activities, VERIS mappings, cloud controls (Azure/GCP).',
    parameters: {
      type: "OBJECT",
      properties: {
        attack_id: { type: "STRING", description: 'ATT&CK technique ID' },
      },
      required: ['attack_id'],
    },
  },
  {
    name: 'get_threat_reports',
    description: 'Get recent threat intelligence reports from AlienVault OTX, DFIR Report, Unit42, Microsoft Security, Talos. Reports are mapped to ATT&CK techniques.',
    parameters: {
      type: "OBJECT",
      properties: {
        limit: { type: "NUMBER", description: 'Max results (default 10)' },
      },
    },
  },
  // -- New tools --------------------------------------------------------------
  {
    name: 'get_software_detail',
    description: 'Get malware or tool profile: techniques it uses, groups that use it, campaigns, platforms. Covers 914 ATT&CK software entries.',
    parameters: {
      type: "OBJECT",
      properties: {
        attack_id: { type: "STRING", description: 'Software ATT&CK ID, e.g. S0154 for Cobalt Strike' },
      },
      required: ['attack_id'],
    },
  },
  {
    name: 'search_software',
    description: 'Search malware and tools by name. Returns software ID, name, type (malware/tool), and technique count.',
    parameters: {
      type: "OBJECT",
      properties: {
        search: { type: "STRING", description: 'Search keyword (minimum 3 characters)' },
        sector: { type: "STRING", description: 'Filter by sector slug' },
        limit: { type: "NUMBER", description: 'Max results (default 10)' },
      },
    },
  },
  {
    name: 'get_campaign_detail',
    description: 'Get campaign details: techniques used, software deployed, groups involved, timeline.',
    parameters: {
      type: "OBJECT",
      properties: {
        attack_id: { type: "STRING", description: 'Campaign ATT&CK ID, e.g. C0028' },
      },
      required: ['attack_id'],
    },
  },
  {
    name: 'search_campaigns',
    description: 'Search named campaigns. Returns campaign ID, name, dates, and linked groups.',
    parameters: {
      type: "OBJECT",
      properties: {
        search: { type: "STRING", description: 'Search keyword (minimum 3 characters)' },
        sector: { type: "STRING", description: 'Filter by sector slug' },
        limit: { type: "NUMBER", description: 'Max results (default 10)' },
      },
    },
  },
  {
    name: 'get_mitigation_detail',
    description: 'Get mitigation details: description, techniques it addresses, domain coverage.',
    parameters: {
      type: "OBJECT",
      properties: {
        attack_id: { type: "STRING", description: 'Mitigation ATT&CK ID, e.g. M1036' },
      },
      required: ['attack_id'],
    },
  },
  {
    name: 'search_mitigations',
    description: 'Search mitigations by name or description. Returns mitigation ID, name, and technique count.',
    parameters: {
      type: "OBJECT",
      properties: {
        search: { type: "STRING", description: 'Search keyword (minimum 3 characters)' },
        limit: { type: "NUMBER", description: 'Max results (default 10)' },
      },
    },
  },
  {
    name: 'search_iocs',
    description: 'Search Indicators of Compromise: IPs, domains, hashes, URLs, CVEs. Includes VirusTotal verdicts and malware families. Sources: OTX, ThreatFox, MalwareBazaar, CISA KEV.',
    parameters: {
      type: "OBJECT",
      properties: {
        q: { type: "STRING", description: 'Search query (IOC value, keyword)' },
        type: { type: "STRING", description: 'IOC type: ip, domain, url, hash, cve, email' },
        source: { type: "STRING", description: 'Source filter: otx, threatfox, malwarebazaar, cisa_kev' },
        malware: { type: "STRING", description: 'Filter by malware family name' },
        since: { type: "STRING", description: 'ISO date -- only IOCs seen after this date' },
        limit: { type: "NUMBER", description: 'Max results (default 20)' },
      },
    },
  },
  {
    name: 'search_sigma_rules',
    description: 'Search Sigma detection rules by keyword, technique, or severity level. 3,100+ rules from SigmaHQ.',
    parameters: {
      type: "OBJECT",
      properties: {
        q: { type: "STRING", description: 'Search keyword in title/description' },
        technique: { type: "STRING", description: 'Filter by ATT&CK technique ID, e.g. T1059' },
        level: { type: "STRING", description: 'Severity level: critical, high, medium, low, informational' },
        limit: { type: "NUMBER", description: 'Max results (default 20)' },
      },
    },
  },
  {
    name: 'search_atomic_tests',
    description: 'Search Atomic Red Team tests by keyword, technique, or platform. 1,770+ tests for adversary emulation.',
    parameters: {
      type: "OBJECT",
      properties: {
        q: { type: "STRING", description: 'Search keyword' },
        technique: { type: "STRING", description: 'Filter by ATT&CK technique ID' },
        platform: { type: "STRING", description: 'Platform filter: windows, linux, macos' },
        limit: { type: "NUMBER", description: 'Max results (default 20)' },
      },
    },
  },
  {
    name: 'get_external_actor',
    description: 'Get external threat actor profile from ETDA/ThaiCERT: country, motivation, state sponsor, suspected victims, MITRE group mapping.',
    parameters: {
      type: "OBJECT",
      properties: {
        name: { type: "STRING", description: 'Actor name, e.g. APT28, Lazarus Group' },
      },
      required: ['name'],
    },
  },
  {
    name: 'search_external_actors',
    description: 'Search 514 external threat actors by name, country, or category. Includes state sponsors, motivation, and MITRE ATT&CK group mappings.',
    parameters: {
      type: "OBJECT",
      properties: {
        search: { type: "STRING", description: 'Search keyword (minimum 2 characters)' },
        country: { type: "STRING", description: 'Country filter, e.g. Russia, China, Iran' },
        category: { type: "STRING", description: 'Category filter' },
        limit: { type: "NUMBER", description: 'Max results (default 20)' },
      },
    },
  },
  {
    name: 'get_tactic_detail',
    description: 'Get tactic details: description, all techniques under this tactic, domain.',
    parameters: {
      type: "OBJECT",
      properties: {
        attack_id: { type: "STRING", description: 'Tactic ATT&CK ID, e.g. TA0001 for Initial Access' },
      },
      required: ['attack_id'],
    },
  },
  {
    name: 'get_data_source_detail',
    description: 'Get data source details: description, data components, techniques it can detect.',
    parameters: {
      type: "OBJECT",
      properties: {
        attack_id: { type: "STRING", description: 'Data source ATT&CK ID, e.g. DS0009 for Process' },
      },
      required: ['attack_id'],
    },
  },
  {
    name: 'get_owasp_top10',
    description: 'Get OWASP Top 10 categories for Web (2021), ML (2023), and LLM (2025) with CWE counts, technique counts, ATLAS counts, and CVE counts.',
    parameters: {
      type: "OBJECT",
      properties: {
        framework: { type: "STRING", description: 'Filter by framework: web-2021, ml-2023, or llm-2025. Omit for all.' },
      },
    },
  },
  {
    name: 'get_owasp_category',
    description: 'Get details for a specific OWASP category: CWEs, ATT&CK techniques, ATLAS techniques, top CVEs, affected applications, and related categories across frameworks.',
    parameters: {
      type: "OBJECT",
      properties: {
        category_id: { type: "STRING", description: 'OWASP category ID: A01-A10 (Web), ML01-ML10, or LLM01-LLM10' },
      },
      required: ['category_id'],
    },
  },
  {
    name: 'get_ghsa_detail',
    description: 'Get full details for a GitHub Security Advisory: summary, description, CVSS v3/v4, CWEs, CAPEC attack patterns (via CWE overlap — `capecPatterns` array with ID/name/severity/likelihood/abstraction), affected open-source packages with vulnerable/fixed version ranges, linked ATT&CK techniques.',
    parameters: {
      type: "OBJECT",
      properties: {
        ghsa_id: { type: "STRING", description: 'GHSA identifier, e.g. GHSA-jfh8-c2jp-5v3q' },
      },
      required: ['ghsa_id'],
    },
  },
  {
    name: 'get_package_vulnerabilities',
    description: 'List vulnerabilities affecting a specific open-source package in an ecosystem (npm, pypi, go, maven, rubygems, nuget, composer, rust). Returns all GHSAs with vulnerable/fixed version ranges and linked ATT&CK techniques.',
    parameters: {
      type: "OBJECT",
      properties: {
        ecosystem: { type: "STRING", description: 'Package ecosystem: npm, pypi, go, maven, rubygems, nuget, composer, rust, erlang, pub, swift, actions' },
        package_name: { type: "STRING", description: 'Package name, e.g. log4js-node, django, @angular/core' },
      },
      required: ['ecosystem', 'package_name'],
    },
  },
  {
    name: 'search_ghsa',
    description: 'Search GitHub Security Advisories by keyword, severity, ecosystem, or publication date. Returns GHSA ID, CVE alias (if any), severity, summary, affected ecosystems, published date.',
    parameters: {
      type: "OBJECT",
      properties: {
        q: { type: "STRING", description: 'Search query (GHSA ID, CVE, summary, or description)' },
        severity: { type: "STRING", description: 'Filter by severity: CRITICAL, HIGH, MEDIUM, LOW' },
        ecosystem: { type: "STRING", description: 'Filter by ecosystem: npm, pypi, go, maven, rubygems, nuget, composer, rust' },
        since: { type: "STRING", description: 'ISO date string — only advisories published after this date' },
        has_cve: { type: "STRING", description: 'Filter by CVE alias presence: "true" (CVE-linked) or "false" (GHSA-only)' },
        limit: { type: "NUMBER", description: 'Max results (default 10, max 50)' },
      },
    },
  },
  {
    name: 'cve_to_packages',
    description: 'Given a CVE ID, return the open-source packages affected via its GitHub Security Advisory alias. Returns empty list if no GHSA is linked to the CVE.',
    parameters: {
      type: "OBJECT",
      properties: {
        cve_id: { type: "STRING", description: 'CVE identifier, e.g. CVE-2021-44228' },
      },
      required: ['cve_id'],
    },
  },
  {
    name: 'get_capec_detail',
    description: 'Get full detail for a MITRE CAPEC attack pattern: description, abstraction (Meta/Standard/Detailed), severity (Very Low..Very High), likelihood (Low/Medium/High), prerequisites, skills required, resources required, consequences, example instances, linked CWEs, mapped ATT&CK techniques, mitigations, and related patterns (ChildOf/ParentOf/CanPrecede/CanFollow).',
    parameters: {
      type: "OBJECT",
      properties: {
        capec_id: { type: "STRING", description: 'CAPEC identifier, e.g. CAPEC-66 for SQL Injection' },
      },
      required: ['capec_id'],
    },
  },
  {
    name: 'search_capec',
    description: 'Search/filter 615 CAPEC attack patterns by keyword, abstraction, severity, or likelihood. Returns CAPEC ID, name, abstraction, severity, likelihood, CWE refs, and counts of mapped ATT&CK techniques and mitigations.',
    parameters: {
      type: "OBJECT",
      properties: {
        q: { type: "STRING", description: 'Search keyword against CAPEC name/ID (minimum 2 characters)' },
        abstraction: { type: "STRING", description: 'Abstraction level: Meta, Standard, Detailed' },
        severity: { type: "STRING", description: 'Severity: Very Low, Low, Medium, High, Very High' },
        likelihood: { type: "STRING", description: 'Likelihood of attack: Low, Medium, High' },
        limit: { type: "NUMBER", description: 'Max results (default 20, max 50)' },
      },
    },
  },
  {
    name: 'search_advisories',
    description: 'Unified search across GHSA (OSS packages: npm/PyPI/Maven/Go/NuGet/RubyGems/Composer/crates.io/Pub/Hex) AND OSV (OS + distro + kernel: Linux kernel, Debian, Ubuntu, Alpine, Android, Red Hat, Rocky, Alma, SUSE, openSUSE, OSS-Fuzz, Bitnami, Chainguard, Wolfi, Hackage, CRAN, Julia). Each row carries a `source: GHSA|OSV` badge; the two sources are disjoint by ingest (no duplicate advisories). Filter by source, severity, ecosystem, date, or CVE-alias presence. Returns advisoryId, source, cveId, summary, severity, cvssScore, publishedAt, ecosystems, packageCount.',
    parameters: {
      type: "OBJECT",
      properties: {
        q: { type: "STRING", description: 'Keyword search over advisory ID, CVE ID, summary (min 3 chars)' },
        source: { type: "STRING", description: 'Restrict to one source: "GHSA" (OSS packages) or "OSV" (OS/distros). Omit for both.' },
        severity: { type: "STRING", description: 'Severity filter: CRITICAL, HIGH, MEDIUM, LOW' },
        ecosystem: { type: "STRING", description: 'Ecosystem filter — GHSA uses lowercase names (npm, pypi, go, maven, rubygems, nuget, composer, rust, hex, pub); OSV uses case-preserved names (Linux, Debian, Ubuntu, Alpine, Android, Rocky Linux, AlmaLinux, SUSE, openSUSE, Bitnami, OSS-Fuzz, etc.)' },
        since: { type: "STRING", description: 'ISO date — only advisories published after this date' },
        has_cve: { type: "STRING", description: 'Filter by CVE alias presence: "true" or "false"' },
        limit: { type: "NUMBER", description: 'Max results (default 50, max 100)' },
      },
    },
  },
  {
    name: 'get_osv_detail',
    description: 'Get full details for an OSV advisory by its native ID — distro / kernel / OS advisories from osv.dev (DSA-xxxx, USN-xxxx, LBSEC-xxxx, ALAS-xxxx, RLSA-xxxx, etc.). Returns summary, description, aliases (CVE/GHSA IDs), CVSS score + vector, and affected packages grouped by ecosystem with vulnerable version ranges. Covers only non-GHSA ecosystems (Linux, Debian, Ubuntu, Alpine, Android, Red Hat, Rocky, Alma, SUSE, OSS-Fuzz, Bitnami, etc.) — GHSA-covered ecosystems use get_ghsa_detail instead.',
    parameters: {
      type: "OBJECT",
      properties: {
        osv_id: { type: "STRING", description: 'OSV native identifier, e.g. DSA-5678-1, USN-6543-1, LBSEC-2024-0001' },
      },
      required: ['osv_id'],
    },
  },
  {
    name: 'list_compliance_frameworks',
    description: 'List compliance and regulatory frameworks bridged to MITRE ATT&CK via the Secure Controls Framework (SCF). Curated default set is 21 Tier 1+2 frameworks (NIS2, DORA, PCI DSS, NIST 800-53 r5, NIST CSF v2, ISO 27002, HIPAA, GDPR, CMMC 2, EU AI Act, EU CRA, OWASP Top 10, EU DORA, CIS Controls v8.1, NIST 800-171 r3, FedRAMP r5, NERC CIP, IEC 62443, UK Cyber Essentials, AU Essential Eight, NIST AI RMF). Returns framework_key (stable URL slug for /compliance/<key>), name, version, source_org, upstream_url, region, tier, license, scf_controls (count of SCF controls mapped to this framework), techniques_total (distinct ATT&CK techniques referenced), techniques_filtered (techniques referenced by ≥2 SCF controls — the depth-of-coverage metric). Use this to answer "what compliance frameworks does X cover?" or "which framework has the deepest ATT&CK coverage?".',
    parameters: {
      type: "OBJECT",
      properties: {
        include_all: { type: "BOOLEAN", description: 'When true returns Tier 3 long-tail (~250 frameworks); default returns curated 22.' },
      },
    },
  },
  {
    name: 'get_compliance_framework',
    description: 'Get full detail for a single compliance framework: metadata, all ATT&CK techniques it references (with the article/section ID that cites each), grouped by article/section. Also returns related frameworks ranked by technique overlap. Use this to answer "what techniques does NIS2 cover?" or "which DORA articles map to T1059?". Returns a 404 when the framework_key is unknown — never invent slugs; if uncertain, call list_compliance_frameworks first to confirm the slug.',
    parameters: {
      type: "OBJECT",
      properties: {
        framework_key: { type: "STRING", description: 'Stable URL slug — e.g. eu-nis2, eu-dora, pci-dss-4, nist-800-53-r5, hipaa-security-rule, gdpr, eu-cra, eu-ai-act, cmmc-2, owasp-top10-2025, soc-2-tsc, iso-27002-2022, fedramp-r5, nerc-cip-2024, iec-62443, uk-cyber-essentials, au-essential-8, nist-ai-rmf, cis-controls-8-1, nist-800-171-r3' },
      },
      required: ['framework_key'],
    },
  },
  {
    name: 'get_technique_compliance',
    description: 'Get the compliance-framework chip list for a single ATT&CK technique: which Tier 1+2 frameworks (NIS2, DORA, PCI DSS, ISO, HIPAA, ...) reference this technique, the SCF control count per framework, and the specific framework article/section IDs (ref_ids) that cite it. Use this to answer "if I mitigate T1059, which compliance regimes do I satisfy?". Returns empty `frameworks` array when no SCF mapping exists for the technique — treat that as authoritative "not covered", do NOT infer or hallucinate a mapping.',
    parameters: {
      type: "OBJECT",
      properties: {
        attack_id: { type: "STRING", description: 'ATT&CK technique ID, e.g. T1059, T1059.001, T1190' },
        include_all: { type: "BOOLEAN", description: 'Include Tier 3 long-tail frameworks (default false — Tier 1+2 only).' },
      },
      required: ['attack_id'],
    },
  },
];

// Dynamic system instruction -- injects current date so Gemini calculates relative dates correctly
function buildSystemInstruction(): string {
  const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
  return `You are the MITRE Explorer threat intelligence agent. You help security professionals, SOC analysts, and AI agents query the MITRE ATT&CK knowledge base, CVE vulnerabilities, and application security data.

IMPORTANT: Today's date is ${today}. Always use this date for relative time calculations (e.g. "last 7 days" means since ${new Date(Date.now() - 7 * 86400000).toISOString().split('T')[0]}). Never assume a different year.

Use the available tools to answer questions. Always call a tool before answering -- never guess or hallucinate data.

Tool selection rules:
- When asked about a SPECIFIC group (e.g. "Lazarus Group", "APT29"): use search_groups to find the ID, then get_group_profile for the full profile
- When asked about a SPECIFIC technique: use get_technique_detail for description + get_technique_intelligence for feeds
- When asked about a SPECIFIC software/malware: use search_software to find the ID, then get_software_detail
- When asked about a SPECIFIC CAPEC attack pattern (e.g. "CAPEC-66", "SQL Injection attack pattern"): use get_capec_detail; to list/filter patterns use search_capec
- When asked about a SPECIFIC OSV / distro / kernel advisory (DSA-*, USN-*, ALAS-*, RLSA-*, LBSEC-*, etc.): use get_osv_detail
- When asked about advisories broadly ("show me recent Debian advisories", "which Alpine CVEs this week", "OSS package vulnerabilities for npm"): use search_advisories with the ecosystem / source filter. This unifies GHSA (OSS packages) + OSV (OS/distros/kernels) into one list.
- For GHSA-specific advisory detail (e.g. "GHSA-jfh8-c2jp-5v3q"): use get_ghsa_detail. For Debian/Ubuntu/Alpine/kernel advisories: use get_osv_detail.
- "search_" tools return summaries/lists; "get_" tools return full profiles -- always prefer the full profile for specific entities
- For OWASP categories: use get_owasp_top10 (optionally filtered by framework: web-2021, ml-2023, llm-2025), then get_owasp_category for details
- OWASP links: [A01 Broken Access Control](https://mitre-explorer.org/frameworks/owasp/A01)
- For COMPLIANCE / regulatory questions (NIS2, DORA, PCI DSS, ISO 27002, HIPAA, GDPR, CMMC, FedRAMP, NIST 800-53, NIST CSF v2, EU CRA, EU AI Act, OWASP Top 10, etc.): use list_compliance_frameworks to discover, get_compliance_framework for a single framework's techniques and articles, get_technique_compliance to find which frameworks reference a given T-ID. These are bridged to ATT&CK via the Secure Controls Framework (SCF, CC BY 4.0). Curated default = 21 Tier 1+2 frameworks; pass include_all=true for the ~250 long-tail. Coverage is FINITE — if a framework or framework/technique pair returns no data, state explicitly that the SCF crosswalk does not cover it; never infer a mapping. Compliance link example: [EU NIS2](https://mitre-explorer.org/compliance/eu-nis2).
- You MUST generate a human-readable summary from the tool results -- never return empty or "No response generated"

When responding:
- Be concise and factual
- For EVERY CVE mentioned, always include: CVE ID, CVSS score, severity (CRITICAL/HIGH/MEDIUM/LOW), published date, and linked ATT&CK techniques if available
- If the CVE detail response includes epssScore and epssPercentile, surface them: "EPSS: 0.94 (97th percentile)" means 94% predicted exploitation in 30 days and ranked in top 3% of all scored CVEs. Omit cleanly when null.
- If the CVE / GHSA / technique detail response includes capecPatterns, list them by CAPEC ID with severity (e.g. "CAPEC-66 SQL Injection — High severity") and link to [CAPEC-66](https://mitre-explorer.org/cti/capec/CAPEC-66)
- If the CVE detail response includes an osvAdvisories array (distro/kernel advisories aliasing the CVE), surface them grouped by ecosystem with a short list per ecosystem. E.g. "Also affected: Debian ([DSA-5678-1](https://mitre-explorer.org/cti/osv/DSA-5678-1)), Ubuntu ([USN-6543-1](https://mitre-explorer.org/cti/osv/USN-6543-1)), Alpine, ..."
- Include clickable markdown links to MITRE Explorer for every entity mentioned:
  - CVEs: [CVE-2024-3400](https://mitre-explorer.org/cti/cves/CVE-2024-3400)
  - Techniques: [T1059](https://mitre-explorer.org/techniques/T1059)
  - Groups: [APT29](https://mitre-explorer.org/?entity=G0016&tab=actor)
  - Applications: [LiteLLM](https://mitre-explorer.org/?entity=litellm%2Flitellm&tab=application-map)
  - CAPEC patterns: [CAPEC-66 SQL Injection](https://mitre-explorer.org/cti/capec/CAPEC-66)
  - OSV advisories: [DSA-5678-1](https://mitre-explorer.org/cti/osv/DSA-5678-1)
  - Unified advisories list: [advisories for Debian](https://mitre-explorer.org/cti/advisories?source=OSV&ecosystem=Debian)
- Use tables for structured data when listing multiple items
- Always mention total result count (e.g. "Showing 10 of 47 results")
- Keep a consistent schema per entity type -- do not change column layout between responses
- Do not truncate CVE descriptions mid-sentence -- include the full description or summarize it cleanly
- When reporting CVEs, add this note at the end: "NVD typically adds CPE entries days after CVE publication -- recent CVEs may show empty until enriched."
- For each CVE with linked techniques, list the technique IDs (e.g. T1190, T1059) -- these are the bridge between a vulnerability and the actual attack behaviour it enables
- For each CVE, include the affected applications if available (the "applications" field in the response) -- this tells the user which products are impacted
- When showing date ranges in your response, always confirm the actual dates used (e.g. "CVEs published between 2026-03-22 and 2026-03-29")`;
}

// -- Input validation allowlists ----------------------------------------------

const IOC_TYPES = new Set(['ip', 'domain', 'url', 'hash', 'cve', 'email']);
const IOC_SOURCES = new Set(['otx', 'threatfox', 'malwarebazaar', 'cisa_kev']);
const SIGMA_LEVELS = new Set(['critical', 'high', 'medium', 'low', 'informational']);
const PLATFORMS = new Set(['windows', 'linux', 'macos']);

function clampLimit(val: unknown, def: number, max: number): string {
  return String(Math.min(Math.max(Number(val) || def, 1), max));
}

// -- Internal API caller ------------------------------------------------------

async function callInternalApi(path: string): Promise<Record<string, unknown>> {
  const url = `${BASE_URL}/api/v1${path}`;
  const resp = await fetch(url, {
    headers: { 'Accept': 'application/json' },
    signal: AbortSignal.timeout(8000),
  });
  if (!resp.ok) return { error: `API returned ${resp.status}`, path };
  return resp.json() as Promise<Record<string, unknown>>;
}

async function executeTool(name: string, args: Record<string, unknown>): Promise<Record<string, unknown>> {
  switch (name) {
    case 'search_cves': {
      const params = new URLSearchParams();
      if (args.q) params.set('q', sanitizeSearch(args.q));
      if (args.severity) {
        const sev = String(args.severity).toUpperCase();
        if (SEVERITY_VALUES.has(sev)) params.set('severity', sev);
      }
      if (args.since) {
        const d = new Date(String(args.since));
        if (!isNaN(d.getTime())) params.set('since', d.toISOString());
      }
      params.set('limit', clampLimit(args.limit, 10, 50));
      return callInternalApi(`/cves?${params}`);
    }
    case 'get_cve_detail': {
      const id = validateCveId(args.cve_id);
      if (!id) return { error: 'Invalid CVE ID format' };
      return callInternalApi(`/cves/${id}`);
    }
    case 'get_technique_intelligence': {
      const id = validateAttackId(args.attack_id);
      if (!id) return { error: 'Invalid ATT&CK ID format' };
      return callInternalApi(`/feed/intelligence/${id}`);
    }
    case 'get_technique_detail': {
      const id = validateAttackId(args.attack_id);
      if (!id) return { error: 'Invalid ATT&CK ID format' };
      return callInternalApi(`/techniques/${id}`);
    }
    case 'get_group_profile': {
      const id = validateAttackId(args.attack_id);
      if (!id) return { error: 'Invalid group ID format' };
      return callInternalApi(`/groups/${id}`);
    }
    case 'search_groups': {
      const s = sanitizeSearch(args.search);
      if (s.length > 0 && s.length < 3) return { error: 'Search query must be at least 3 characters' };
      const params = new URLSearchParams();
      if (s.length >= 3) params.set('search', s);
      const sec = validateSector(args.sector);
      if (sec) params.set('sector', sec);
      const dom = validateDomain(args.domain);
      if (dom) params.set('domain', dom);
      params.set('limit', clampLimit(args.limit, 10, 50));
      return callInternalApi(`/groups?${params}`);
    }
    case 'get_application_security': {
      const v = String(args.vendor ?? '').toLowerCase().replace(/[^a-z0-9_-]/g, '');
      const p = String(args.product ?? '').toLowerCase().replace(/[^a-z0-9_-]/g, '');
      if (!v || !p) return { error: 'Vendor and product are required' };
      return callInternalApi(`/applications/${v}/${p}`);
    }
    case 'search_applications': {
      const params = new URLSearchParams();
      if (args.search) params.set('search', sanitizeSearch(args.search));
      params.set('limit', clampLimit(args.limit, 10, 50));
      return callInternalApi(`/applications?${params}`);
    }
    case 'get_sector_threats': {
      const sec = validateSector(args.sector);
      if (!sec) return { error: 'Invalid sector slug' };
      return callInternalApi(`/sectors/${sec}/relationships`);
    }
    case 'search_entities': {
      const s = sanitizeSearch(args.q);
      if (s.length < 3) return { error: 'Search query must be at least 3 characters' };
      return callInternalApi(`/search?q=${encodeURIComponent(s)}`);
    }
    case 'get_dashboard_stats': {
      const params = new URLSearchParams();
      const dom = validateDomain(args.domain);
      if (dom) params.set('domain', dom);
      const sec = validateSector(args.sector);
      if (sec) params.set('sector', sec);
      return callInternalApi(`/dashboard?${params}`);
    }
    case 'get_framework_mappings': {
      const id = validateAttackId(args.attack_id);
      if (!id) return { error: 'Invalid ATT&CK ID format' };
      return callInternalApi(`/frameworks/technique/${id}`);
    }
    case 'get_threat_reports': {
      const params = new URLSearchParams();
      params.set('limit', clampLimit(args.limit, 10, 50));
      return callInternalApi(`/feed/reports?${params}`);
    }
    // -- New tools ------------------------------------------------------------
    case 'get_software_detail': {
      const id = validateAttackId(args.attack_id);
      if (!id) return { error: 'Invalid software ID format' };
      return callInternalApi(`/software/${id}`);
    }
    case 'search_software': {
      const s = sanitizeSearch(args.search);
      if (s.length > 0 && s.length < 3) return { error: 'Search query must be at least 3 characters' };
      const params = new URLSearchParams();
      if (s.length >= 3) params.set('search', s);
      const sec = validateSector(args.sector);
      if (sec) params.set('sector', sec);
      params.set('limit', clampLimit(args.limit, 10, 50));
      return callInternalApi(`/software?${params}`);
    }
    case 'get_campaign_detail': {
      const id = validateAttackId(args.attack_id);
      if (!id) return { error: 'Invalid campaign ID format' };
      return callInternalApi(`/campaigns/${id}`);
    }
    case 'search_campaigns': {
      const s = sanitizeSearch(args.search);
      if (s.length > 0 && s.length < 3) return { error: 'Search query must be at least 3 characters' };
      const params = new URLSearchParams();
      if (s.length >= 3) params.set('search', s);
      const sec = validateSector(args.sector);
      if (sec) params.set('sector', sec);
      params.set('limit', clampLimit(args.limit, 10, 50));
      return callInternalApi(`/campaigns?${params}`);
    }
    case 'get_mitigation_detail': {
      const id = validateAttackId(args.attack_id);
      if (!id) return { error: 'Invalid mitigation ID format' };
      return callInternalApi(`/mitigations/${id}`);
    }
    case 'search_mitigations': {
      const s = sanitizeSearch(args.search);
      if (s.length > 0 && s.length < 3) return { error: 'Search query must be at least 3 characters' };
      const params = new URLSearchParams();
      if (s.length >= 3) params.set('search', s);
      params.set('limit', clampLimit(args.limit, 10, 50));
      return callInternalApi(`/mitigations?${params}`);
    }
    case 'search_iocs': {
      const params = new URLSearchParams();
      if (args.q) params.set('q', sanitizeSearch(args.q));
      if (args.type) {
        const t = String(args.type).toLowerCase();
        if (IOC_TYPES.has(t)) params.set('type', t);
      }
      if (args.source) {
        const s = String(args.source).toLowerCase();
        if (IOC_SOURCES.has(s)) params.set('source', s);
      }
      if (args.malware) params.set('malware', sanitizeSearch(args.malware));
      if (args.since) {
        const d = new Date(String(args.since));
        if (!isNaN(d.getTime())) params.set('since', d.toISOString());
      }
      params.set('limit', clampLimit(args.limit, 20, 50));
      return callInternalApi(`/feed/iocs?${params}`);
    }
    case 'search_sigma_rules': {
      const params = new URLSearchParams();
      if (args.q) params.set('q', sanitizeSearch(args.q));
      if (args.technique) {
        const tid = validateAttackId(args.technique);
        if (tid) params.set('technique', tid);
      }
      if (args.level) {
        const lvl = String(args.level).toLowerCase();
        if (SIGMA_LEVELS.has(lvl)) params.set('level', lvl);
      }
      params.set('limit', clampLimit(args.limit, 20, 50));
      return callInternalApi(`/feed/sigma?${params}`);
    }
    case 'search_atomic_tests': {
      const params = new URLSearchParams();
      if (args.q) params.set('q', sanitizeSearch(args.q));
      if (args.technique) {
        const tid = validateAttackId(args.technique);
        if (tid) params.set('technique', tid);
      }
      if (args.platform) {
        const plat = String(args.platform).toLowerCase();
        if (PLATFORMS.has(plat)) params.set('platform', plat);
      }
      params.set('limit', clampLimit(args.limit, 20, 50));
      return callInternalApi(`/feed/atomic?${params}`);
    }
    case 'get_external_actor': {
      const n = sanitizeSearch(args.name);
      if (n.length < 2) return { error: 'Actor name must be at least 2 characters' };
      return callInternalApi(`/external-actors/${encodeURIComponent(n)}`);
    }
    case 'search_external_actors': {
      const s = sanitizeSearch(args.search);
      if (s.length > 0 && s.length < 2) return { error: 'Search query must be at least 2 characters' };
      const params = new URLSearchParams();
      if (s.length >= 2) params.set('search', s);
      if (args.country) params.set('country', sanitizeSearch(args.country));
      if (args.category) params.set('category', sanitizeSearch(args.category));
      params.set('limit', clampLimit(args.limit, 20, 50));
      return callInternalApi(`/external-actors?${params}`);
    }
    case 'get_tactic_detail': {
      const id = validateAttackId(args.attack_id);
      if (!id) return { error: 'Invalid tactic ID format' };
      return callInternalApi(`/tactics/${id}`);
    }
    case 'get_data_source_detail': {
      const id = validateAttackId(args.attack_id);
      if (!id) return { error: 'Invalid data source ID format' };
      return callInternalApi(`/data-sources/${id}`);
    }
    case 'get_owasp_top10': {
      const fw = args.framework ? String(args.framework) : '';
      const qs = fw ? `?framework=${encodeURIComponent(fw)}` : '';
      return callInternalApi(`/frameworks/owasp${qs}`);
    }
    case 'get_owasp_category': {
      const cat = String(args.category_id ?? '').toUpperCase();
      if (!/^(A|ML|LLM)\d{2}$/.test(cat)) return { error: 'Invalid category ID (A01-A10, ML01-ML10, LLM01-LLM10)' };
      return callInternalApi(`/frameworks/owasp/${cat}`);
    }
    case 'get_ghsa_detail': {
      // Preserve case of the random segments — GHSA stores them lowercase.
      const id = String(args.ghsa_id ?? '').replace(/^ghsa-/i, 'GHSA-');
      if (!/^GHSA(-[0-9a-z]{4}){3}$/.test(id)) return { error: 'Invalid GHSA ID format' };
      return callInternalApi(`/ghsa/${id}`);
    }
    case 'get_package_vulnerabilities': {
      const eco = String(args.ecosystem ?? '').toLowerCase();
      const name = String(args.package_name ?? '');
      if (!/^[a-z][a-z0-9-]{1,49}$/.test(eco)) return { error: 'Invalid ecosystem' };
      if (!name || name.length > 500) return { error: 'Invalid package name' };
      return callInternalApi(`/packages/${eco}/${encodeURIComponent(name)}`);
    }
    case 'search_ghsa': {
      const params = new URLSearchParams();
      if (args.q) params.set('q', sanitizeSearch(args.q));
      if (args.severity) {
        const sev = String(args.severity).toUpperCase();
        if (SEVERITY_VALUES.has(sev)) params.set('severity', sev);
      }
      if (args.ecosystem) {
        const eco = String(args.ecosystem).toLowerCase();
        if (/^[a-z][a-z0-9-]{1,49}$/.test(eco)) params.set('ecosystem', eco);
      }
      if (args.since) {
        const d = new Date(String(args.since));
        if (!isNaN(d.getTime())) params.set('since', d.toISOString());
      }
      if (args.has_cve === 'true' || args.has_cve === 'false') {
        params.set('has_cve', String(args.has_cve));
      }
      params.set('limit', clampLimit(args.limit, 10, 50));
      return callInternalApi(`/ghsa?${params}`);
    }
    case 'cve_to_packages': {
      const id = validateCveId(args.cve_id);
      if (!id) return { error: 'Invalid CVE ID format' };
      return callInternalApi(`/cves/${id}/packages`);
    }
    case 'get_capec_detail': {
      const id = validateCapecId(args.capec_id);
      if (!id) return { error: 'Invalid CAPEC ID format (expected CAPEC-N)' };
      return callInternalApi(`/capec/${id}`);
    }
    case 'search_capec': {
      const params = new URLSearchParams();
      const q = sanitizeSearch(args.q);
      if (q.length > 0 && q.length < 2) return { error: 'Search query must be at least 2 characters' };
      if (q.length >= 2) params.set('q', q);
      if (args.abstraction) {
        const a = String(args.abstraction);
        if (CAPEC_ABSTRACTION_VALUES.has(a)) params.set('abstraction', a);
      }
      if (args.severity) {
        const s = String(args.severity);
        if (CAPEC_SEVERITY_VALUES.has(s)) params.set('severity', s);
      }
      if (args.likelihood) {
        const l = String(args.likelihood);
        if (CAPEC_LIKELIHOOD_VALUES.has(l)) params.set('likelihood', l);
      }
      params.set('limit', clampLimit(args.limit, 20, 50));
      return callInternalApi(`/capec?${params}`);
    }
    case 'search_advisories': {
      const params = new URLSearchParams();
      const q = sanitizeSearch(args.q);
      if (q.length > 0 && q.length < 3) return { error: 'Search query must be at least 3 characters' };
      if (q.length >= 3) params.set('q', q);
      if (args.source) {
        const s = String(args.source).toUpperCase();
        if (ADVISORY_SOURCE_VALUES.has(s)) params.set('source', s);
      }
      if (args.severity) {
        const sev = String(args.severity).toUpperCase();
        if (SEVERITY_VALUES.has(sev)) params.set('severity', sev);
      }
      if (args.ecosystem) {
        const eco = validateAdvisoryEcosystem(args.ecosystem);
        if (eco) params.set('ecosystem', eco);
      }
      if (args.since) {
        const d = new Date(String(args.since));
        if (!isNaN(d.getTime())) params.set('since', d.toISOString());
      }
      if (args.has_cve === 'true' || args.has_cve === 'false') {
        params.set('has_cve', String(args.has_cve));
      }
      params.set('limit', clampLimit(args.limit, 50, 100));
      return callInternalApi(`/advisories?${params}`);
    }
    case 'get_osv_detail': {
      const id = validateOsvId(args.osv_id);
      if (!id) return { error: 'Invalid OSV ID format' };
      return callInternalApi(`/osv/${encodeURIComponent(id)}`);
    }
    case 'list_compliance_frameworks': {
      const params = new URLSearchParams();
      if (args.include_all === true || args.include_all === 'true') params.set('include_all', '1');
      return callInternalApi(`/compliance/frameworks?${params}`);
    }
    case 'get_compliance_framework': {
      const key = String(args.framework_key ?? '').trim().toLowerCase();
      if (!/^[a-z0-9][a-z0-9-]{1,80}$/.test(key)) return { error: 'Invalid framework_key format' };
      return callInternalApi(`/compliance/frameworks/${encodeURIComponent(key)}`);
    }
    case 'get_technique_compliance': {
      const id = validateAttackId(args.attack_id);
      if (!id) return { error: 'Invalid ATT&CK ID format' };
      const params = new URLSearchParams();
      if (args.include_all === true || args.include_all === 'true') params.set('include_all', '1');
      return callInternalApi(`/compliance/techniques/${encodeURIComponent(id)}?${params}`);
    }
    default:
      return { error: `Unknown tool: ${name}` };
  }
}

// -- Rate limiting ------------------------------------------------------------

/**
 * Static salt used to hash client IPs before they touch the database. The raw
 * IP is never persisted — only the salted SHA-256, which is sufficient for
 * rate-limit bucketing but pseudonymous under GDPR (Art. 4(5)).
 *
 * Set A2A_IP_SALT in the Vercel environment. In local dev, a fallback is used
 * with a loud warning; this is NOT GDPR-compliant for production, but lets
 * tests and local development work without extra setup.
 */
const IP_SALT = process.env.A2A_IP_SALT || (() => {
  console.warn('[a2a] A2A_IP_SALT is not set — using insecure fallback. Set the env var in production.');
  return 'dev-only-insecure-salt';
})();

function getRawClientIp(req: NextRequest): string {
  // Trust Vercel's infrastructure-set headers first. These are written by the
  // Vercel edge and cannot be spoofed by the user agent:
  //   - `x-vercel-forwarded-for` (preferred): real client IP
  //   - `x-real-ip` (legacy): also set by Vercel
  // DO NOT trust the user-supplied `x-forwarded-for`: an attacker can send
  // `X-Forwarded-For: <anything>` and rotate through "fresh" IPs to bypass
  // our 50-req/day quota.
  const vercelIp = req.headers.get('x-vercel-forwarded-for');
  if (vercelIp) return vercelIp.split(',')[0].trim();
  const realIp = req.headers.get('x-real-ip');
  if (realIp) return realIp.trim();
  // Fallback to last hop of x-forwarded-for — Vercel appends the real IP at
  // the end if they forward the header at all.
  const forwarded = req.headers.get('x-forwarded-for');
  if (forwarded) {
    const hops = forwarded.split(',').map((s) => s.trim()).filter(Boolean);
    return hops[hops.length - 1] ?? 'unknown';
  }
  return 'unknown';
}

/**
 * Returns a salted SHA-256 hex digest of the client IP. Stable across
 * requests (so rate-limit counts aggregate correctly) but irreversible
 * without the salt. The raw IP is never stored or logged by this module.
 */
function getClientIpHash(req: NextRequest): string {
  const raw = getRawClientIp(req);
  return createHash('sha256').update(IP_SALT).update(':').update(raw).digest('hex');
}

async function checkRateLimit(ipHash: string): Promise<{ allowed: boolean; remaining: number }> {
  const result = await query<{ count: string }>(
    `SELECT COUNT(*) FROM a2a_requests WHERE ip = $1 AND requested_at > NOW() - INTERVAL '24 hours'`,
    [ipHash],
  );
  const used = parseInt(result.rows[0].count, 10);
  return { allowed: used < DAILY_LIMIT, remaining: Math.max(0, DAILY_LIMIT - used) };
}

interface A2aLog {
  /** Salted SHA-256 hash of the client IP — never the raw address. */
  ipHash: string;
  userQuery: string | null;
  skillId: string | null;
  toolsCalled: string[];
  responseText: string | null;
  tokensUsed: number;
  latencyMs: number;
  error: string | null;
}

async function recordRequest(log: A2aLog): Promise<void> {
  try {
    await query(
      `INSERT INTO a2a_requests (ip, user_query, skill_id, tools_called, response_text, tokens_used, latency_ms, error)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [log.ipHash, log.userQuery, log.skillId, log.toolsCalled, log.responseText, log.tokensUsed, log.latencyMs, log.error],
    );
  } catch (e) {
    console.error('A2A log write failed:', e instanceof Error ? e.message : e);
  }
}

// -- JSON-RPC handler ---------------------------------------------------------

interface JsonRpcRequest {
  jsonrpc: '2.0';
  id: string | number;
  method: string;
  params?: Record<string, unknown>;
}

function jsonRpcError(id: string | number | null, code: number, message: string) {
  return { jsonrpc: '2.0', id, error: { code, message } };
}

export async function POST(req: NextRequest) {
  // Origin-restricted CORS closure — stays in scope for all response returns below.
  const withCors = (resp: NextResponse) => withCorsRestricted(resp, req);

  const body = (await req.json()) as JsonRpcRequest;
  if (!body?.jsonrpc || body.jsonrpc !== '2.0' || !body.method) {
    return withCors(NextResponse.json(
      jsonRpcError(body?.id ?? null, -32600, 'Invalid JSON-RPC request'),
      { status: 400 },
    ));
  }

  // Validate body.id
  const reqId = typeof body.id === 'string' ? body.id.slice(0, 100) : typeof body.id === 'number' ? body.id : null;
  if (reqId === null) {
    return withCors(NextResponse.json(
      jsonRpcError(null, -32600, 'Missing or invalid request id'),
      { status: 400 },
    ));
  }

  const ipHash = getClientIpHash(req);

  // Rate limit -- fail-closed on DB errors
  let remaining = DAILY_LIMIT;
  try {
    const rl = await checkRateLimit(ipHash);
    remaining = rl.remaining;
    if (!rl.allowed) {
      const resp = NextResponse.json(
        jsonRpcError(reqId, -32000, `Rate limit exceeded. ${DAILY_LIMIT} requests/day per IP.`),
        { status: 429 },
      );
      resp.headers.set('Retry-After', '86400');
      resp.headers.set('X-RateLimit-Limit', String(DAILY_LIMIT));
      resp.headers.set('X-RateLimit-Remaining', '0');
      return withCors(resp);
    }
  } catch {
    return withCors(NextResponse.json(
      jsonRpcError(reqId, -32603, 'Service temporarily unavailable'),
      { status: 503 },
    ));
  }

  // Accept both v1.0 (PascalCase) and v0.x (slash) method names
  if (body.method === 'SendMessage' || body.method === 'message/send') {
    const message = body.params?.message as { role?: string; parts?: Array<{ text?: string }> } | undefined;
    let userText = message?.parts?.[0]?.text;

    if (!userText) {
      return withCors(NextResponse.json(
        jsonRpcError(reqId, -32602, 'Missing message.parts[0].text'),
        { status: 400 },
      ));
    }

    if (userText.length > MAX_INPUT_LENGTH) {
      userText = userText.slice(0, MAX_INPUT_LENGTH);
    }

    const startMs = Date.now();

    try {
      const apiKey = process.env.GEMINI_API_KEY;
      if (!apiKey) {
        return withCors(NextResponse.json(
          jsonRpcError(reqId, -32603, 'AI service unavailable'),
          { status: 500 },
        ));
      }

      const ai = new GoogleGenAI({ apiKey });
      const toolsConfig = [{ functionDeclarations: TOOL_DECLARATIONS as any }];
      // Hoist once per request — the function is pure modulo today's date,
      // which doesn't change across the agentic loop (max 4 calls / request).
      const systemInstruction = buildSystemInstruction();

      // Initial Gemini call with function declarations
      const response = await ai.models.generateContent({
        model: MODEL,
        contents: [{ role: 'user', parts: [{ text: userText }] }],
        config: { systemInstruction, tools: toolsConfig },
      });

      const candidate = response.candidates?.[0];
      const parts = candidate?.content?.parts ?? [];
      const functionCalls = parts.filter((p) => p.functionCall);

      let finalText = '';
      const skillsUsed: string[] = [];
      let totalTokens = response.usageMetadata?.totalTokenCount ?? 0;
      let rawToolData: Record<string, unknown>[] = [];

      if (functionCalls.length > 0) {
        // Execute tool calls in parallel (cap at 5)
        const capped = functionCalls.slice(0, 5);
        const settled = await Promise.allSettled(
          capped.map(async (fc) => {
            const toolName = fc.functionCall!.name!;
            const toolArgs = (fc.functionCall!.args ?? {}) as Record<string, unknown>;
            skillsUsed.push(toolName);
            const result = await executeTool(toolName, toolArgs);
            return { name: toolName, id: fc.functionCall!.id, args: toolArgs, result };
          }),
        );
        const toolResults = settled.map((s, i) =>
          s.status === 'fulfilled'
            ? s.value
            : { name: capped[i].functionCall!.name!, id: capped[i].functionCall!.id, args: {}, result: { error: `Tool failed: ${(s.reason as Error)?.message ?? 'unknown'}` } },
        );

        // Capture full raw API results for structured artifact
        rawToolData = toolResults.map((tr) => ({ tool: tr.name, args: tr.args, data: tr.result }));

        // Trim tool results for Gemini context -- full data stays in rawToolData for the artifact
        const trimmedForGemini = toolResults.map((tr) => {
          const json = JSON.stringify(tr.result);
          if (json.length <= 4000) return tr;
          // Truncate: keep top-level scalars, trim arrays to first 5 items
          const trimmed: Record<string, unknown> = {};
          for (const [k, v] of Object.entries(tr.result)) {
            if (Array.isArray(v)) {
              trimmed[k] = v.slice(0, 5);
              if (v.length > 5) trimmed[`${k}_total`] = v.length;
            } else {
              trimmed[k] = v;
            }
          }
          return { ...tr, result: trimmed };
        });

        // Agentic loop: Gemini may chain tools (search -> get_profile). Max 3 rounds.
        let conversationParts: Array<{ role: string; parts: unknown[] }> = [
          { role: 'user', parts: [{ text: userText }] },
          { role: 'model', parts },
          { role: 'user', parts: trimmedForGemini.map((tr) => ({
            functionResponse: { name: tr.name, id: tr.id, response: { output: tr.result } },
          })) },
        ];

        for (let round = 0; round < 3; round++) {
          const followUp = await ai.models.generateContent({
            model: MODEL,
            contents: conversationParts as any,
            config: { systemInstruction, tools: toolsConfig },
          });

          totalTokens += followUp.usageMetadata?.totalTokenCount ?? 0;
          const followParts = followUp.candidates?.[0]?.content?.parts ?? [];
          const moreCalls = followParts.filter((p) => p.functionCall);

          if (moreCalls.length === 0) {
            // No more tool calls -- extract text
            const followText = followParts.find((p) => p.text)?.text;
            finalText = followText ?? followUp.text ?? '';
            break;
          }

          // Execute next round of tool calls
          const nextCapped = moreCalls.slice(0, 3);
          const nextSettled = await Promise.allSettled(
            nextCapped.map(async (fc) => {
              const toolName = fc.functionCall!.name!;
              const toolArgs = (fc.functionCall!.args ?? {}) as Record<string, unknown>;
              skillsUsed.push(toolName);
              const result = await executeTool(toolName, toolArgs);
              return { name: toolName, id: fc.functionCall!.id, args: toolArgs, result };
            }),
          );
          const nextResults = nextSettled.map((s, i) =>
            s.status === 'fulfilled'
              ? s.value
              : { name: nextCapped[i].functionCall!.name!, id: nextCapped[i].functionCall!.id, args: {}, result: { error: `Tool failed: ${(s.reason as Error)?.message ?? 'unknown'}` } },
          );

          // Add to raw data + trim for Gemini
          rawToolData.push(...nextResults.map((tr) => ({ tool: tr.name, args: tr.args, data: tr.result })));
          const nextTrimmed = nextResults.map((tr) => {
            const json = JSON.stringify(tr.result);
            if (json.length <= 4000) return tr;
            const trimmed: Record<string, unknown> = {};
            for (const [k, v] of Object.entries(tr.result)) {
              if (Array.isArray(v)) {
                trimmed[k] = v.slice(0, 5);
                if (v.length > 5) trimmed[`${k}_total`] = v.length;
              } else { trimmed[k] = v; }
            }
            return { ...tr, result: trimmed };
          });

          conversationParts = [
            ...conversationParts,
            { role: 'model', parts: followParts },
            { role: 'user', parts: nextTrimmed.map((tr) => ({
              functionResponse: { name: tr.name, id: tr.id, response: { output: tr.result } },
            })) },
          ];
        }

        // Fallback if Gemini still produced no text
        if (!finalText) {
          finalText = `Tools called: ${skillsUsed.join(', ')}. See the structured_data artifact for full results.`;
        }
      } else {
        finalText = response.text ?? 'No response generated.';
      }

      await recordRequest({
        ipHash, userQuery: userText, skillId: skillsUsed[0] ?? null,
        toolsCalled: skillsUsed, responseText: finalText.slice(0, 4000),
        tokensUsed: totalTokens, latencyMs: Date.now() - startMs, error: null,
      });

      const taskId = `task-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
      const now = new Date().toISOString();

      // Build artifacts: always include summary; add structured data when tools were called
      const artifacts: Array<Record<string, unknown>> = [
        {
          artifactId: `${taskId}-summary`,
          name: 'summary',
          description: 'Human-readable response with markdown links',
          parts: [{ text: finalText }],
        },
      ];
      if (rawToolData.length > 0) {
        artifacts.push({
          artifactId: `${taskId}-data`,
          name: 'structured_data',
          description: 'Raw API results as structured JSON for downstream parsing',
          parts: [{ text: JSON.stringify(rawToolData) }],
        });
      }

      const resp = NextResponse.json({
        jsonrpc: '2.0',
        id: reqId,
        result: {
          id: taskId,
          contextId: taskId,
          status: {
            state: 'completed',
            message: { role: 'agent', parts: [{ text: finalText }] },
            timestamp: now,
          },
          history: [
            { role: 'user', parts: [{ text: userText }] },
            { role: 'agent', parts: [{ text: finalText }] },
          ],
          artifacts,
          metadata: { tokensUsed: totalTokens, toolsCalled: skillsUsed },
          createdAt: now,
          updatedAt: now,
        },
      });
      resp.headers.set('X-RateLimit-Limit', String(DAILY_LIMIT));
      resp.headers.set('X-RateLimit-Remaining', String(remaining));
      return withCors(resp);
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err);
      console.error('A2A error:', errMsg);
      await recordRequest({
        ipHash, userQuery: userText, skillId: null, toolsCalled: [],
        responseText: null, tokensUsed: 0, latencyMs: Date.now() - startMs, error: errMsg.slice(0, 1000),
      });
      return withCors(NextResponse.json(
        jsonRpcError(reqId, -32603, 'Internal error processing request'),
        { status: 500 },
      ));
    }
  } else {
    return withCors(NextResponse.json(
      jsonRpcError(reqId, -32601, 'Method not supported. Use SendMessage'),
      { status: 400 },
    ));
  }
}
