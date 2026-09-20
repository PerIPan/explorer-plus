/**
 * The tool catalogue this knowledge base exposes to agents.
 *
 * Shared, not A2A-specific: both the A2A endpoint (app/api/a2a/route.ts, which
 * hands these to Gemini as function declarations) and the MCP endpoint
 * (app/api/mcp/route.ts, which converts them to JSON Schema) read this one
 * array. Keeping a single copy is deliberate -- two hand-maintained copies of
 * the same catalogue drift, and this repo has already been bitten by exactly
 * that (a CI pin at mitreattack-python==4.0.0 against a manifest saying 5.4.3).
 *
 * The schema dialect here is Gemini's: UPPERCASE type names ("OBJECT",
 * "STRING"). MCP needs lowercase JSON Schema, so the MCP route converts on the
 * way out rather than this file changing dialect and breaking A2A.
 *
 * Descriptions are deliberately long and cross-referential ("use X instead
 * for Y") -- that text is the only thing steering a model's tool choice.
 */

/** One entry in the catalogue, in Gemini function-declaration shape. */
export interface ToolDeclaration {
  name: string;
  description: string;
  parameters?: {
    type: string;
    properties?: Record<string, unknown>;
    required?: string[];
  };
}

// -- Gemini function declarations for our API --------------------------------

export const TOOL_DECLARATIONS: ToolDeclaration[] = [
  {
    name: 'search_cves',
    description: 'Search CVE vulnerabilities by keyword, severity, or date range. Returns CVE ID, CVSS score, severity, description, linked ATT&CK technique IDs, and affected applications. Use `app` to scope to a vendor/product and `version` (substring/text match, requires `app`) to a product version. Use get_cve_detail for EPSS exploit-probability score and CAPEC attack patterns.',
    parameters: {
      type: "OBJECT",
      properties: {
        q: { type: "STRING", description: 'Search query (CVE ID, keyword, CWE)' },
        severity: { type: "STRING", enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], description: 'Filter by severity' },
        since: { type: "STRING", description: 'ISO date string -- only CVEs published after this date' },
        app: { type: "STRING", description: 'Filter to CVEs affecting a vendor/product (substring match), e.g. nginx, apache' },
        version: { type: "STRING", description: 'Filter to a product version (substring/text match, e.g. 1.20.1). REQUIRES `app`. Surfaces CVEs whose affected version range MENTIONS this string — NOT a "this version is vulnerable" verdict; say so.' },
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
        version: { type: "STRING", description: 'Optional. Narrows the `affectedApps` list to entries whose version range (substring/text) mentions this value, e.g. 1.20. Surfaces matches — NOT a "this version is vulnerable" verdict; say so.' },
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
        domain: { type: "STRING", enum: ['enterprise-attack', 'ics-attack', 'mobile-attack', 'atlas-attack'], description: 'ATT&CK domain' },
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
        version: { type: "STRING", description: 'Optional. Narrows the returned CVE list to entries whose affected version range (substring/text) mentions this value, e.g. 1.20. Surfaces matches — NOT a "this version is vulnerable" verdict; say so.' },
      },
      required: ['vendor', 'product'],
    },
  },
  {
    name: 'search_applications',
    description: 'Search applications by name. Returns vendor, product, CVE count. Pass `version` (requires `search`) to keep only products that have an advisory mentioning that version.',
    parameters: {
      type: "OBJECT",
      properties: {
        search: { type: "STRING", description: 'Search keyword' },
        version: { type: "STRING", description: 'Optional product version (substring/text match, e.g. 1.20). REQUIRES `search`. Surfaces matches — NOT a "this version is vulnerable" verdict; say so.' },
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
    description: 'Cross-domain search returning techniques, groups, software, campaigns, mitigations, data sources, OWASP categories and NIST CSF subcategories. It does NOT search applications, advisories, CAPEC, Sigma, Atomic tests, external actors or ICS assets — an empty result here says nothing about those, so use search_applications, search_advisories, search_capec, search_sigma_rules, search_atomic_tests, search_external_actors or search_assets for them. Minimum 3 characters. Use ONLY when the entity type is unknown or ambiguous — when you know the type, the dedicated search tool returns richer results.',
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
        domain: { type: "STRING", enum: ['enterprise-attack', 'ics-attack', 'mobile-attack', 'atlas-attack'], description: 'Optional ATT&CK domain filter' },
        sector: { type: "STRING", description: 'Optional sector filter' },
      },
    },
  },
  {
    name: 'get_framework_mappings',
    description: 'Get direct per-technique framework mappings: NIST 800-53 controls, MITRE Engage activities, VERIS categories, AWS/Azure/GCP cloud controls. Use THIS tool for 800-53/Engage/VERIS/cloud questions. For regulatory frameworks (NIS2, DORA, PCI DSS, ISO 27002, HIPAA, GDPR, CMMC, ...) use get_technique_compliance instead — those come from the SCF crosswalk, not this tool.',
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
    description: 'Get the latest N threat intelligence reports from AlienVault OTX, DFIR Report, Unit42, Microsoft Security, Talos. Returns most-recent only — NOT filterable by technique, keyword, or actor. For technique-specific report links use get_technique_intelligence; for group context use get_group_profile.',
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
        type: { type: "STRING", enum: ['ip', 'domain', 'url', 'hash', 'cve', 'email'], description: 'IOC type' },
        source: { type: "STRING", enum: ['otx', 'threatfox', 'malwarebazaar', 'cisa_kev'], description: 'Source filter' },
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
        level: { type: "STRING", enum: ['critical', 'high', 'medium', 'low', 'informational'], description: 'Severity level' },
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
        platform: { type: "STRING", enum: ['windows', 'linux', 'macos'], description: 'Platform filter' },
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
        version: { type: "STRING", description: 'Optional. Narrows the affected-packages list to entries whose vulnerable/fixed range (substring/text) mentions this value, e.g. 14.10. Surfaces matches — NOT a "this version is vulnerable" verdict; say so.' },
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
        version: { type: "STRING", description: 'Optional. Narrows the advisory list to entries whose vulnerable/fixed range (substring/text) mentions this value, e.g. 14.10. Surfaces matches — NOT a "this version is vulnerable" verdict; say so.' },
      },
      required: ['ecosystem', 'package_name'],
    },
  },
  {
    name: 'search_ghsa',
    description: 'Search GitHub Security Advisories ONLY (OSS packages: npm/PyPI/Maven/Go/etc.) by keyword, severity, ecosystem, or publication date. Returns GHSA ID, CVE alias (if any), severity, summary, affected ecosystems, published date. For OS/distro/kernel advisories or a unified GHSA+OSV view, use search_advisories instead. To filter by affected package VERSION, use get_package_vulnerabilities (ecosystem+package_name+version) or get_ghsa_detail (ghsa_id+version) — version is not a list-level filter here.',
    parameters: {
      type: "OBJECT",
      properties: {
        q: { type: "STRING", description: 'Search query (GHSA ID, CVE, summary, or description)' },
        severity: { type: "STRING", enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], description: 'Filter by severity' },
        ecosystem: { type: "STRING", description: 'Filter by ecosystem: npm, pypi, go, maven, rubygems, nuget, composer, rust' },
        since: { type: "STRING", description: 'ISO date string — only advisories published after this date' },
        has_cve: { type: "STRING", description: 'Filter by CVE alias presence: "true" (CVE-linked) or "false" (GHSA-only)' },
        limit: { type: "NUMBER", description: 'Max results (default 10, max 50)' },
      },
    },
  },
  {
    name: 'get_cve_packages',
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
        abstraction: { type: "STRING", enum: ['Meta', 'Standard', 'Detailed'], description: 'Abstraction level' },
        severity: { type: "STRING", enum: ['Very Low', 'Low', 'Medium', 'High', 'Very High'], description: 'Severity' },
        likelihood: { type: "STRING", enum: ['Low', 'Medium', 'High'], description: 'Likelihood of attack' },
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
        source: { type: "STRING", enum: ['GHSA', 'OSV'], description: 'Restrict to one source: GHSA (OSS packages) or OSV (OS/distros). Omit for both.' },
        severity: { type: "STRING", enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], description: 'Severity filter' },
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
        include_all: { type: "BOOLEAN", description: 'When true returns Tier 3 long-tail (~250 frameworks); default returns the curated 21.' },
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
  {
    name: 'search_assets',
    description: 'Search the ATT&CK for ICS asset catalogue -- the operational-technology equipment MITRE names: PLCs, RTUs, safety controllers (SIS), historians, HMIs, engineering workstations, jump hosts, field I/O and the network kit between them. Filter by Purdue level, Purdue zone, industrial sector, or whether the asset sits on the IT/OT boundary. Returns ATT&CK ID (A0001-A0018), the Purdue levels each asset spans, and how many ICS techniques target it. Use get_asset_detail for one asset\'s full technique list, and get_purdue_model for the level definitions and the flow rules between levels. IMPORTANT: the asset itself (name, sectors, techniques) is MITRE-published, but every Purdue field returned here -- primaryLevel, zone, spansLevels, isBoundary and rationale -- is CURATED from NIST SP 800-82r3 and ISA-95, not published by MITRE. Attribute it that way; do not say \'per MITRE ATT&CK, this asset sits at Level 3\'. NOTE: MITRE publishes an asset catalogue for the ICS domain ONLY -- there is no enterprise, mobile or ATLAS equivalent, so an empty result for a non-ICS question is expected rather than missing data.',
    parameters: {
      type: "OBJECT",
      properties: {
        search: { type: "STRING", description: 'Name or ATT&CK ID substring, e.g. "historian", "PLC", "A0001". Minimum 2 characters or it is ignored.' },
        level: { type: "STRING", enum: ['l0', 'l1', 'l2', 'l3', 'l3_5', 'l4', 'l5'], description: 'Purdue level the asset is PRESENT at, not merely primary at -- a historian primarily at L3 but replicated into the DMZ matches both l3 and l3_5. l3_5 is the industrial DMZ.' },
        zone: { type: "STRING", enum: ['ot', 'dmz', 'it'], description: 'Purdue zone. ot = levels 0-3 (plant floor, where a breach moves physical things), dmz = level 3.5, it = levels 4-5 (corporate network).' },
        sector: { type: "STRING", description: 'Industrial sector the asset is used in, e.g. electric, manufacturing, water.' },
        boundary: { type: "BOOLEAN", description: 'True returns only assets present in the industrial DMZ (L3.5) -- the IT/OT crossing points an attacker pivots through. Six of the eighteen assets qualify.' },
        limit: { type: "NUMBER", description: 'Max results (default 50, max 200)' },
      },
    },
  },
  {
    name: 'get_asset_detail',
    description: 'Get one ATT&CK for ICS asset by ID (A0001-A0018): description, industrial sectors, platforms, related asset names, every ICS technique that targets it, and its Purdue placement -- primary level, all levels it spans, whether it is an IT/OT boundary asset, and the curated rationale for that placement. Use search_assets to find an asset ID first. Purdue placement is curated from NIST SP 800-82r3 and ISA-95, NOT published by MITRE -- say so when citing it.',
    parameters: {
      type: "OBJECT",
      properties: {
        asset_id: { type: "STRING", description: 'ICS asset ID, e.g. A0001 (Engineering Workstation), A0013 (Field I/O). Range is A0001-A0018.' },
      },
      required: ['asset_id'],
    },
  },
  {
    name: 'get_purdue_model',
    description: 'Get the Purdue model (ISA-95 / PERA) as data: the seven levels (L0 Physical through L5 Enterprise, including L3.5 the industrial DMZ) with zone, description and per-level asset and technique counts; every ICS asset placed on those levels; and the full 42-pair flow matrix saying which levels may communicate. In the flow matrix, directAllowed means the two levels are topologically adjacent -- it does NOT mean either side may initiate a session. Always read the accompanying `note`, which carries the directionality constraint: l3_5 -> l3 is directAllowed yet the note says the OT side initiates and a DMZ host must not open sessions inward. A pair carrying brokerLevel is reachable ONLY by terminating a session at that level first -- never read a brokered pair as adjacency. Use this to answer "what may talk to what", to reason about lateral movement across the IT/OT boundary, or to explain why an ICS technique needs a pivot. Level placement is curated from NIST SP 800-82r3 and ISA-95, not MITRE-published; technique counts are ICS-domain only, so L4/L5 carry no assets by design.',
    parameters: {
      type: "OBJECT",
      properties: {},
    },
  },
];
