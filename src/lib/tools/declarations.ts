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
    description: 'CVE summary rows by keyword, severity, date or product: CVSS, EPSS, CWE, linked ATT&CK IDs and affected apps, ordered newest first, not worst first. get_cve_detail has the full record. version matches text in an affected range, not a verdict that the version is vulnerable; say so.',
    parameters: {
      type: "OBJECT",
      properties: {
        q: { type: "STRING", description: 'Search query (CVE ID, keyword, CWE)' },
        severity: { type: "STRING", enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], description: 'Filter by severity' },
        since: { type: "STRING", description: 'ISO date string -- only CVEs published after this date' },
        app: { type: "STRING", description: 'Filter to CVEs affecting a vendor/product (substring match), e.g. nginx, apache' },
        version: { type: "STRING", description: 'Filter to a product version (substring/text match, e.g. 1.20.1). REQUIRES `app`. Surfaces CVEs whose affected version range MENTIONS this string — NOT a "this version is vulnerable" verdict; say so.' },
        limit: { type: "NUMBER", description: 'Max results (default 10, max 50)' },
        page: { type: "NUMBER", description: 'Page number, default 1. See pagination.total in the response.' },
      },
    },
  },
  {
    name: 'get_cve_detail',
    description: 'Full record for one CVE: CWEs, CVSS, EPSS, affected apps, OWASP categories, KEV status, GHSA alias, and osvAdvisories -- the distro and kernel advisories aliasing it, which answer which distros are affected. CAPEC patterns and ATT&CK techniques are inferred from shared CWEs, not published per-CVE; attribute them that way. version matches text in an affected range, not a verdict that the version is vulnerable; say so. Find a CVE ID with search_cves.',
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
    description: 'Detection and threat-intel layer for an ATT&CK or ATLAS technique: Sigma rules, Atomic Red Team tests, D3FEND countermeasures, detection strategies, plus top-N samples of threat reports, linked CVEs, IOCs and affected apps. Groups, mitigations and sub-techniques are in get_technique_detail; regulatory frameworks are not returned here -- call get_technique_compliance.',
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
    description: 'The technique record for an ATT&CK or ATLAS ID: description, tactics, platforms, sub-techniques, plus linked groups, software, campaigns, mitigations, data components, CAPEC patterns and ICS assets whose Purdue fields are curated from NIST SP 800-82r3 / ISA-95, not MITRE-published. Detection content is not returned here -- call get_technique_intelligence; regulatory frameworks, get_technique_compliance.',
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
    description: 'Full threat group profile: every technique, software and campaign, plus targeted sectors and a capped list of affected applications. If you have only a name, call search_groups for the ID first. For country, motivation and state sponsor instead, use get_external_actor.',
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
    description: 'Threat group summaries matching a name or description search, filterable by sector and domain -- no technique counts. Use get_group_profile for the full record.',
    parameters: {
      type: "OBJECT",
      properties: {
        search: { type: "STRING", description: 'Search keyword (minimum 3 characters)' },
        sector: { type: "STRING", enum: ['defense', 'education', 'energy', 'financial', 'government', 'healthcare', 'manufacturing', 'media', 'retail', 'technology', 'telecommunications', 'transportation'], description: 'Filter to groups targeting this sector.' },
        domain: { type: "STRING", enum: ['enterprise-attack', 'ics-attack', 'mobile-attack', 'atlas-attack'], description: 'ATT&CK domain' },
        limit: { type: "NUMBER", description: 'Max results (default 10)' },
        page: { type: "NUMBER", description: 'Page number, default 1. See pagination.total in the response.' },
      },
    },
  },
  {
    name: 'get_application_security',
    description: 'Security posture for one vendor and product: CVEs, CWE profile, reachable ATT&CK techniques and threat groups; search_applications finds the exact vendor and product pair. version narrows the CVE list by text in an affected range, not a verdict that the version is vulnerable; say so.',
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
    description: 'Application summary rows by name: vendor, product, CVE count; get_application_security has the full posture. version (requires search) keeps only products with an advisory whose range text mentions it -- not a verdict that the version is vulnerable; say so.',
    parameters: {
      type: "OBJECT",
      properties: {
        search: { type: "STRING", description: 'Search keyword' },
        version: { type: "STRING", description: 'Optional product version (substring/text match, e.g. 1.20). REQUIRES `search`. Surfaces matches — NOT a "this version is vulnerable" verdict; say so.' },
        limit: { type: "NUMBER", description: 'Max results (default 10)' },
        page: { type: "NUMBER", description: 'Page number, default 1. See pagination.total in the response.' },
      },
    },
  },
  {
    name: 'get_sector_threats',
    description: 'Threat landscape for one industry sector: the groups targeting it plus their campaigns, software, top techniques and vulnerable applications. The cves field is a 4-row recent sample, not the full sector CVE set.',
    parameters: {
      type: "OBJECT",
      properties: {
        sector: { type: "STRING", enum: ['defense', 'education', 'energy', 'financial', 'government', 'healthcare', 'manufacturing', 'media', 'retail', 'technology', 'telecommunications', 'transportation'], description: 'Sector to profile.' },
      },
      required: ['sector'],
    },
  },
  {
    name: 'search_entities',
    description: 'Cross-domain keyword search over ATT&CK techniques, groups, software, campaigns, mitigations and data sources plus OWASP categories and NIST CSF subcategories -- summaries only, up to 20 rows per type. Nothing else is searched, so an empty result says nothing about applications, advisories, CAPEC, Sigma, Atomic tests, external actors or ICS assets; use their own search_ tools. Prefer a dedicated search_ tool whenever the entity type is known.',
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
    description: 'ATT&CK corpus overview: entity counts, top groups, most-targeted techniques, sector breakdown and the ingested ATT&CK version. ATT&CK entities only -- no CVE, advisory or CAPEC totals.',
    parameters: {
      type: "OBJECT",
      properties: {
        domain: { type: "STRING", enum: ['enterprise-attack', 'ics-attack', 'mobile-attack', 'atlas-attack'], description: 'Optional ATT&CK domain filter' },
        sector: { type: "STRING", enum: ['defense', 'education', 'energy', 'financial', 'government', 'healthcare', 'manufacturing', 'media', 'retail', 'technology', 'telecommunications', 'transportation'], description: 'Optional: scope the stats to one sector.' },
      },
    },
  },
  {
    name: 'get_framework_mappings',
    description: 'Direct per-technique control mappings for one ATT&CK technique: NIST 800-53, NIST CSF v2 subcategories, MITRE Engage, VERIS, AWS/Azure/GCP cloud controls and OWASP categories. For regulatory regimes (NIS2, DORA, PCI DSS, ISO 27002, HIPAA, GDPR, CMMC, ...) use get_technique_compliance instead -- those come from the SCF crosswalk, not from here.',
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
    description: 'The most recently published threat-intelligence reports, newest first; no keyword, technique, actor or source filter exists here. For reports on one technique use get_technique_intelligence, for a group use get_group_profile.',
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
    description: 'Malware or tool profile: type, platforms, aliases, techniques used, groups using it, campaigns. Find the ID with search_software.',
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
    description: 'Malware and tool summaries (with the malware/tool type) matching a name or description search, filterable by sector. Use get_software_detail for the full record.',
    parameters: {
      type: "OBJECT",
      properties: {
        search: { type: "STRING", description: 'Search keyword (minimum 3 characters)' },
        sector: { type: "STRING", enum: ['defense', 'education', 'energy', 'financial', 'government', 'healthcare', 'manufacturing', 'media', 'retail', 'technology', 'telecommunications', 'transportation'], description: 'Filter by sector.' },
        limit: { type: "NUMBER", description: 'Max results (default 10)' },
        page: { type: "NUMBER", description: 'Page number, default 1. See pagination.total in the response.' },
      },
    },
  },
  {
    name: 'get_campaign_detail',
    description: 'Campaign profile: first/last seen dates, techniques used, software deployed, groups involved. Find the ID with search_campaigns.',
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
    description: 'Campaign summaries matching a name or description search, filterable by sector, with first/last seen dates. Use get_campaign_detail for techniques, software and groups.',
    parameters: {
      type: "OBJECT",
      properties: {
        search: { type: "STRING", description: 'Search keyword (minimum 3 characters)' },
        sector: { type: "STRING", enum: ['defense', 'education', 'energy', 'financial', 'government', 'healthcare', 'manufacturing', 'media', 'retail', 'technology', 'telecommunications', 'transportation'], description: 'Filter by sector.' },
        limit: { type: "NUMBER", description: 'Max results (default 10)' },
        page: { type: "NUMBER", description: 'Page number, default 1. See pagination.total in the response.' },
      },
    },
  },
  {
    name: 'get_mitigation_detail',
    description: 'Mitigation profile: description, domain and every technique it addresses.  Find the ID with search_mitigations.',
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
    description: 'Mitigation summaries matching a name or description search -- no technique list. Use get_mitigation_detail for the techniques one addresses.',
    parameters: {
      type: "OBJECT",
      properties: {
        search: { type: "STRING", description: 'Search keyword (minimum 3 characters)' },
        limit: { type: "NUMBER", description: 'Max results (default 10)' },
        page: { type: "NUMBER", description: 'Page number, default 1. See pagination.total in the response.' },
      },
    },
  },
  {
    name: 'search_iocs',
    description: 'Search indicators of compromise (IPs, domains, URLs, file hashes) from OTX, ThreatFox, MalwareBazaar and CISA KEV, newest first, with malware family and a count of linked ATT&CK techniques -- the technique IDs themselves are not returned. CVE rows are excluded unless type is cve or source is cisa_kev; use search_cves for vulnerabilities.',
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
    description: 'Search SigmaHQ detection rules: rule ID, title, severity level, log source and mapped ATT&CK technique. Keyword matches titles and rule IDs only, not rule logic, so a miss is not proof no rule covers it.',
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
    description: 'Search Atomic Red Team emulation tests: test name, platforms, executor type, the run and cleanup commands, and the ATT&CK technique covered. Keyword matches test names and technique IDs only.',
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
    description: 'ETDA/ThaiCERT reference metadata for one external actor: country, motivation, state sponsor, suspected victims, MITRE group mapping. No techniques, software or campaigns -- use get_group_profile for TTPs. The lookup is an exact name match, so a miss means only that this dataset has no entry under that spelling; always try search_groups before calling an actor unknown. Browse the dataset with search_external_actors.',
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
    description: 'ETDA/ThaiCERT external actors by keyword, country or category, with motivation and MITRE group mapping. Keyword is whole-word full text over name and description, not substring, so a partial stem like lazar does not match Lazarus; country and category are exact equality. These rows are already near-complete -- get_external_actor adds only the first-seen date for one actor; for ATT&CK TTPs use search_groups.',
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
    description: 'Tactic profile: description, domain and every technique under the tactic.',
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
    description: 'Data source profile: description, its data components and the techniques it can detect.',
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
    description: 'Lists the OWASP Top 10 categories for Web 2021, ML 2023 and LLM 2025 with per-category CWE, ATT&CK technique, ATLAS and CVE counts. Use get_owasp_category for one category in full.',
    parameters: {
      type: "OBJECT",
      properties: {
        framework: { type: "STRING", description: 'Filter by framework: web-2021, ml-2023, or llm-2025. Omit for all.' },
      },
    },
  },
  {
    name: 'get_owasp_category',
    description: 'Full record for one OWASP category: CWEs, mapped ATT&CK and ATLAS techniques, top CVEs, affected applications, and related categories in the other OWASP frameworks. get_owasp_top10 lists the categories.',
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
    description: 'Full record for one GitHub Security Advisory: summary, CVSS v3 and v4, CWEs, affected packages with vulnerable and fixed ranges. CAPEC patterns and ATT&CK techniques are inferred from shared CWEs, not published by GitHub; attribute them that way. version matches text in an affected range, not a verdict that the version is vulnerable; say so. Find an ID with search_ghsa.',
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
    description: 'Every advisory affecting one package in one ecosystem (exact name match). GHSA ecosystems (npm, pypi, go, maven...) carry vulnerable and fixed ranges and linked ATT&CK techniques; OSV distro ones (Debian, Ubuntu, Alpine...) carry neither, and their null ranges mean not modelled, never no fix. version applies to GHSA only, is ignored for OSV, and matches text in an affected range, not a verdict that the version is vulnerable; say so.',
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
    description: 'GHSA-only summary rows (OSS packages) by keyword, severity, ecosystem or date, newest first; get_ghsa_detail has the full record. For OS, distro and kernel advisories or a combined view use search_advisories; to narrow by package version use get_package_vulnerabilities.',
    parameters: {
      type: "OBJECT",
      properties: {
        q: { type: "STRING", description: 'Search query (GHSA ID, CVE, summary, or description)' },
        severity: { type: "STRING", enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], description: 'Filter by severity' },
        ecosystem: { type: "STRING", description: 'Filter by ecosystem: npm, pypi, go, maven, rubygems, nuget, composer, rust' },
        since: { type: "STRING", description: 'ISO date string — only advisories published after this date' },
        has_cve: { type: "STRING", description: 'Filter by CVE alias presence: "true" (CVE-linked) or "false" (GHSA-only)' },
        limit: { type: "NUMBER", description: 'Max results (default 10, max 50)' },
        page: { type: "NUMBER", description: 'Page number, default 1. See pagination.total in the response.' },
      },
    },
  },
  {
    name: 'get_cve_packages',
    description: 'Open-source packages affected by one CVE via its GHSA alias, with vulnerable and fixed ranges. An empty list means no GHSA alias or a failed lookup, never proof that no package is affected -- check osvAdvisories in get_cve_detail.',
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
    description: 'Full record for one CAPEC attack pattern: prerequisites, skills and resources needed, consequences, linked CWEs, mapped ATT&CK techniques, mitigations and related patterns. search_capec finds an ID.',
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
    description: 'Summary rows for the 615 CAPEC attack patterns by keyword, abstraction, severity or likelihood, with CWE refs and mapped technique and mitigation counts; get_capec_detail has the full record. The keyword matches name and ID only, never description text.',
    parameters: {
      type: "OBJECT",
      properties: {
        q: { type: "STRING", description: 'Search keyword against CAPEC name/ID (minimum 2 characters)' },
        abstraction: { type: "STRING", enum: ['Meta', 'Standard', 'Detailed'], description: 'Abstraction level' },
        severity: { type: "STRING", enum: ['Very Low', 'Low', 'Medium', 'High', 'Very High'], description: 'Severity' },
        likelihood: { type: "STRING", enum: ['Low', 'Medium', 'High'], description: 'Likelihood of attack' },
        limit: { type: "NUMBER", description: 'Max results (default 20, max 50)' },
        page: { type: "NUMBER", description: 'Page number, default 1. See pagination.total in the response.' },
      },
    },
  },
  {
    name: 'search_advisories',
    description: 'Unified summary rows over GHSA (OSS packages) and OSV (OS, distro, kernel), each tagged with its source; the two sets are disjoint, so no duplicates. Filter by source, severity, ecosystem, date or CVE-alias presence; rows are severity-ranked, then newest. Full record: get_ghsa_detail or get_osv_detail. This is the unified GHSA+OSV view; search_ghsa queries the GHSA corpus directly, returns more rows for the same query and adds techniqueCount and withdrawnAt, so prefer it when ATT&CK linkage or withdrawal status matters.',
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
        page: { type: "NUMBER", description: 'Page number, default 1. See pagination.total in the response.' },
      },
    },
  },
  {
    name: 'get_osv_detail',
    description: 'Full record for one OSV advisory by native ID (DSA-, USN-, RLSA-, ALAS-): summary, aliases (CVE and GHSA), CVSS, affected packages by ecosystem with vulnerable ranges. Distro, kernel and OS ecosystems only -- use get_ghsa_detail for OSS packages, search_advisories to find an ID.',
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
    description: 'Lists the compliance and regulatory frameworks bridged to ATT&CK through the Secure Controls Framework (SCF), each with its framework_key slug and coverage counts (SCF controls, techniques referenced, techniques referenced by 2 or more controls). Default is the curated 21 Tier 1+2 set; include_all adds the Tier 3 long tail. Call this first to confirm a slug, then get_compliance_framework for one framework in full.',
    parameters: {
      type: "OBJECT",
      properties: {
        include_all: { type: "BOOLEAN", description: 'When true returns Tier 3 long-tail (~250 frameworks); default returns the curated 21.' },
      },
    },
  },
  {
    name: 'get_compliance_framework',
    description: 'Full record for one framework by framework_key: every ATT&CK technique it references, grouped by article or section with the ref_id that cites each, plus the frameworks it overlaps most. Returns 404 for an unknown key -- never invent a slug; call list_compliance_frameworks to confirm it.',
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
    description: 'Which compliance frameworks reference a single ATT&CK technique, with the SCF control count per framework and up to 8 of the article or section ref_ids that cite it -- a sample, not the full citation list. Takes T-IDs only -- ATLAS AML IDs are rejected. An empty frameworks array is authoritative not-covered for the tiers queried (Tier 1+2 unless include_all): do not infer or invent a mapping. For direct ATT&CK mappings (800-53, Engage, VERIS, cloud controls) use get_framework_mappings.',
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
    name: 'get_usage_guide',
    description: 'Loads the usage guide for this server: how to choose between similar tools, data provenance and how to report it honestly, pagination, controlled vocabularies (sectors, framework keys, OWASP frameworks) and the ICS Purdue model semantics. Call it once when you need detail that individual tool descriptions do not carry. Takes no arguments.',
    parameters: {
      type: "OBJECT",
      properties: {},
    },
  },
  {
    name: 'search_assets',
    description: 'Search the ATT&CK for ICS asset catalogue -- A0001-A0018: PLCs, RTUs, safety controllers, historians, HMIs, engineering workstations, field I/O -- by name, Purdue level, zone, sector or IT/OT boundary; returns summary rows, while get_asset_detail returns one full record and get_purdue_model the level and flow definitions. Every Purdue field (primaryLevel, zone, spansLevels, isBoundary, rationale) is CURATED from NIST SP 800-82r3 and ISA-95, not published by MITRE -- attribute it that way. MITRE publishes assets for the ICS domain only, so an empty result for a non-ICS question is expected, not missing data.',
    parameters: {
      type: "OBJECT",
      properties: {
        search: { type: "STRING", description: 'Name or ATT&CK ID substring, e.g. "historian", "PLC", "A0001". Minimum 2 characters or it is ignored.' },
        level: { type: "STRING", enum: ['l0', 'l1', 'l2', 'l3', 'l3_5', 'l4', 'l5'], description: 'Purdue level the asset is PRESENT at, not merely primary at -- a historian primarily at L3 but replicated into the DMZ matches both l3 and l3_5. l3_5 is the industrial DMZ.' },
        zone: { type: "STRING", enum: ['ot', 'dmz', 'it'], description: 'Purdue zone. ot = levels 0-3 (plant floor, where a breach moves physical things), dmz = level 3.5, it = levels 4-5 (corporate network).' },
        sector: { type: "STRING", description: 'Industrial sector the asset is used in, e.g. electric, manufacturing, water.' },
        boundary: { type: "BOOLEAN", description: 'True returns only assets present in the industrial DMZ (L3.5) -- the IT/OT crossing points an attacker pivots through. Six of the eighteen assets qualify.' },
        limit: { type: "NUMBER", description: 'Max results (default 50, max 200)' },
        page: { type: "NUMBER", description: 'Page number, default 1. See pagination.total in the response.' },
      },
    },
  },
  {
    name: 'get_asset_detail',
    description: 'Full record for one ATT&CK for ICS asset (A0001-A0018): description, sectors, platforms, related assets, every ICS technique that targets it, and its Purdue placement. Use search_assets to find the ID. The Purdue placement (primary level, spans, boundary flag, rationale) is CURATED from NIST SP 800-82r3 and ISA-95, not MITRE-published -- say so when citing it.',
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
    description: 'The Purdue model (ISA-95 / PERA) as data: the seven levels L0 to L5 including L3.5 the industrial DMZ with per-level asset and technique counts, every ICS asset placed on them, and the full 42-pair flow matrix -- use it for lateral-movement and IT/OT pivot questions. directAllowed means the two levels are topologically ADJACENT, not that either side may initiate: read the note field for directionality (l3_5 to l3 is directAllowed, yet the OT side initiates and a DMZ host must not open sessions inward), and a pair carrying brokerLevel is reachable only by terminating a session at that level, never adjacency. Placement is curated from NIST SP 800-82r3 and ISA-95, not MITRE-published; MITRE publishes assets and techniques for the ICS domain only, so L4/L5 carrying no assets is by design, not missing data.',
    parameters: {
      type: "OBJECT",
      properties: {},
    },
  },
];
