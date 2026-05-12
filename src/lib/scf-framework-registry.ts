// src/lib/scf-framework-registry.ts
//
// Hand-curated registry of Tier 1 + Tier 2 compliance frameworks surfaced
// on /compliance. Drives:
//   1. sync-scf.mjs — when ingest sees an SCF column header in `aliases`,
//      it maps the row to this framework_key.
//   2. /compliance hub — display order, section grouping, region/tier filters.
//   3. /compliance/<framework_key> — metadata block (effective date, scope,
//      enforcer, upstream URL).
//
// Everything not in this registry defaults to Tier 3 and is hidden behind
// the "Show all (250+)" toggle on the hub.
//
// Spec: docs/superpowers/specs/2026-05-12-scf-compliance-design.md
//   - Tier 1: 12 global high-demand
//   - Tier 2: 10 sectoral/regional
//
// Maintenance: when SCF ships a new release and a column header changes,
// add the new header string to the entry's `aliases` array. The ingester
// fails loud if a Tier-1 entry has zero matching headers in the workbook.

export type Region = 'global' | 'eu' | 'us' | 'uk' | 'apac' | 'mena' | 'americas';

export type LicenseClass =
  | 'public-domain'
  | 'permissive'
  | 'cc-by'
  | 'cc-by-sa'
  | 'cc-by-nc-sa'
  | 'commercial';

export interface ScfFrameworkEntry {
  framework_key: string;
  name: string;
  version?: string;
  source_org: string;
  upstream_url: string;
  region: Region;
  tier: 1 | 2;
  license: string;
  license_class: LicenseClass;
  short_blurb: string;
  /** Substring matches against SCF column headers — case-insensitive. */
  aliases: string[];
  /** Optional richer metadata for /compliance/<key> detail page header. */
  effective?: string;
  scope?: string;
  enforcer?: string;
}

export const SCF_FRAMEWORK_REGISTRY: ScfFrameworkEntry[] = [
  // ----- Tier 1 — Global, high-demand (12) -----------------------------
  {
    framework_key: 'nist-800-53-r5',
    name: 'NIST SP 800-53 r5',
    version: 'Revision 5',
    source_org: 'NIST',
    upstream_url: 'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final',
    region: 'us',
    tier: 1,
    license: 'Public Domain (US Government Work)',
    license_class: 'public-domain',
    short_blurb: 'US federal baseline of security & privacy controls.',
    aliases: ['NIST SP 800-53 R5', 'NIST 800-53 R5', '800-53 R5', 'NIST 800-53 rev5'],
    effective: 'Published September 2020 (updated 2023-11-07)',
    scope: 'US federal information systems + adopted by contractors',
    enforcer: 'OMB, agency CIOs',
  },
  {
    framework_key: 'nist-csf-v2',
    name: 'NIST CSF v2.0',
    version: '2.0',
    source_org: 'NIST',
    upstream_url: 'https://www.nist.gov/cyberframework',
    region: 'global',
    tier: 1,
    license: 'Public Domain (US Government Work)',
    license_class: 'public-domain',
    short_blurb: 'Voluntary outcomes-based cybersecurity framework (GV/ID/PR/DE/RS/RC).',
    aliases: ['NIST Cybersecurity Framework v2.0', 'NIST CSF 2.0', 'CSF v2'],
    effective: 'Published 26 February 2024',
    scope: 'Critical infrastructure + any org seeking risk-management baseline',
  },
  {
    framework_key: 'iso-27002-2022',
    name: 'ISO/IEC 27002:2022',
    version: '2022',
    source_org: 'ISO/IEC',
    upstream_url: 'https://www.iso.org/standard/75652.html',
    region: 'global',
    tier: 1,
    license: 'Commercial — ISO standards storefront',
    license_class: 'commercial',
    short_blurb: 'Information security controls reference. Companion to ISO 27001.',
    aliases: ['ISO/IEC 27002:2022', 'ISO 27002:2022', 'ISO 27002 v2022'],
    effective: 'Published February 2022',
  },
  {
    framework_key: 'pci-dss-4',
    name: 'PCI DSS v4.0.1',
    version: '4.0.1',
    source_org: 'PCI SSC',
    upstream_url: 'https://www.pcisecuritystandards.org/document_library/',
    region: 'global',
    tier: 1,
    license: 'Free with PCI SSC registration',
    license_class: 'permissive',
    short_blurb: 'Payment card industry data security standard.',
    aliases: ['PCI DSS v4.0', 'PCI DSS 4.0.1', 'PCI-DSS v4'],
    effective: 'PCI DSS v4.0 effective 31 March 2024; v4.0.1 errata 11 June 2024',
    scope: 'Merchants + service providers handling cardholder data',
    enforcer: 'Acquiring banks, payment brands',
  },
  {
    framework_key: 'soc-2-tsc',
    name: 'SOC 2 Trust Services Criteria',
    version: '2017 (rev 2022)',
    source_org: 'AICPA',
    upstream_url: 'https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services',
    region: 'us',
    tier: 1,
    license: 'AICPA licensed',
    license_class: 'commercial',
    short_blurb: 'Service-organization controls (Security, Availability, Processing Integrity, Confidentiality, Privacy).',
    aliases: ['SOC 2 TSC', 'AICPA TSC', 'AICPA SOC 2 Trust Services'],
  },
  {
    framework_key: 'hipaa-security-rule',
    name: 'HIPAA Security Rule',
    version: '45 CFR Part 164 Subpart C',
    source_org: 'HHS OCR',
    upstream_url: 'https://www.hhs.gov/hipaa/for-professionals/security/index.html',
    region: 'us',
    tier: 1,
    license: 'Public Domain (US Government Work)',
    license_class: 'public-domain',
    short_blurb: 'Administrative, physical, and technical safeguards for ePHI.',
    aliases: ['HIPAA', 'HIPAA Security', '45 CFR 164 Subpart C'],
    scope: 'US covered entities + business associates',
    enforcer: 'HHS Office for Civil Rights',
  },
  {
    framework_key: 'gdpr',
    name: 'EU GDPR',
    version: 'Regulation (EU) 2016/679',
    source_org: 'European Parliament & Council',
    upstream_url: 'https://eur-lex.europa.eu/eli/reg/2016/679/oj',
    region: 'eu',
    tier: 1,
    license: 'EU Official Journal (public)',
    license_class: 'public-domain',
    short_blurb: 'General Data Protection Regulation — personal-data security obligations (Art. 32 et al.).',
    aliases: ['GDPR', 'EU 2016/679', 'General Data Protection Regulation'],
    effective: '25 May 2018',
    scope: 'Any org processing personal data of EU/EEA residents',
    enforcer: 'EU national DPAs (BfDI, CNIL, ICO pre-Brexit, etc.)',
  },
  {
    framework_key: 'eu-nis2',
    name: 'EU NIS2 Directive',
    version: 'Directive (EU) 2022/2555',
    source_org: 'European Parliament & Council',
    upstream_url: 'https://eur-lex.europa.eu/eli/dir/2022/2555/oj',
    region: 'eu',
    tier: 1,
    license: 'EU Official Journal (public)',
    license_class: 'public-domain',
    short_blurb: 'Cybersecurity obligations for "essential" and "important" entities across the EU.',
    aliases: ['EU NIS2', 'NIS2 Directive', 'EU 2022/2555', 'NIS 2'],
    effective: 'Transposition deadline 17 October 2024',
    scope: 'Essential + important entities (energy, transport, banking, health, ICT, public admin)',
    enforcer: 'National competent authorities + ENISA',
  },
  {
    framework_key: 'eu-cra',
    name: 'EU Cyber Resilience Act',
    version: 'Regulation (EU) 2024/2847',
    source_org: 'European Parliament & Council',
    upstream_url: 'https://eur-lex.europa.eu/eli/reg/2024/2847/oj',
    region: 'eu',
    tier: 1,
    license: 'EU Official Journal (public)',
    license_class: 'public-domain',
    short_blurb: 'Horizontal cybersecurity requirements for products with digital elements.',
    aliases: ['EU CRA', 'Cyber Resilience Act', 'EU 2024/2847'],
    effective: 'Main obligations apply from 11 December 2027',
    scope: 'Manufacturers, importers, distributors of products with digital elements placed on EU market',
  },
  {
    framework_key: 'eu-ai-act',
    name: 'EU AI Act',
    version: 'Regulation (EU) 2024/1689',
    source_org: 'European Parliament & Council',
    upstream_url: 'https://eur-lex.europa.eu/eli/reg/2024/1689/oj',
    region: 'eu',
    tier: 1,
    license: 'EU Official Journal (public)',
    license_class: 'public-domain',
    short_blurb: 'Risk-based regulation of AI systems placed on the EU market.',
    aliases: ['EU AI Act', 'EU 2024/1689', 'AI Act'],
    effective: 'Phased — prohibited practices from 2 Feb 2025; high-risk obligations 2 Aug 2026',
  },
  {
    framework_key: 'cmmc-2',
    name: 'CMMC 2.0',
    version: '2.0 (32 CFR Part 170)',
    source_org: 'US DoD',
    upstream_url: 'https://dodcio.defense.gov/CMMC/',
    region: 'us',
    tier: 1,
    license: 'Public Domain (US Government Work)',
    license_class: 'public-domain',
    short_blurb: 'Cybersecurity Maturity Model Certification for DoD contractors.',
    aliases: ['CMMC 2.0', 'CMMC Level 2', 'CMMC Level 3'],
    effective: 'Final rule effective 16 December 2024',
    scope: 'US DoD contractors + subcontractors handling FCI/CUI',
    enforcer: 'DoD via DCMA + C3PAOs',
  },
  {
    framework_key: 'owasp-top10-2025',
    name: 'OWASP Top 10 (2025)',
    version: '2025',
    source_org: 'OWASP Foundation',
    upstream_url: 'https://owasp.org/Top10/',
    region: 'global',
    tier: 1,
    license: 'CC BY-SA 4.0',
    license_class: 'cc-by-sa',
    short_blurb: 'The ten most critical web application security risks.',
    aliases: ['OWASP Top 10', 'OWASP Top10 2025', 'OWASP Top 10 2021'],
  },

  // ----- Tier 2 — Sectoral / regional (10) -----------------------------
  {
    framework_key: 'eu-dora',
    name: 'EU DORA',
    version: 'Regulation (EU) 2022/2554',
    source_org: 'European Parliament & Council',
    upstream_url: 'https://eur-lex.europa.eu/eli/reg/2022/2554/oj',
    region: 'eu',
    tier: 2,
    license: 'EU Official Journal (public)',
    license_class: 'public-domain',
    short_blurb: 'Digital Operational Resilience Act for the EU financial sector.',
    aliases: ['EU DORA', 'DORA', 'EU 2022/2554'],
    effective: '17 January 2025',
    scope: 'EU financial entities + ICT third-party providers',
    enforcer: 'ESMA, EBA, EIOPA, national competent authorities',
  },
  {
    framework_key: 'cis-controls-8-1',
    name: 'CIS Controls v8.1',
    version: '8.1',
    source_org: 'Center for Internet Security',
    upstream_url: 'https://www.cisecurity.org/controls',
    region: 'global',
    tier: 2,
    license: 'CC BY-NC-SA 4.0 (ID-only here — text restricted)',
    license_class: 'cc-by-nc-sa',
    short_blurb: 'Prioritized set of safeguards (cross-referenced via SCF — full text not republished).',
    aliases: ['CIS CSC 8.1', 'CIS CSC 8', 'CIS Controls v8.1', 'CIS Controls 8.1', 'CIS Controls v8'],
  },
  {
    framework_key: 'nist-800-171-r3',
    name: 'NIST SP 800-171 r3',
    version: 'Revision 3',
    source_org: 'NIST',
    upstream_url: 'https://csrc.nist.gov/pubs/sp/800/171/r3/final',
    region: 'us',
    tier: 2,
    license: 'Public Domain (US Government Work)',
    license_class: 'public-domain',
    short_blurb: 'Protecting Controlled Unclassified Information (CUI) in non-federal systems.',
    aliases: ['NIST SP 800-171 R3', 'NIST 800-171 R3', '800-171 R3'],
    effective: 'Published 14 May 2024',
  },
  {
    framework_key: 'fedramp-r5',
    name: 'FedRAMP r5',
    version: 'Rev. 5',
    source_org: 'GSA / OMB',
    upstream_url: 'https://www.fedramp.gov/baselines/',
    region: 'us',
    tier: 2,
    license: 'Public Domain (US Government Work)',
    license_class: 'public-domain',
    short_blurb: 'US federal cloud security baselines (Low/Moderate/High).',
    aliases: ['FedRAMP r5', 'FedRAMP Rev 5', 'FedRAMP Rev. 5'],
  },
  {
    framework_key: 'nerc-cip-2024',
    name: 'NERC CIP (2024)',
    version: '2024 standards set',
    source_org: 'NERC',
    upstream_url: 'https://www.nerc.com/pa/Stand/Pages/CIPStandards.aspx',
    region: 'us',
    tier: 2,
    license: 'Public (NERC standards)',
    license_class: 'permissive',
    short_blurb: 'Critical Infrastructure Protection standards for the Bulk Electric System.',
    aliases: ['NERC CIP', 'NERC CIP-002 through CIP-014', 'NERC CIP 2024'],
  },
  {
    framework_key: 'iec-62443',
    name: 'IEC 62443 (umbrella)',
    version: '2-1 / 3-3 / 4-2',
    source_org: 'IEC / ISA',
    upstream_url: 'https://www.iec.ch/blog/understanding-iec-62443',
    region: 'global',
    tier: 2,
    license: 'Commercial — IEC standards storefront',
    license_class: 'commercial',
    short_blurb: 'Industrial automation & control systems (IACS) security.',
    aliases: ['IEC 62443-2-1', 'IEC 62443-3-3', 'IEC 62443-4-2', 'IEC 62443'],
  },
  {
    framework_key: 'uk-cyber-essentials',
    name: 'UK Cyber Essentials',
    version: 'Montpellier (2025)',
    source_org: 'UK NCSC / IASME',
    upstream_url: 'https://www.ncsc.gov.uk/cyberessentials/overview',
    region: 'uk',
    tier: 2,
    license: 'Open Government Licence v3.0',
    license_class: 'permissive',
    short_blurb: 'UK baseline cyber-hygiene certification for any organisation.',
    aliases: ['UK Cyber Essentials', 'Cyber Essentials', 'NCSC Cyber Essentials'],
  },
  {
    framework_key: 'au-essential-8',
    name: 'AU Essential Eight',
    version: 'ML1-ML3 (ACSC 2023)',
    source_org: 'Australian Cyber Security Centre (ACSC)',
    upstream_url: 'https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight',
    region: 'apac',
    tier: 2,
    license: 'CC BY 4.0',
    license_class: 'cc-by',
    short_blurb: 'Eight mitigation strategies — Maturity Levels 1-3 — for Australian organisations.',
    aliases: ['Australia Essential 8', 'AU Essential 8', 'Essential Eight', 'ACSC Essential Eight'],
  },
  {
    framework_key: 'nist-ai-rmf',
    name: 'NIST AI RMF 1.0',
    version: '1.0 + Generative AI Profile',
    source_org: 'NIST',
    upstream_url: 'https://www.nist.gov/itl/ai-risk-management-framework',
    region: 'global',
    tier: 2,
    license: 'Public Domain (US Government Work)',
    license_class: 'public-domain',
    short_blurb: 'Voluntary AI risk-management framework (Govern, Map, Measure, Manage).',
    aliases: ['NIST AI RMF 1.0', 'NIST AI RMF', 'AI RMF'],
    effective: 'Published 26 January 2023',
  },
  // (Removed mitre-attck-mitigations: SCF's "MITRE ATT&CK" column maps to
  // T-codes, not M-codes, and those flow into scf_attack_mappings. The /mitigations
  // page on this site already lists Mxxxx separately.)
];

export const TIER1_KEYS = SCF_FRAMEWORK_REGISTRY.filter((f) => f.tier === 1).map((f) => f.framework_key);
export const TIER2_KEYS = SCF_FRAMEWORK_REGISTRY.filter((f) => f.tier === 2).map((f) => f.framework_key);

/**
 * Look up a framework entry by key. Returns undefined for Tier-3 keys
 * (ingested but not in the curated registry).
 */
export function getFrameworkEntry(framework_key: string): ScfFrameworkEntry | undefined {
  return SCF_FRAMEWORK_REGISTRY.find((f) => f.framework_key === framework_key);
}

/**
 * Build a substring-match lookup table for the ingester. Each alias maps
 * to the framework_key. The ingester walks the workbook's column headers
 * and resolves each match to its key.
 */
export function buildAliasLookup(): Array<{ alias: string; framework_key: string }> {
  const out: Array<{ alias: string; framework_key: string }> = [];
  for (const entry of SCF_FRAMEWORK_REGISTRY) {
    for (const alias of entry.aliases) {
      out.push({ alias: alias.toLowerCase(), framework_key: entry.framework_key });
    }
  }
  // Longer aliases first so 'NIST SP 800-53 R5' matches before 'NIST 800-53'.
  out.sort((a, b) => b.alias.length - a.alias.length);
  return out;
}
