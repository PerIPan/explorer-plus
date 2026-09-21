#!/usr/bin/env node
// scripts/gen-framework-section-text.mjs
//
// Generates src/lib/framework-section-text.ts — the short text shown next to
// section and reference IDs on /compliance/[key].
//
// RIGHTS. Only frameworks whose text is public domain or openly licensed are
// generated here. NIST publications are works of the US federal government and
// carry no domestic copyright; NIST asks only for credit, which the compliance
// page gives in its Sources line. ISO 27002, PCI DSS, SOC 2 (AICPA),
// IEC 62443 and CIS Controls are copyrighted and MUST NOT be added — their
// sections stay ID-only. See the framework-text-rights note.
//
// Source: NIST Cybersecurity and Privacy Reference Tool (CPRT) JSON export.
// Fetched live so a regeneration always reflects the published document.
//
// Usage: node scripts/gen-framework-section-text.mjs [--offline=<dir>]

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(ROOT, 'src/lib/framework-section-text.ts');

const CPRT = (doc) =>
  `https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/${doc}/export/json?element=all`;

const DOCS = {
  'sp_800_53_5_2_0': 'NIST SP 800-53 Rev. 5',
  'sp_800_171_3_0_0': 'NIST SP 800-171 Rev. 3',
};

/** Acronyms that must stay upper-case when title-casing NIST's ALL CAPS titles. */
const ACRONYMS = new Set([
  'US', 'U.S.', 'NSA', 'GSA', 'NIAP', 'FIPS', 'PIV', 'PKI', 'FICAM', 'SCRM',
  'PII', 'CUI', 'IP', 'IPV6', 'DNS', 'VOIP', 'USB', 'RF', 'GPS', 'PKE',
  'OCSP', 'CRL', 'TLS', 'SSL', 'API', 'CPU', 'OS', 'IT', 'ICS', 'SCADA',
  'HTTP', 'FTP', 'SMTP', 'DHCP', 'LDAP', 'SAML', 'XML', 'JSON', 'SQL', 'ID',
  'IDS', 'IPS', 'SIEM', 'MAC', 'DAC', 'RBAC', 'ABAC', 'VPN', 'WAN', 'LAN',
  'COTS', 'GOTS', 'SBOM', 'CVE', 'CWE', 'TTP', 'TTPS', 'DDOS', 'DOS',
]);

/** Small words that stay lower-case unless they start the title. */
const MINOR = new Set(['a', 'an', 'and', 'as', 'at', 'by', 'for', 'from', 'in', 'of', 'on', 'or', 'the', 'to', 'with', 'within']);

/**
 * "ACCESS CONTROL" -> "Access Control"; "PIV CREDENTIALS" -> "PIV Credentials".
 * Mixed-case input (SP 800-171 ships title case already) is returned untouched.
 */
export function titleCase(raw) {
  const s = String(raw ?? '').replace(/\s+/g, ' ').trim();
  if (!s || s !== s.toUpperCase()) return s; // already cased — leave it alone
  return s
    .split(' ')
    .map((word, i) => {
      // Keep punctuation attached: split on the leading/trailing non-letters.
      const m = word.match(/^([^A-Za-z0-9]*)(.*?)([^A-Za-z0-9]*)$/);
      const [, pre, core, post] = m ?? ['', '', word, ''];
      if (!core) return word;
      if (ACRONYMS.has(core)) return pre + core + post;
      // Hyphenated / slashed compounds: case each part.
      const cased = core
        .split(/([-/])/)
        .map((part) => {
          if (part === '-' || part === '/') return part;
          if (ACRONYMS.has(part)) return part;
          const lower = part.toLowerCase();
          if (i > 0 && MINOR.has(lower)) return lower;
          return lower.charAt(0).toUpperCase() + lower.slice(1);
        })
        .join('');
      return pre + cased + post;
    })
    .join(' ');
}

async function loadDoc(doc, offlineDir) {
  if (offlineDir) {
    const p = path.join(offlineDir, `${doc}.json`);
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  }
  const resp = await fetch(CPRT(doc), { signal: AbortSignal.timeout(120_000) });
  if (!resp.ok) throw new Error(`CPRT ${doc}: HTTP ${resp.status}`);
  return resp.json();
}

/**
 * SP 800-53: families (AC, AU, ...) plus every control and enhancement.
 * SCF cites them as 'AC-01' / 'AC-02(01)', which is CPRT's own identifier
 * format — verified 810/810 for nist-800-53-r5 and 490/490 for fedramp-r5.
 */
function extract80053(json) {
  const els = json.response.elements.elements;
  const out = {};
  for (const e of els) {
    if (e.element_type === 'family') out[e.element_identifier] = titleCase(e.title);
    if (e.element_type === 'control' || e.element_type === 'control_enhancement') {
      out[e.element_identifier] = titleCase(e.title);
    }
  }
  return out;
}

/**
 * SP 800-171: families are '03.01'; requirements are cited by SCF as
 * '03.01.01.a', which CPRT identifies as 'SR-03.01.01.a' — verified 275/275.
 */
function extract800171(json) {
  const els = json.response.elements.elements;
  const out = {};
  for (const e of els) {
    if (e.element_type === 'family') out[e.element_identifier] = titleCase(e.title);
    if (e.element_type === 'security_requirement') {
      const id = e.element_identifier.replace(/^SR-/, '');
      // Sub-parts carry the requirement sentence as `text` and a bare index
      // ("a", "01") as title; the sentence is what a reader needs.
      const label = e.text?.trim() || e.title?.trim();
      if (label && !/^\d+$/.test(label) && label.length > 2) out[id] = titleCase(label);
    }
  }
  return out;
}

function serialize(obj) {
  const keys = Object.keys(obj).sort();
  return `{\n${keys.map((k) => `  ${JSON.stringify(k)}: ${JSON.stringify(obj[k])},`).join('\n')}\n}`;
}

async function main() {
  const offlineArg = process.argv.find((a) => a.startsWith('--offline='));
  const offlineDir = offlineArg ? offlineArg.slice('--offline='.length) : null;

  const [j53, j171] = await Promise.all([
    loadDoc('sp_800_53_5_2_0', offlineDir),
    loadDoc('sp_800_171_3_0_0', offlineDir),
  ]);

  const nist80053 = extract80053(j53);
  const nist800171 = extract800171(j171);

  // Fail loudly rather than emit a stub: the page silently loses every title
  // if this is wrong, exactly the class of failure the SCF ingest just taught us.
  if (Object.keys(nist80053).length < 1000) throw new Error(`SP 800-53 produced only ${Object.keys(nist80053).length} entries`);
  if (Object.keys(nist800171).length < 200) throw new Error(`SP 800-171 produced only ${Object.keys(nist800171).length} entries`);
  for (const fam of ['AC', 'AU', 'SC', 'SI', 'SR']) {
    if (!nist80053[fam]) throw new Error(`SP 800-53 family ${fam} missing`);
  }

  const banner = `// GENERATED FILE -- do not edit by hand.
// Regenerate: node scripts/gen-framework-section-text.mjs
//
// Short text for section and reference IDs on /compliance/[key].
//
// RIGHTS: NIST publications are works of the US federal government and carry no
// domestic copyright; NIST asks only for credit, which the compliance page
// gives in its Sources line. Frameworks whose text is licensed -- ISO 27002,
// PCI DSS, SOC 2 (AICPA), IEC 62443, CIS Controls -- are deliberately absent
// and render as bare IDs.
//
// Source: NIST Cybersecurity and Privacy Reference Tool (CPRT) JSON export
// (${Object.entries(DOCS).map(([k, v]) => `${v} = ${k}`).join(', ')}).
`;

  const body = `${banner}
/** ${DOCS['sp_800_53_5_2_0']} -- families, controls and control enhancements. */
const NIST_800_53: Record<string, string> = ${serialize(nist80053)};

/** ${DOCS['sp_800_171_3_0_0']} -- families and security requirements. */
const NIST_800_171: Record<string, string> = ${serialize(nist800171)};

/**
 * framework_key -> lookup for its section and reference IDs.
 *
 * FedRAMP baselines are SP 800-53 controls under a GSA/OMB wrapper and cite the
 * identical IDs, so they share the table.
 */
export const FRAMEWORK_SECTION_TEXT: Record<string, Record<string, string>> = {
  'nist-800-53-r5': NIST_800_53,
  'fedramp-r5': NIST_800_53,
  'nist-800-171-r3': NIST_800_171,
};

/** Look up one section or ref ID. Returns null when the framework has no source. */
export function sectionText(frameworkKey: string, id: string): string | null {
  return FRAMEWORK_SECTION_TEXT[frameworkKey]?.[id] ?? null;
}
`;

  fs.writeFileSync(OUT, body);
  console.log(`[gen-section-text] wrote ${OUT}`);
  console.log(`  SP 800-53:  ${Object.keys(nist80053).length} entries`);
  console.log(`  SP 800-171: ${Object.keys(nist800171).length} entries`);
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1].endsWith('gen-framework-section-text.mjs')) {
  main().catch((e) => { console.error('[gen-section-text] FAILED:', e.message); process.exit(1); });
}
