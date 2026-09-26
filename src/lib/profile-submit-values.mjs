// src/lib/profile-submit-values.mjs
//
// The telemetry sink's VOCABULARY — the exact set of values each of the six
// dimension columns on `profile_submissions` may hold. `profile-submit-schema.mjs`
// turns each list into a `z.enum`.
//
// ── Why this file exists at all ──────────────────────────────────────────────
//
// It is plain `.mjs` because `scripts/lib/profile-submit.test.mjs` imports the
// schema under bare `node --test`, with no bundler and no TS loader. That rules
// out importing `src/lib/profile-options.ts` (sectors, platforms) or
// `src/lib/scf-framework-registry.ts` (framework keys) directly, however much
// one would prefer to: those are `.ts`, and bare node cannot load them.
//
// So these lists are a deliberate, guarded MIRROR, not a second source of
// truth. `scripts/lib/profile-submit.test.mjs` re-derives every one of them
// from its authoring module by reading that file and fails loudly, naming the
// file, the moment the two disagree. Adding a sector, a platform, a role or a
// framework in its own module and forgetting this one is a red `npm test`, not
// a 400 in production on a legitimate submission.
//
// ── Why enums at the edge at all ─────────────────────────────────────────────
//
// `slugList` used to be `z.array(z.string().min(1).max(64))`, so all six
// columns accepted ANY 64-character string, 20 rows per IP per day, on the
// repo's only unauthenticated public write. The spec's Optionality table
// requires `z.enum` here — "never free-string" — because this table is not just
// storage: the apply/dismiss ratio computed from it is the single metric the
// whole feature is judged on, and a column anyone can write arbitrary values
// into cannot be grouped by.

/** Sectors. Mirrors `SECTOR_SLUGS` in src/lib/profile-options.ts. */
export const SECTOR_VALUES = [
  'defense',
  'education',
  'energy',
  'financial',
  'government',
  'healthcare',
  'manufacturing',
  'media',
  'retail',
  'technology',
  'telecommunications',
  'transportation',
];

/**
 * Platforms. Mirrors `PLATFORMS` in src/lib/profile-options.ts — the union of
 * ENTERPRISE_PLATFORMS, MOBILE_PLATFORMS and ICS_PLATFORMS, in that order.
 *
 * The seven ICS values are included even though no picker may ever offer them
 * (no live ICS technique carries any platform), because they remain legal input
 * to the assembler and the telemetry vocabulary must not be narrower than the
 * assembler's: a URL that the API accepts must not produce a submission the
 * sink rejects.
 */
export const PLATFORM_VALUES = [
  // enterprise-attack
  'Windows',
  'Linux',
  'macOS',
  'IaaS',
  'SaaS',
  'Containers',
  'Office Suite',
  'Identity Provider',
  'PRE',
  'ESXi',
  'Network Devices',
  // mobile-attack
  'Android',
  'iOS',
  // ics-attack
  'Field Controller/RTU/PLC/IED',
  'Safety Instrumented System/Protection Relay',
  'Engineering Workstation',
  'Human-Machine Interface',
  'Control Server',
  'Data Historian',
  'Input/Output Server',
];

/**
 * ATT&CK for ICS asset ids. Mirrors `assetIdSchema` in
 * app/api/v1/lib/validate.ts, which is bounded to `A00(0[1-9]|1[0-8])` rather
 * than a loose `A\d{4}` because `attack_assets` holds exactly 18 rows, all
 * live. Generated rather than written out so the bound is stated once.
 */
export const ASSET_VALUES = Array.from(
  { length: 18 },
  (_, i) => `A${String(i + 1).padStart(4, '0')}`,
);

/**
 * Purdue level keys. Mirrors `purdueLevelSchema` in app/api/v1/lib/validate.ts,
 * which is exactly `purdue_levels.level_key` and exactly the values the
 * `spans_valid` CHECK on `asset_purdue_placement.spans_levels` permits.
 *
 * `l5` is legal and resolves to zero assets (Enterprise IT carries no ATT&CK
 * asset) — an honest absence, and a real answer a visitor may give, so it
 * belongs in the telemetry vocabulary.
 */
export const PURDUE_LEVEL_VALUES = ['l0', 'l1', 'l2', 'l3', 'l3_5', 'l4', 'l5'];

/**
 * Roles. Mirrors `ROLE_OPTIONS` in src/components/profile/ProfilePanel.tsx.
 *
 * Roles are the one dimension with no source of truth in the database — no
 * table, no enum — so the picker's authored shortlist IS the vocabulary. That
 * makes the drift test over it the only thing keeping the two honest.
 */
export const ROLE_VALUES = [
  'soc-detection',
  'threat-intel',
  'incident-response',
  'appsec',
  'grc',
  'red-team',
  'ot-engineering',
];

/**
 * Framework keys. Mirrors `framework_key` across `SCF_FRAMEWORK_REGISTRY` in
 * src/lib/scf-framework-registry.ts, which is what the panel's framework picker
 * is built from. 21 entries (Tier 1 + Tier 2).
 *
 * Keys only. No framework TEXT of any kind belongs here: this list names ISO,
 * PCI DSS, SOC 2, IEC 62443 and CIS Controls, whose text this project may not
 * reproduce.
 */
export const FRAMEWORK_VALUES = [
  'nist-800-53-r5',
  'nist-csf-v2',
  'iso-27002-2022',
  'pci-dss-4',
  'soc-2-tsc',
  'hipaa-security-rule',
  'gdpr',
  'eu-nis2',
  'eu-cra',
  'eu-ai-act',
  'cmmc-2',
  'owasp-top10-2025',
  'eu-dora',
  'cis-controls-8-1',
  'nist-800-171-r3',
  'fedramp-r5',
  'nerc-cip-2024',
  'iec-62443',
  'uk-cyber-essentials',
  'au-essential-8',
  'nist-ai-rmf',
];
