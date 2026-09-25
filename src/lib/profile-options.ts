// src/lib/profile-options.ts
//
// Plain, zod-free value lists shared by the API validators and the client.
//
// These live outside `app/api/v1/lib/validate.ts` for one reason: the Threat
// Profile panel (a 'use client' component on the homepage) needs to render
// pickers over exactly these values, and importing the validator module to get
// them would drag zod into the first-load bundle of the most-visited page in
// the app — ~13 KB gz to read two arrays.
//
// `validate.ts` builds `platformSchema` / `sectorSlugSchema` from these, so
// there is still exactly ONE source of truth and the picker can never offer a
// value the API would 400 on. Keep them `as const`: the literal-union types
// below, and `z.enum`'s narrowing over in `validate.ts`, both depend on it.

/**
 * ATT&CK platforms.
 *
 * Verified against production 2026-09-26, and the claim is narrower than it
 * used to read here. What is true: every ENTERPRISE and MOBILE entry matches
 * >=1 live technique (Windows 474, ESXi 117, Network Devices 100). 'Network',
 * 'Google Workspace' and 'Azure AD' were removed (0 live techniques each) and
 * ESXi/Network Devices added — they previously 400'd.
 *
 * What is NOT true, and what this comment previously asserted: the seven ICS
 * entries below match ZERO live techniques each — Control Server 0, Data
 * Historian 0, Engineering Workstation 0, Field Controller/RTU/PLC/IED 0,
 * Human-Machine Interface 0, Input/Output Server 0, Safety Instrumented
 * System/Protection Relay 0. ATT&CK for ICS does not model platforms: every
 * live ICS technique carries either the literal platform 'None' (73) or no
 * platforms array at all (24). Filtering ICS techniques by any of these seven
 * values therefore returns an empty pool, silently.
 *
 * They stay in the list because they are still legal API input (dropping them
 * would 400 a URL that used to work) and because `ICS_PLATFORMS` below derives
 * the IT/OT picker split from them. The OT path does not rank on platforms at
 * all — it ranks on ATT&CK assets (A0001-A0018) and Purdue levels; see the OT
 * branch of app/api/v1/profile/route.ts. Never offering these seven in a
 * picker is the UI's job, not this list's.
 */
export const PLATFORMS = [
  // Enterprise
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
  // ICS
  'Field Controller/RTU/PLC/IED',
  'Safety Instrumented System/Protection Relay',
  'Engineering Workstation',
  'Human-Machine Interface',
  'Control Server',
  'Data Historian',
  'Input/Output Server',
  // Mobile
  'Android',
  'iOS',
] as const;

export type Platform = (typeof PLATFORMS)[number];

/** Sector slugs. */
export const SECTOR_SLUGS = [
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
] as const;

export type SectorSlug = (typeof SECTOR_SLUGS)[number];

/* ────────────────────────────────────────────────────────────────────────────
 * Derived pickers
 *
 * These lived in src/components/profile/ProfilePanel.tsx until the briefing
 * page needed them too. That module also builds a framework picker from
 * `SCF_FRAMEWORK_REGISTRY` (254 entries), so importing it purely to read two
 * option arrays dragged the whole registry into /profile's bundle — the same
 * class of cost this module was created to avoid for zod. ProfilePanel now
 * imports and re-exports them, so its public surface is unchanged.
 * ──────────────────────────────────────────────────────────────────────────── */

/** Presentation only: the 12 slugs come from `SECTOR_SLUGS`, these are the
 *  human labels for them. Typed as a total `Record` so adding a slug to the
 *  shared list without a label is a compile error. */
const SECTOR_LABELS: Record<SectorSlug, string> = {
  defense: 'Defense',
  education: 'Education',
  energy: 'Energy & Utilities',
  financial: 'Financial Services',
  government: 'Government',
  healthcare: 'Healthcare',
  manufacturing: 'Manufacturing',
  media: 'Media',
  retail: 'Retail',
  technology: 'Technology',
  telecommunications: 'Telecommunications',
  transportation: 'Transportation',
};

export const SECTOR_OPTIONS: ReadonlyArray<{ value: SectorSlug; label: string }> =
  SECTOR_SLUGS.map((slug) => ({ value: slug, label: SECTOR_LABELS[slug] }));

/**
 * The ICS half of `PLATFORMS`. Named and exported so the OT variant can take
 * this set directly (and the IT variant below its complement) instead of both
 * hand-maintaining a copy of the split that then drifts apart.
 *
 * `satisfies readonly Platform[]` is the guard: if ATT&CK renames one of these
 * in `PLATFORMS`, this list stops compiling instead of quietly excluding
 * nothing from the IT picker.
 */
export const ICS_PLATFORMS = [
  'Field Controller/RTU/PLC/IED',
  'Safety Instrumented System/Protection Relay',
  'Engineering Workstation',
  'Human-Machine Interface',
  'Control Server',
  'Data Historian',
  'Input/Output Server',
] as const satisfies readonly Platform[];

const ICS_PLATFORM_SET: ReadonlySet<string> = new Set<string>(ICS_PLATFORMS);

/** Enterprise + mobile platforms — `PLATFORMS` minus the ICS values. */
export const IT_PLATFORMS: Platform[] = PLATFORMS.filter((p) => !ICS_PLATFORM_SET.has(p));

/** The complement, for the OT variant. Derived here so the two never diverge. */
export const OT_PLATFORMS: Platform[] = PLATFORMS.filter((p) => ICS_PLATFORM_SET.has(p));
