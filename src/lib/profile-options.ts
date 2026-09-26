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

/* ────────────────────────────────────────────────────────────────────────────
 * ATT&CK platforms, BY DOMAIN
 *
 * The three lists below are the authoritative per-domain platform vocabularies,
 * measured against production 2026-09-26 over live (non-revoked, non-deprecated)
 * techniques. `PLATFORMS` is assembled FROM them rather than the other way
 * round, so a picker built for a domain cannot offer a value that domain has no
 * technique for — the defect this replaces (see `IT_PLATFORMS` below).
 * ──────────────────────────────────────────────────────────────────────────── */

/**
 * enterprise-attack. All eleven match >=1 live technique: Windows 474,
 * macOS 356, Linux 355, ESXi 117, IaaS 104, Network Devices 100, PRE 96,
 * Office Suite 78, SaaS 70, Identity Provider 48, Containers 48.
 *
 * 'Network', 'Google Workspace' and 'Azure AD' were removed in an earlier pass
 * (0 live techniques each) and ESXi / Network Devices added — they previously
 * 400'd. Order is by live technique count, not alphabetical: this list is
 * rendered straight into a picker and the platforms most visitors defend
 * should not be the ones they have to scroll for.
 */
export const ENTERPRISE_PLATFORMS = [
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
] as const;

/**
 * mobile-attack. Measured: Android 122 live techniques, iOS 89 — and ZERO
 * enterprise techniques each.
 *
 * That zero is the whole point of this list existing. `IT_PLATFORMS` used to be
 * "PLATFORMS minus the seven ICS values", which left Android and iOS in the
 * picker offered to a visitor whose domain is pinned to enterprise-attack.
 * Selecting either produced an empty pool, the assembler's `platformDropped`
 * fallback fired, and the visitor's only environment answer was silently
 * discarded — a question that could not affect the result, which is the same
 * defect as offering a sector question on the OT path.
 */
export const MOBILE_PLATFORMS = ['Android', 'iOS'] as const;

/**
 * ics-attack. Measured: every one of these seven matches ZERO live techniques —
 * Control Server 0, Data Historian 0, Engineering Workstation 0, Field
 * Controller/RTU/PLC/IED 0, Human-Machine Interface 0, Input/Output Server 0,
 * Safety Instrumented System/Protection Relay 0.
 *
 * ATT&CK for ICS does not model platforms at all: every live ICS technique
 * carries either the literal platform 'None' (73 techniques) or no platforms
 * array whatsoever (24). Filtering an ICS pool by any of these seven returns an
 * empty pool, silently.
 *
 * So there is NO OT platform picker and no `OT_PLATFORMS` export. The OT path
 * ranks on ATT&CK assets (A0001-A0018) and Purdue levels instead — see the OT
 * branch of app/api/v1/profile/route.ts. These seven stay in `PLATFORMS` ONLY
 * because they are still legal API input and dropping them would 400 a URL that
 * used to work; nothing may ever OFFER them.
 *
 * atlas-attack is absent from this file deliberately: measured, all 155 live
 * ATLAS techniques carry no platforms array at all, so its picker is empty and
 * `PLATFORMS_BY_DOMAIN` says so with an empty list rather than a named one.
 */
export const ICS_PLATFORMS = [
  'Field Controller/RTU/PLC/IED',
  'Safety Instrumented System/Protection Relay',
  'Engineering Workstation',
  'Human-Machine Interface',
  'Control Server',
  'Data Historian',
  'Input/Output Server',
] as const;

/**
 * Every platform the API will accept — the union of the three lists above, in
 * that order. ASSEMBLED, never hand-maintained: `validate.ts` builds
 * `platformSchema` from this, so a value that is legal input but belongs to no
 * domain list is now impossible by construction.
 */
export const PLATFORMS = [
  ...ENTERPRISE_PLATFORMS,
  ...MOBILE_PLATFORMS,
  ...ICS_PLATFORMS,
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
 * `SCF_FRAMEWORK_REGISTRY` (32 entries — not the 254 this comment claimed for
 * a while; `grep -c framework_key` on src/lib/scf-framework-registry.ts is
 * 32), so importing it purely to read two option arrays dragged the whole
 * registry into /profile's bundle — the same class of cost this module was
 * created to avoid for zod. ProfilePanel now imports and re-exports them, so
 * its public surface is unchanged, and the registry itself sits behind a
 * `next/dynamic` boundary there.
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
 * The platform picker for one ATT&CK domain — the ONLY sanctioned way to build
 * one.
 *
 * Keyed by the four values of `VALID_DOMAINS` in app/api/v1/lib/validate.ts.
 * `ics-attack` and `atlas-attack` are deliberately EMPTY, and that is a
 * measured fact rather than a gap: no live ICS technique carries any of the 20
 * platform values (73 carry the literal 'None', 24 carry none at all), and all
 * 155 live ATLAS techniques carry no platforms array. A domain whose list is
 * empty must be asked a different question entirely — which is exactly what the
 * OT path does with assets and Purdue levels — never offered an empty picker,
 * and never offered another domain's list.
 */
export const PLATFORMS_BY_DOMAIN: Readonly<Record<string, readonly Platform[]>> = {
  'enterprise-attack': ENTERPRISE_PLATFORMS,
  'mobile-attack': MOBILE_PLATFORMS,
  'ics-attack': [],
  'atlas-attack': [],
};

/**
 * Platforms for a domain, or an empty list for a domain that has none (and for
 * an unrecognised one — a bad `?domain=` is the API's 400 to give, not a
 * reason for a picker to guess).
 */
export function platformsForDomain(domain: string | null | undefined): readonly Platform[] {
  if (!domain) return [];
  return PLATFORMS_BY_DOMAIN[domain] ?? [];
}

/**
 * The IT panel's picker. The panel pins `domain: 'enterprise-attack'`, so this
 * is that domain's list and nothing else.
 *
 * It was `PLATFORMS` minus the seven ICS values, which is not the same thing:
 * that subtraction left Android and iOS in a picker whose domain is pinned to
 * enterprise, where both match ZERO techniques. Anyone who answered the one
 * environment question with "iOS" got an empty pool, the `platformDropped`
 * fallback, and their answer thrown away without being told. Deriving the list
 * from the domain is what makes that unrepresentable.
 *
 * There is deliberately no `OT_PLATFORMS` counterpart any more — see
 * `ICS_PLATFORMS` above.
 */
export const IT_PLATFORMS: readonly Platform[] = ENTERPRISE_PLATFORMS;
