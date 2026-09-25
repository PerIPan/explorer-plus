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
 * ATT&CK platforms. Values verified against production 2026-09-25: every entry
 * matches >=1 live technique. 'Network', 'Google Workspace' and 'Azure AD' were
 * removed (0 live techniques each) and ESXi/Network Devices added (117/100) —
 * they previously 400'd.
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
