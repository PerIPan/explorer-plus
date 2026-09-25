// src/lib/profile-url.mjs — pure, no React, no DOM. Tested by
// scripts/lib/profile-url.test.mjs.
//
// Builds the URL that Apply navigates to. Kept out of useProfileState.ts so
// its guarantees can be pinned by fixture tests rather than asserted in a
// comment — in particular the `domain` rule below, which is a correctness
// requirement of the briefing page and not a formatting preference.

/** The briefing page. */
export const PROFILE_PATH = '/profile';

/**
 * Cap on values in any one list param. Mirrors `slugList`'s `.max(24)` in
 * src/lib/profile-submit-schema.mjs and `platformsParam` on the assembler —
 * over the cap the API 400s the whole request, so truncate here rather than
 * navigate the visitor to an error.
 */
export const MAX_LIST_VALUES = 24;

/**
 * A URL param carried from the panel's answers. An array becomes a
 * comma-separated list (the form `/profile` parses); a plain string is written
 * as-is; null/undefined/empty is omitted entirely — never written as a blank
 * param, because a blank is indistinguishable from "answered with nothing".
 *
 * @typedef {string | string[] | null | undefined} ProfileParamValue
 */

/**
 * @typedef {Object} ProfileUrlInput
 * @property {string | null} sector
 *   The load-bearing single-select answer. Omitted when null — `/profile`
 *   detects an absent sector and says so rather than inventing one.
 * @property {string} domain
 *   ATT&CK domain. ALWAYS written (see `buildProfileUrl`).
 * @property {Readonly<Record<string, ProfileParamValue>>} [params]
 *   Everything else the variant wants in the URL, keyed by param name — the
 *   IT variant passes `platforms`; the OT variant adds `assets` and
 *   `purdue_levels` without changing this signature.
 */

/**
 * @param {ProfileParamValue} value
 * @returns {string | null} the param value to write, or null to omit the param
 */
function normalize(value) {
  if (value == null) return null;
  if (Array.isArray(value)) {
    const cleaned = value.map((v) => String(v).trim()).filter(Boolean).slice(0, MAX_LIST_VALUES);
    return cleaned.length > 0 ? cleaned.join(',') : null;
  }
  const single = String(value).trim();
  return single.length > 0 ? single : null;
}

/**
 * Build `/profile?…` for one Apply.
 *
 * `domain` is written UNCONDITIONALLY, including when it equals the default.
 * On the homepage an absent `domain` is harmless — DomainContext resolves it
 * back to enterprise — but the assembler reads
 * `AND ($2::text IS NULL OR t.domain = $2)`, so on `/profile` an absent domain
 * means NO domain filter at all: the briefing would rank enterprise, mobile,
 * ICS and ATLAS techniques together, most of which have no Sigma or CVE
 * evidence to speak with, under a heading naming one sector. Omitting it is a
 * correctness bug, not a tidier URL.
 *
 * Param order is fixed — sector, then `params` in insertion order, then
 * domain — so the result is comparable in tests and stable in the address bar.
 *
 * @param {ProfileUrlInput} input
 * @returns {string}
 */
export function buildProfileUrl(input) {
  const search = new URLSearchParams();

  const sector = normalize(input.sector);
  if (sector) search.set('sector', sector);

  for (const [key, value] of Object.entries(input.params ?? {})) {
    if (key === 'sector' || key === 'domain') continue; // owned above/below
    const normalized = normalize(value);
    if (normalized) search.set(key, normalized);
  }

  const domain = normalize(input.domain);
  if (domain) search.set('domain', domain);

  const qs = search.toString();
  return qs ? `${PROFILE_PATH}?${qs}` : PROFILE_PATH;
}
