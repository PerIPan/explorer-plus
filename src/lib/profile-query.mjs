// src/lib/profile-query.mjs — pure, no React, no DOM. Tested by
// scripts/lib/profile-query.test.mjs.
//
// The READ side of the briefing's URL contract. src/lib/profile-url.mjs
// builds `/profile?…` on the Apply path; this resolves whatever actually
// arrives — a bare `/profile`, a pasted link, a back-button landing, a
// control change — into the query the assembler is called with.
//
// It exists because the one rule that matters here was previously an inline
// `if (domain)` in the view, where nothing could pin it and a missing domain
// was invisible. See `resolveProfileDomain`.

/** The site-wide domain dropdown's cross-domain option. NOT an API value. */
export const ALL_DOMAINS = 'all';

/**
 * @typedef {Object} ResolvedDomain
 * @property {string | null} domain
 *   What to send as `?domain=`. `null` ONLY for an explicit all-domains
 *   request — never merely because the parameter was absent.
 * @property {boolean} allDomains
 *   True when the visitor explicitly asked for every domain at once, so the
 *   page can disclose that the pool is mixed rather than pretend it is not.
 */

/**
 * Resolve the domain filter for one briefing.
 *
 * An ABSENT `domain` must never reach the assembler. It reads
 * `AND ($2::text IS NULL OR t.domain = $2)`, so omitting the parameter is not
 * "enterprise" — it is NO FILTER AT ALL, and the briefing silently ranks
 * enterprise, mobile, ICS and ATLAS techniques together under a single
 * sector's name. Measured on production 2026-09-25: the `energy` pool of 219
 * is 205 enterprise + 12 ics-attack + 2 mobile-attack. Mobile and ICS
 * techniques hold essentially no CVE/KEV/EPSS evidence, so they enter as
 * permanent zeroes that still consume band slots and still dilute lift.
 *
 * `'all'` is the single legitimate no-filter case: the site-wide dropdown can
 * put it in the URL, it would 400 if forwarded (it is not one of the four
 * `VALID_DOMAINS`), and silently coercing it to the default would overrule a
 * choice the visitor actually made. It resolves to `domain: null` WITH the
 * flag, so the caller discloses it instead of hiding it.
 *
 * @param {string | null | undefined} rawDomain the `?domain=` value, if any
 * @param {string} defaultDomain passed in (not imported) to keep this module
 *   free of the 'use client' DomainContext that owns the constant
 * @returns {ResolvedDomain}
 */
export function resolveProfileDomain(rawDomain, defaultDomain) {
  const raw = typeof rawDomain === 'string' ? rawDomain.trim() : '';
  if (raw === ALL_DOMAINS) return { domain: null, allDomains: true };
  return { domain: raw === '' ? defaultDomain : raw, allDomains: false };
}

/**
 * Split a `?platforms=` value into its members. Blank entries are dropped, so
 * `platforms=` and `platforms=,,` both mean "no constraint" rather than a
 * constraint on the empty string — matching `platformsParam` on the
 * assembler, which preprocesses the same shapes to `undefined`.
 *
 * @param {string | null | undefined} rawPlatforms
 * @returns {string[]}
 */
export function parsePlatforms(rawPlatforms) {
  if (typeof rawPlatforms !== 'string') return [];
  return rawPlatforms.split(',').map((s) => s.trim()).filter(Boolean);
}

/**
 * Build the assembler's query string: ONLY the four parameters
 * `GET /api/v1/profile` reads, in a fixed order, so unrelated params the app
 * carries around (`entity`, `tab`, …) neither reach the API nor fragment the
 * react-query cache key.
 *
 * `domain` is written whenever it is non-null — i.e. always, except for the
 * explicit all-domains case above.
 *
 * @param {Object} input
 * @param {string | null | undefined} input.sector
 * @param {string[]} [input.platforms]
 * @param {string} input.sort
 * @param {string | null} input.domain already resolved by `resolveProfileDomain`
 * @returns {string} a query string with no leading `?`
 */
export function buildProfileApiQuery({ sector, platforms = [], sort, domain }) {
  const p = new URLSearchParams();
  if (sector) p.set('sector', sector);
  if (platforms.length > 0) p.set('platforms', platforms.join(','));
  p.set('sort', sort);
  if (domain) p.set('domain', domain);
  return p.toString();
}
