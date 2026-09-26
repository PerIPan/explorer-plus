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
 * Split a comma-separated list param into its members. Blank entries are
 * dropped, so `platforms=` and `platforms=,,` both mean "no constraint" rather
 * than a constraint on the empty string — matching `csvMembers` on the
 * assembler, which preprocesses the same shapes to `undefined`.
 *
 * One function for `platforms`, `assets` and `purdue_levels`: the assembler
 * normalises all three through a single shared preprocessor, and three
 * hand-copied splitters on this side is three chances to drift from it.
 *
 * @param {string | null | undefined} raw
 * @returns {string[]}
 */
export function parseCsvParam(raw) {
  if (typeof raw !== 'string') return [];
  return raw.split(',').map((s) => s.trim()).filter(Boolean);
}

/**
 * `?platforms=` specifically. Kept as a named export because it is what the IT
 * briefing calls and what this module's tests pin; it is `parseCsvParam` under
 * a name that says which param.
 *
 * @param {string | null | undefined} rawPlatforms
 * @returns {string[]}
 */
export function parsePlatforms(rawPlatforms) {
  return parseCsvParam(rawPlatforms);
}

/**
 * Build the assembler's query string: ONLY the parameters
 * `GET /api/v1/profile` reads, in a fixed order, so unrelated params the app
 * carries around (`entity`, `tab`, …) neither reach the API nor fragment the
 * react-query cache key.
 *
 * `domain` is ALWAYS written. A non-null value goes through as itself; the
 * `null` that `resolveProfileDomain` returns for an explicit all-domains request
 * is written as the literal `all`, which is now what the assembler's
 * `profileDomainSchema` expects for that case.
 *
 * It used to be OMITTED for all-domains, which worked only because an absent
 * `?domain=` happened to mean "no filter" at the API. It no longer does: the
 * assembler DEFAULTS an absent domain to enterprise-attack (a public v1 API must
 * not hand out a silently mixed pool). Omitting it would therefore have quietly
 * converted the visitor's explicit "all domains" into "enterprise only" while
 * the page went on disclosing a mixed pool — a worse lie than the one the
 * default was added to fix. `undefined`, meaning a caller that never resolved a
 * domain at all, is still omitted and still picks up the API's default.
 *
 * `assets` and `levels` are the OT path's answers. Note the NAME CHANGE across
 * the boundary: the page URL carries `?purdue_levels=` (which is what the
 * telemetry row calls the field, and what reads as a question rather than an
 * abbreviation), while the API param is `?levels=`, which is what
 * `profileQuerySchema` validates. The translation happens HERE, once, rather
 * than being spelled either way in two views.
 *
 * `sort` is optional. The OT engine ranks Band A on exposure by definition and
 * exposes no sort option at all, so sending a sort key it will ignore would put
 * a parameter in the URL that cannot affect the answer.
 *
 * Empty lists are omitted rather than written blank, for the same reason the
 * page URL builder omits them: a blank param is indistinguishable from
 * "answered with nothing", and on the OT path that distinction is the whole
 * difference between `no-assets` and `empty-selection`.
 *
 * @param {Object} input
 * @param {string | null | undefined} [input.sector]
 * @param {string[]} [input.platforms]
 * @param {string[]} [input.assets] ATT&CK ICS asset ids (A0001-A0018)
 * @param {string[]} [input.levels] Purdue level keys, written as `levels`
 * @param {string} [input.sort] omitted entirely when absent
 * @param {string | null} input.domain already resolved by `resolveProfileDomain`
 * @returns {string} a query string with no leading `?`
 */
export function buildProfileApiQuery({ sector, platforms = [], assets = [], levels = [], sort, domain }) {
  const p = new URLSearchParams();
  if (sector) p.set('sector', sector);
  if (platforms.length > 0) p.set('platforms', platforms.join(','));
  if (assets.length > 0) p.set('assets', assets.join(','));
  if (levels.length > 0) p.set('levels', levels.join(','));
  if (sort) p.set('sort', sort);
  if (domain) p.set('domain', domain);
  else if (domain === null) p.set('domain', ALL_DOMAINS);
  return p.toString();
}
