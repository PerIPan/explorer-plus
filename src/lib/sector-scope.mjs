/**
 * Which sector scope applies to a page — the one rule, in one place.
 *
 * Two files have to agree about this and sat ten directories apart:
 * `app/providers.tsx` decides whether to WRITE the stored sector into the URL,
 * and `src/contexts/SectorContext.tsx` decides which sector the page then
 * FILTERS BY. They disagreed in a way nothing could catch by reading either
 * one: the Threat Profile's evidence counts are computed with no sector scope
 * at all, and their links inherited the sector the profile itself had just
 * stored, so every count pointed at a strictly smaller list — "29 CVEs" landing
 * on a page headed "1-17 of 17", and a "1" landing on "No CVEs found."
 *
 * Extracted as plain `.mjs` so it is testable without a DOM, in the same shape
 * as src/lib/profile-rank.mjs and src/lib/profile-url.mjs.
 */

/** The one path where a remembered sector must never be re-applied. */
export const PROFILE_PATH = '/profile';

/** The query parameter a link uses to say "this list has no sector scope". */
export const ALL_SECTORS_PARAM = 'allSectors';

/**
 * The sector a page should filter by.
 *
 * `allSectors` wins over both the URL and the cache: a link that declares no
 * sector scope is answering on behalf of the page it points at, and the whole
 * point is that nothing downstream re-adds one.
 *
 * @param {{ urlSector?: string|null, storedSector?: string|null, allSectors?: boolean }} input
 * @returns {string|null} the sector slug, or null for "all sectors"
 */
export function resolveSector({ urlSector = null, storedSector = null, allSectors = false } = {}) {
  if (allSectors) return null;
  return urlSector || storedSector || null;
}

/**
 * Whether the stored sector should be written into this URL.
 *
 * Takes `hasSectorParam` rather than the value, deliberately: the caller tests
 * presence (`params.has`), so `?sector=` with an empty value counts as "the URL
 * has spoken" and is left alone rather than being filled in from the cache.
 *
 * @param {{ hasSectorParam?: boolean, storedSector?: string|null, allSectors?: boolean, pathname?: string }} input
 * @returns {boolean}
 */
export function shouldInjectStoredSector({
  hasSectorParam = false, storedSector = null, allSectors = false, pathname = '',
} = {}) {
  if (!storedSector) return false;
  if (hasSectorParam) return false;
  if (allSectors) return false;
  // The briefing is not a filter: it is a claim about who the reader is, headed
  // with the sector's name. A bare /profile must stay bare so the page can say
  // it has no sector, rather than render a full briefing for one chosen in some
  // earlier minute on some other page.
  return pathname !== PROFILE_PATH;
}
