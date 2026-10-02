/**
 * The application catalogue's slug rule — ONE copy.
 *
 * `applications.normalized` holds a lowercase-alphanumerics-only slug per part,
 * produced by the CVE product ingest. Anything else 400s on
 * `/api/v1/applications/{vendor}/{product}`: `src/lib/tools/execute.ts` records
 * that keeping `-` and `_` rejected 2,430 of 7,206 catalogue entries —
 * log4j-core, iphone_os, federation-internals.
 *
 * It lived in three places: the ingest that writes the slugs
 * (scripts/sync-cve-products.mjs), the MCP tool layer that reads them
 * (src/lib/tools/execute.ts), and the CLI. A guard compared two of the three by
 * string-matching the regex literal, which both missed real drift (a `.slice()`
 * appended after it) and fired on cosmetics (`[^a-z\d]`, double quotes, a line
 * break). One module is the repo's own answer to that, so this is it.
 *
 * `.mjs` so the ingest scripts, the CLI package and the TypeScript app can all
 * import the same file.
 */

/**
 * Normalise one path part — a vendor or a product — to its catalogue slug.
 * @param {unknown} part
 * @returns {string} lowercase a-z0-9 only; empty string for null/undefined
 */
export function appSlug(part) {
  return String(part ?? '').toLowerCase().replace(/[^a-z0-9]/g, '');
}
