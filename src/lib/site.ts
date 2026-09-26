/**
 * Canonical site origin — single source of truth.
 *
 * Imported by layout (JSON-LD WebSite/Org `@id`), the technique page (JSON-LD
 * `url`/`isPartOf`), sitemap, and robots so a domain change can't silently
 * break the structured-data graph linkage. Override per-environment via
 * NEXT_PUBLIC_SITE_URL (e.g. preview deployments).
 */
export const SITE_URL = process.env.NEXT_PUBLIC_SITE_URL || 'https://mitre-explorer.org';

/**
 * Size of the agent tool catalogue (src/lib/tools/declarations.ts), quoted in
 * the UI in several places. A constant rather than a literal per site: the A2A
 * tab silently said "39 tools" for a while after the catalogue grew, and six
 * copies of a number is how that happens. Not derived from the catalogue itself
 * because importing it would pull ~31KB of tool descriptions into the browser
 * bundle. Keep in sync when adding or removing a tool.
 */
export const AGENT_TOOL_COUNT = 43;

/**
 * Size of the public REST catalogue (src/lib/api-catalog.ts), quoted in the
 * sidebar as `Open APIs (81)`.
 *
 * A constant for the same reason as AGENT_TOOL_COUNT: the catalogue is ~700
 * lines of endpoint descriptions, and importing it into the sidebar would put
 * all of it in the shell chunk on every page — /open-apis loads it, nothing
 * else needs to. `scripts/check-api-catalog.mjs` fails the build when this
 * number and API_CATALOG.length disagree, so it cannot drift silently.
 */
export const API_ENDPOINT_COUNT = 82;

/**
 * Marker header the API documentation pages set on every live-Run fetch.
 *
 * `middleware.ts` skips the `api_usage` tag when it is present. 61 of the 86
 * routes under /api/v1 set no `cacheTtl`, so every Run is a CDN miss — a Neon
 * wake plus an `api_usage` UPSERT — and without this the docs page would become
 * the top endpoint in our own API analytics within a day.
 *
 * Declared here rather than in `src/lib/api-catalog.ts` so `middleware.ts` can
 * import one constant instead of the whole catalogue (this module has no
 * imports; the catalogue is ~700 lines and runs on the edge for every request).
 */
export const DOCS_PROBE_HEADER = 'x-mitre-docs-probe';
