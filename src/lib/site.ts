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
export const AGENT_TOOL_COUNT = 42;
