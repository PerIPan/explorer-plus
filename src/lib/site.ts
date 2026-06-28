/**
 * Canonical site origin — single source of truth.
 *
 * Imported by layout (JSON-LD WebSite/Org `@id`), the technique page (JSON-LD
 * `url`/`isPartOf`), sitemap, and robots so a domain change can't silently
 * break the structured-data graph linkage. Override per-environment via
 * NEXT_PUBLIC_SITE_URL (e.g. preview deployments).
 */
export const SITE_URL = process.env.NEXT_PUBLIC_SITE_URL || 'https://mitre-explorer.org';
