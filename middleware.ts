import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { DOCS_PROBE_HEADER } from './src/lib/site';

// ---------------------------------------------------------------------------
// API usage counting (part 1 of 2)
// ---------------------------------------------------------------------------
// We count every /api/v1/* request that actually reaches the origin (a cache
// MISS). Middleware runs *before* the CDN cache and can't tell a hit from a
// miss, so it does NOT write anything here — it only tags the request with a
// normalized endpoint header. The counting write happens at the origin, in
// jsonResponse() (see app/api/lib/handler.ts, part 2), which only runs on a
// miss. Net effect: CDN hits are free (no Neon wake), and every counted
// request is one that already hit the server.

/**
 * Known *static* second path segments per top-level resource, derived from the
 * app/api/v1 route tree (literal sub-folders, not [param] ones). Any second
 * segment NOT listed here is a dynamic id and collapses to ":id", so row
 * cardinality is bounded by route shape (e.g. /applications/<vendor> -> :id).
 * NOTE: keep in sync when adding static sub-routes under these resources.
 */
const STATIC_CHILDREN: Record<string, Set<string>> = {
  feed: new Set(['atomic', 'intelligence', 'iocs', 'reports', 'sigma', 'status', 'vt-lookup']),
  frameworks: new Set(['by-techniques', 'cloud-controls', 'csf', 'detection', 'engage', 'iso27001', 'nist', 'owasp', 'purdue', 'react', 'status', 'technique', 'veris']),
  compliance: new Set(['frameworks', 'groups', 'sectors', 'software', 'tactics', 'techniques']),
  home: new Set(['recent-affected']),
  profile: new Set(['submit']),
};

/** Normalized endpoints to NOT count — internal/UI-noise, not real API usage. */
const EXCLUDED_ENDPOINTS = new Set(['/api/v1/site-health']);

/**
 * Collapse a request path to a stable, low-cardinality endpoint key.
 *   /api/v1/cves/CVE-2024-1234/packages -> /api/v1/cves/:id
 *   /api/v1/applications/microsoft/...  -> /api/v1/applications/:id
 *   /api/v1/feed/reports                -> /api/v1/feed/reports
 */
function normalizeEndpoint(pathname: string): string | null {
  if (!pathname.startsWith('/api/v1/') && pathname !== '/api/v1') return null;
  const rest = pathname.slice('/api/v1'.length).replace(/^\/+|\/+$/g, '');
  if (!rest) return '/api/v1';
  const segs = rest.split('/');
  let key = '/api/v1/' + segs[0];
  if (segs[1]) {
    const staticSet = STATIC_CHILDREN[segs[0]];
    key += '/' + (staticSet?.has(segs[1]) ? segs[1] : ':id');
  }
  return key;
}

// ---------------------------------------------------------------------------

export function middleware(request: NextRequest) {
  // API routes (only /api/v1/* reaches here per the matcher): tag with the
  // normalized endpoint so the origin can count it. No DB work here.
  if (request.nextUrl.pathname.startsWith('/api/')) {
    const method = request.method;
    // Skip CORS preflights / HEAD probes — not real data reads. And skip the
    // documentation pages' own live-Run calls (/open-apis' Run button): they are
    // a reader pressing a button in our docs, not API consumption, and 61 of
    // these routes set no cacheTtl, so counting them would make the docs page
    // the top endpoint in our own analytics.
    /**
     * `x-usage-endpoint` is a TRUSTED header: handler.ts writes it verbatim into
     * api_usage(endpoint, day), where `endpoint` is half the primary key and an
     * unbounded `text` column. So every path out of this branch has to hand the
     * route a value the CLIENT did not choose — which means deleting any copy
     * they sent UP FRONT, before the skip conditions, because three of them
     * return without setting one: the docs probe, OPTIONS/HEAD, and anything in
     * EXCLUDED_ENDPOINTS.
     *
     * Left unstripped, `curl -H 'x-usage-endpoint: <anything>' .../site-health`
     * inserts <anything> as a new primary-key row on the repo's only
     * unauthenticated write — precisely the unbounded cardinality that
     * normalizeEndpoint() exists to prevent, reached by skipping it.
     */
    const headers = new Headers(request.headers);
    headers.delete('x-usage-endpoint');

    const endpoint =
      method === 'OPTIONS' || method === 'HEAD' || request.headers.get(DOCS_PROBE_HEADER)
        ? null
        : normalizeEndpoint(request.nextUrl.pathname);
    if (endpoint && !EXCLUDED_ENDPOINTS.has(endpoint)) {
      headers.set('x-usage-endpoint', endpoint);
    }
    return NextResponse.next({ request: { headers } });
  }

  // Page routes: attach the per-request CSP nonce.
  const nonce = crypto.randomUUID();
  const isDev = process.env.NODE_ENV === 'development';
  const csp = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' https://va.vercel-scripts.com${isDev ? " 'unsafe-eval'" : ''}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    `connect-src 'self' https://*.vercel-insights.com https://va.vercel-scripts.com https://vitals.vercel-insights.com${isDev ? ' ws://localhost:* http://localhost:*' : ''}`,
    "font-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join('; ');

  const response = NextResponse.next();
  response.headers.set('Content-Security-Policy', csp);
  response.headers.set('x-nonce', nonce);
  return response;
}

export const config = {
  // Page routes (for CSP) + the public v1 API (to tag usage for origin counting).
  matcher: ['/((?!api|_next/static|_next/image|favicon|.*\\..*).*)', '/api/v1/:path*'],
};
