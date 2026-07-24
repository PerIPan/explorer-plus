import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

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
  frameworks: new Set(['by-techniques', 'cloud-controls', 'csf', 'detection', 'engage', 'iso27001', 'nist', 'owasp', 'react', 'status', 'technique', 'veris']),
  compliance: new Set(['frameworks', 'groups', 'sectors', 'software', 'tactics', 'techniques']),
  home: new Set(['recent-affected']),
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
    // Skip CORS preflights / HEAD probes — not real data reads.
    const endpoint =
      method === 'OPTIONS' || method === 'HEAD'
        ? null
        : normalizeEndpoint(request.nextUrl.pathname);
    if (endpoint && !EXCLUDED_ENDPOINTS.has(endpoint)) {
      const headers = new Headers(request.headers);
      headers.set('x-usage-endpoint', endpoint);
      return NextResponse.next({ request: { headers } });
    }
    return NextResponse.next();
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
