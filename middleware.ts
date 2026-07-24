import { NextResponse } from 'next/server';
import type { NextRequest, NextFetchEvent } from 'next/server';
import { neon } from '@neondatabase/serverless';

// ---------------------------------------------------------------------------
// API usage counting
// ---------------------------------------------------------------------------
// Every /api/v1/* request is counted once here (the routes share no path-aware
// wrapper, so middleware is the single choke point). We write a daily, per-
// normalized-endpoint counter to the `api_usage` table via a non-blocking
// UPSERT (event.waitUntil), so it adds no latency to the response.
//
// Cost note: this is one tiny UPSERT against the same Neon DB the request is
// already querying — a marginal add, not a new wake-up. IDs are collapsed to
// ':id' so the row count stays bounded.

const conn = process.env.DATABASE_URL || process.env.POSTGRES_URL || '';
// The neon() HTTP driver only talks to Neon hosts — skip locally (localhost PG).
const usageEnabled = /neon\.tech/.test(conn);
const sql = usageEnabled ? neon(conn) : null;
if (conn && !usageEnabled) {
  // Make an accidental disable (e.g. host rotation to a non-Neon provider) visible.
  console.warn('[api_usage] connection host is not a Neon endpoint — API usage counting is disabled.');
}

/**
 * Known *static* second path segments per top-level resource, derived from the
 * app/api/v1 route tree (the literal sub-folders, not the [param] ones). Any
 * second segment NOT listed here is treated as a dynamic id and collapsed to
 * ":id". This keeps row cardinality bounded by the route shape rather than by a
 * string-shape guess — critical because e.g. /applications/<vendor> slugs are
 * lowercase and would otherwise each spawn a permanent row.
 * NOTE: keep in sync when adding static sub-routes under these resources.
 */
const STATIC_CHILDREN: Record<string, Set<string>> = {
  feed: new Set(['atomic', 'intelligence', 'iocs', 'reports', 'sigma', 'status', 'vt-lookup']),
  frameworks: new Set(['by-techniques', 'cloud-controls', 'csf', 'detection', 'engage', 'iso27001', 'nist', 'owasp', 'react', 'status', 'technique', 'veris']),
  compliance: new Set(['frameworks', 'groups', 'sectors', 'software', 'tactics', 'techniques']),
  home: new Set(['recent-affected']),
};

/**
 * Collapse a request path to a stable, low-cardinality endpoint key.
 * Only /api/v1/* is counted; keep at most two segments, dynamic ids → :id.
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

function countUsage(request: NextRequest, event: NextFetchEvent) {
  if (!sql) return;
  // Don't count CORS preflights / HEAD probes — they aren't real data reads.
  if (request.method === 'OPTIONS' || request.method === 'HEAD') return;
  const endpoint = normalizeEndpoint(request.nextUrl.pathname);
  if (!endpoint) return;
  event.waitUntil(
    sql`
      INSERT INTO api_usage (endpoint, day, count)
      VALUES (${endpoint}, (now() AT TIME ZONE 'utc')::date, 1)
      ON CONFLICT (endpoint, day)
      DO UPDATE SET count = api_usage.count + 1, updated_at = now()
    `.catch((err) => {
      // Never let counting failures affect the API response.
      console.error('api_usage upsert failed:', err);
    }),
  );
}

// ---------------------------------------------------------------------------

export function middleware(request: NextRequest, event: NextFetchEvent) {
  // API routes: count usage, pass through untouched (no CSP needed on JSON).
  if (request.nextUrl.pathname.startsWith('/api/')) {
    countUsage(request, event);
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
  // Page routes (for CSP) + the public v1 API (for usage counting).
  matcher: ['/((?!api|_next/static|_next/image|favicon|.*\\..*).*)', '/api/v1/:path*'],
};
