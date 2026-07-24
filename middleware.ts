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

/** A path segment is "dynamic" (an id/name) rather than a fixed sub-resource. */
function isDynamic(seg: string): boolean {
  return /\d/.test(seg) || /[A-Z]/.test(seg) || seg.includes('%') || seg.length > 24;
}

/**
 * Collapse a request path to a stable, low-cardinality endpoint key.
 * Only /api/v1/* is counted; keep at most two segments, with dynamic ids → :id.
 *   /api/v1/cves/CVE-2024-1234/packages -> /api/v1/cves/:id
 *   /api/v1/feed/reports                -> /api/v1/feed/reports
 *   /api/v1/packages/npm/left-pad       -> /api/v1/packages/npm
 */
function normalizeEndpoint(pathname: string): string | null {
  if (!pathname.startsWith('/api/v1/') && pathname !== '/api/v1') return null;
  const rest = pathname.slice('/api/v1'.length).replace(/^\/+|\/+$/g, '');
  if (!rest) return '/api/v1';
  const segs = rest.split('/');
  let key = '/api/v1/' + segs[0];
  if (segs[1]) key += '/' + (isDynamic(segs[1]) ? ':id' : segs[1]);
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
      VALUES (${endpoint}, CURRENT_DATE, 1)
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
