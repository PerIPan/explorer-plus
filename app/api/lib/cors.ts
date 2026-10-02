import { NextRequest, NextResponse } from 'next/server';

// Public API endpoints: open CORS because data is public threat intel and
// external A2A clients / browser dashboards may need cross-origin reads.
const CORS_HEADERS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Cron-Secret',
};

// Restricted endpoints (A2A) — only allow known origins to prevent
// cross-origin browser pages from silently consuming a victim's daily quota.
// Server-to-server callers don't care about CORS, so they're unaffected.
const ALLOWED_ORIGINS = new Set<string>([
  'https://mitre-explorer.org',
  'https://www.mitre-explorer.org',
]);

/**
 * A disallowed origin gets NO `Access-Control-Allow-Origin` header at all.
 *
 * This used to answer `Access-Control-Allow-Origin: null`, which is not a
 * refusal — `null` is a real serialised origin, sent by sandboxed iframes,
 * `data:` URLs and `file://` documents. Echoing it back grants exactly those
 * contexts the cross-origin read the allowlist exists to deny. Omitting the
 * header is the actual deny.
 *
 * `Vary: Origin` stays on every response, including the denials: the header set
 * depends on the request's Origin, so a cache must not serve one origin's
 * answer to another.
 *
 * Worth being clear about what this can and cannot do. CORS gates READING a
 * response, never SENDING the request — so it is not, by itself, protection for
 * a metered write. That job belongs to the `application/json` requirement on
 * each route: it makes a cross-origin POST non-simple, so the browser must
 * preflight, and the preflight is what this allowlist refuses. Without that
 * Content-Type check a page could post `text/plain`, consume a victim's daily
 * quota, and simply not care that it cannot read the reply.
 */
function restrictedHeaders(origin: string | null): Record<string, string> {
  const base: Record<string, string> = {
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Vary': 'Origin',
  };
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    base['Access-Control-Allow-Origin'] = origin;
  }
  return base;
}

/**
 * True when the body is declared as JSON.
 *
 * `req.json()` parses whatever bytes arrive regardless of Content-Type, so
 * without this check a cross-origin `text/plain` POST is a SIMPLE request: no
 * preflight, nothing for restrictedHeaders to refuse, and the write lands.
 * Requiring JSON forces the preflight that makes the allowlist load-bearing.
 *
 * Parameters after `;` are allowed (`application/json; charset=utf-8`).
 */
export function isJsonContentType(req: NextRequest): boolean {
  const ct = req.headers.get('content-type');
  if (!ct) return false;
  return ct.split(';')[0].trim().toLowerCase() === 'application/json';
}

export function corsOptions() {
  return new NextResponse(null, { status: 204, headers: CORS_HEADERS });
}

export function corsOptionsRestricted(req: NextRequest) {
  return new NextResponse(null, { status: 204, headers: restrictedHeaders(req.headers.get('origin')) });
}

export function withCors(response: NextResponse): NextResponse {
  Object.entries(CORS_HEADERS).forEach(([k, v]) => response.headers.set(k, v));
  return response;
}

export function withCorsRestricted(response: NextResponse, req: NextRequest): NextResponse {
  Object.entries(restrictedHeaders(req.headers.get('origin'))).forEach(([k, v]) =>
    response.headers.set(k, v),
  );
  return response;
}
