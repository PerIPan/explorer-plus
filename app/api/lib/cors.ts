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

function restrictedHeaders(origin: string | null): Record<string, string> {
  const allowed = origin && ALLOWED_ORIGINS.has(origin) ? origin : 'null';
  return {
    'Access-Control-Allow-Origin': allowed,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Vary': 'Origin',
  };
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
