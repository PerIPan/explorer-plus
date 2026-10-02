import { NextResponse, after } from 'next/server';
import { headers } from 'next/headers';
import { query } from '../v1/lib/db';

// ---------------------------------------------------------------------------
// API usage counting (part 2 of 2 — see middleware.ts for part 1)
// ---------------------------------------------------------------------------
// jsonResponse() runs only when a request reaches the origin (a CDN cache
// MISS), so counting here — instead of in middleware — means CDN hits are
// never counted and never wake Neon. after() defers the UPSERT until the
// response has flushed, so it never blocks or breaks the API response, and it
// reuses the node `pg` pool the route already used for its data query.
/** The exact shape middleware.ts's normalizeEndpoint() emits, and nothing else. */
const USAGE_ENDPOINT_KEY = /^\/api\/v1(\/[a-z0-9-]+(\/(:id|[a-z0-9-]+))?)?$/;

function recordUsage(): void {
  try {
    after(async () => {
      try {
        const endpoint = (await headers()).get('x-usage-endpoint');
        // Defence in depth. middleware.ts strips any client-supplied copy of
        // this header, so a value reaching here should always be one
        // normalizeEndpoint() produced — but this is the only unauthenticated
        // write in the API and the column is half a primary key, so it refuses
        // anything not shaped like such a key rather than trusting the hop.
        if (!endpoint || !USAGE_ENDPOINT_KEY.test(endpoint)) return;
        await query(
          `INSERT INTO api_usage (endpoint, day, count)
           VALUES ($1, (now() AT TIME ZONE 'utc')::date, 1)
           ON CONFLICT (endpoint, day)
           DO UPDATE SET count = api_usage.count + 1, updated_at = now()`,
          [endpoint],
        );
      } catch (err) {
        console.error('api_usage upsert failed:', err);
      }
    });
  } catch {
    // after() called outside a request scope — never happens for route
    // handlers, but stay defensive so counting can't break a response.
  }
}

/**
 * A non-JSON body that still counts and still caches.
 *
 * Everything public goes out through jsonResponse(), which calls recordUsage()
 * and sets Cache-Control. /api/v1/export/{entityType}?format=csv built a raw
 * NextResponse instead and so got neither: the heaviest response the API serves
 * (a whole entity table, serialised) was invisible to api_usage and uncacheable
 * at the CDN, while its own ?format=json sibling was counted and cached for an
 * hour. Every CSV request was a guaranteed origin hit.
 */
export function fileResponse(
  body: string,
  contentType: string,
  cacheTtl?: number,
  extraHeaders?: Record<string, string>,
) {
  recordUsage();
  const respHeaders: Record<string, string> = {
    'Content-Type': contentType,
    ...extraHeaders,
  };
  if (cacheTtl) {
    respHeaders['Cache-Control'] = `public, s-maxage=${cacheTtl}, stale-while-revalidate=86400`;
  }
  return new NextResponse(body, { status: 200, headers: respHeaders });
}

export function jsonResponse(data: unknown, cacheTtl?: number) {
  recordUsage();
  const respHeaders: Record<string, string> = {};
  if (cacheTtl) {
    respHeaders['Cache-Control'] = `public, s-maxage=${cacheTtl}, stale-while-revalidate=86400`;
  }
  return NextResponse.json(data, { headers: respHeaders });
}

export function errorResponse(
  status: number,
  error: string,
  code: string,
  cacheTtl?: number,
) {
  const headers: Record<string, string> = {};
  if (cacheTtl) {
    // Errors are uncacheable by default, which is right for a 400 (the next
    // caller's input differs) and wrong for an expensive timeout: a 500 with no
    // Cache-Control means every retry of the SAME url re-runs the same
    // multi-second query at the origin. Opt in per call site, only where the
    // failure is a property of the request rather than of the client.
    headers['Cache-Control'] = `public, s-maxage=${cacheTtl}, stale-while-revalidate=0`;
  }
  return NextResponse.json({ error, code }, { status, headers });
}

/**
 * Wrap an API route handler with try/catch that returns JSON errors.
 * Replaces the old `withHandler` pattern from Vercel serverless.
 */
export function withErrorHandler(
  handler: (...args: Parameters<typeof fetch>) => Promise<NextResponse>,
) {
  return async (...args: Parameters<typeof fetch>): Promise<NextResponse> => {
    try {
      return await handler(...args);
    } catch (err) {
      console.error('API error:', err);
      return NextResponse.json(
        { error: 'Internal server error', code: 'INTERNAL_ERROR' },
        { status: 500 },
      );
    }
  };
}
