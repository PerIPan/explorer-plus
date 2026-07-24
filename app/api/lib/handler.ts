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
function recordUsage(): void {
  try {
    after(async () => {
      try {
        const endpoint = (await headers()).get('x-usage-endpoint');
        if (!endpoint) return;
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

export function jsonResponse(data: unknown, cacheTtl?: number) {
  recordUsage();
  const respHeaders: Record<string, string> = {};
  if (cacheTtl) {
    respHeaders['Cache-Control'] = `public, s-maxage=${cacheTtl}, stale-while-revalidate=86400`;
  }
  return NextResponse.json(data, { headers: respHeaders });
}

export function errorResponse(status: number, error: string, code: string) {
  return NextResponse.json({ error, code }, { status });
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
