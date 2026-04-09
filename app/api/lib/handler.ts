import { NextResponse } from 'next/server';

export function jsonResponse(data: unknown, cacheTtl?: number) {
  const headers: Record<string, string> = {};
  if (cacheTtl) {
    headers['Cache-Control'] = `public, s-maxage=${cacheTtl}, stale-while-revalidate=86400`;
  }
  return NextResponse.json(data, { headers });
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
