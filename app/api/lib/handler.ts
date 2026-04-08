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
