import { timingSafeEqual } from 'crypto';
import { NextRequest, NextResponse } from 'next/server';

/**
 * Verify CRON_SECRET for cron handler endpoints.
 * Vercel sends Authorization: Bearer <CRON_SECRET> to cron endpoints.
 * Returns null if authorized, or a NextResponse to send back if not.
 */
export function verifyCronAuth(req: NextRequest): NextResponse | null {
  const cronSecret = process.env.CRON_SECRET;
  if (!cronSecret) {
    // In development without CRON_SECRET, allow through
    if (process.env.NODE_ENV === 'development') return null;
    return NextResponse.json({ error: 'Server misconfigured' }, { status: 500 });
  }
  const provided = String(req.headers.get('authorization') ?? req.headers.get('x-cron-secret') ?? '');
  const expected1 = `Bearer ${cronSecret}`;
  const expected2 = cronSecret;
  const safeEqual = (a: string, b: string): boolean => {
    if (a.length !== b.length) return false;
    return timingSafeEqual(Buffer.from(a), Buffer.from(b));
  };
  if (!safeEqual(provided, expected1) && !safeEqual(provided, expected2)) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }
  return null;
}
