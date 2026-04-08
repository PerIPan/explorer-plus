import { timingSafeEqual } from 'crypto';
import type { VercelRequest, VercelResponse } from '@vercel/node';

/**
 * Verify CRON_SECRET for cron handler endpoints.
 * Vercel sends Authorization: Bearer <CRON_SECRET> to cron endpoints.
 * Returns true if authorized, false if response was already sent.
 */
export function verifyCronAuth(req: VercelRequest, res: VercelResponse): boolean {
  const cronSecret = process.env.CRON_SECRET;
  if (!cronSecret) {
    // In development without CRON_SECRET, allow through
    if (process.env.NODE_ENV === 'development') return true;
    res.status(500).json({ error: 'Server misconfigured' });
    return false;
  }
  const provided = String(req.headers['authorization'] ?? req.headers['x-cron-secret'] ?? '');
  const expected1 = `Bearer ${cronSecret}`;
  const expected2 = cronSecret;
  const safeEqual = (a: string, b: string): boolean => {
    if (a.length !== b.length) return false;
    return timingSafeEqual(Buffer.from(a), Buffer.from(b));
  };
  if (!safeEqual(provided, expected1) && !safeEqual(provided, expected2)) {
    res.status(401).json({ error: 'Unauthorized' });
    return false;
  }
  return true;
}
