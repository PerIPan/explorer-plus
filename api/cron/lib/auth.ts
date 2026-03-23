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
  const provided = req.headers['authorization'] ?? req.headers['x-cron-secret'];
  if (provided !== `Bearer ${cronSecret}` && provided !== cronSecret) {
    res.status(401).json({ error: 'Unauthorized' });
    return false;
  }
  return true;
}
