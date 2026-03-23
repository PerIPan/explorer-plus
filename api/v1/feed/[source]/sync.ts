import type { VercelRequest, VercelResponse } from '@vercel/node';

// Import cron handlers
import otxHandler from '../../../cron/ingest-otx.js';
import abuseCh from '../../../cron/ingest-abuse-ch.js';
import cisaKev from '../../../cron/ingest-cisa-kev.js';
import rss from '../../../cron/ingest-rss.js';
import d3fend from '../../../cron/sync-d3fend.js';

const HANDLERS: Record<string, (req: VercelRequest, res: VercelResponse) => Promise<void>> = {
  otx: otxHandler,
  abuse_ch: abuseCh,
  cisa_kev: cisaKev,
  rss: rss,
  d3fend: d3fend,
};

export default async function handler(req: VercelRequest, res: VercelResponse) {
  // CORS
  const origin = process.env.VERCEL_PROJECT_PRODUCTION_URL
    ? `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}`
    : process.env.VERCEL_URL
    ? `https://${process.env.VERCEL_URL}`
    : 'http://localhost:5173';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }

  // Auth via CRON_SECRET header — required in production
  const cronSecret = process.env.CRON_SECRET;
  if (!cronSecret) {
    res.status(500).json({ error: 'Server misconfigured: CRON_SECRET not set' });
    return;
  }
  const provided = req.headers['x-cron-secret'] ?? req.headers['authorization'];
  if (provided !== cronSecret && provided !== `Bearer ${cronSecret}`) {
    res.status(401).json({ error: 'Unauthorized', code: 'UNAUTHORIZED' });
    return;
  }

  const { source } = req.query;
  const sourceKey = Array.isArray(source) ? source[0] : source ?? '';

  const cronHandler = HANDLERS[sourceKey];
  if (!cronHandler) {
    res.status(404).json({
      error: `Unknown source: ${sourceKey}`,
      available: Object.keys(HANDLERS),
    });
    return;
  }

  try {
    await cronHandler(req, res);
  } catch (err) {
    console.error(`[sync/${sourceKey}]`, err);
    res.status(500).json({ error: 'Feed sync failed' });
  }
}
