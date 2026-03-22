import type { VercelRequest, VercelResponse } from '@vercel/node';

type Handler = (req: VercelRequest, res: VercelResponse) => Promise<void>;

interface HandlerOptions {
  cacheTtl?: number;
}

export function withHandler(handler: Handler, options?: HandlerOptions) {
  return async (req: VercelRequest, res: VercelResponse): Promise<void> => {
    const method = req.method ?? '';

    // CORS preflight — must be checked before the method allow-list so OPTIONS
    // returns 200 rather than 405.
    // Use production URL if available, fallback to deployment URL, then localhost
    const origin = process.env.VERCEL_PROJECT_PRODUCTION_URL
      ? `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}`
      : process.env.VERCEL_URL
        ? `https://${process.env.VERCEL_URL}`
        : 'http://localhost:5173';
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');

    if (method === 'OPTIONS') {
      res.status(200).end();
      return;
    }

    // Method check
    if (method !== 'GET' && method !== 'POST') {
      res.status(405).json({ error: 'Method not allowed', code: 'METHOD_NOT_ALLOWED' });
      return;
    }

    // Cache headers
    if (options?.cacheTtl) {
      res.setHeader(
        'Cache-Control',
        `public, s-maxage=${options.cacheTtl}, stale-while-revalidate=86400`,
      );
    }

    try {
      await handler(req, res);
    } catch (err) {
      console.error('API error:', err);
      res.status(500).json({ error: 'Internal server error', code: 'INTERNAL_ERROR' });
    }
  };
}
