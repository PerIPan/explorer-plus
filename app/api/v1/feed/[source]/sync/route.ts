import { NextRequest } from 'next/server';
import { errorResponse } from '../../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../../lib/cors';
import { NextResponse } from 'next/server';

export { OPTIONS };

// TODO: Cron handlers still use Vercel (req, res) signature.
// Once api/cron/*.ts are migrated to Next.js, update these imports.
// For now, the handler logic is inlined to return NextResponse.
const VALID_SOURCES = ['otx', 'abuse_ch', 'cisa_kev', 'rss', 'd3fend', 'nvd', 'virustotal'];

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ source: string }> }
) {
  const { source: sourceKey } = await params;

  // Auth via CRON_SECRET header — required in production
  const cronSecret = process.env.CRON_SECRET;
  if (!cronSecret) {
    return withCors(errorResponse(500, 'Server misconfigured: CRON_SECRET not set', 'CONFIG_ERROR'));
  }
  const provided = req.headers.get('x-cron-secret') ?? req.headers.get('authorization');
  if (provided !== cronSecret && provided !== `Bearer ${cronSecret}`) {
    return withCors(errorResponse(401, 'Unauthorized', 'UNAUTHORIZED'));
  }

  if (!VALID_SOURCES.includes(sourceKey)) {
    return withCors(errorResponse(404, 'Unknown source', 'NOT_FOUND'));
  }

  try {
    // Dynamic import from old api/cron handlers
    // These handlers still use Vercel (req, res) format — they need their own migration.
    // Until then, this endpoint returns a "not yet migrated" response.
    // To run syncs, use the original /api/v1/feed/[source]/sync endpoint.
    const handlerMap: Record<string, string> = {
      otx: '../../../../../../api/cron/ingest-otx.js',
      abuse_ch: '../../../../../../api/cron/ingest-abuse-ch.js',
      cisa_kev: '../../../../../../api/cron/ingest-cisa-kev.js',
      rss: '../../../../../../api/cron/ingest-rss.js',
      d3fend: '../../../../../../api/cron/sync-d3fend.js',
      nvd: '../../../../../../api/cron/enrich-nvd.js',
      virustotal: '../../../../../../api/cron/enrich-vt.js',
    };

    const handlerPath = handlerMap[sourceKey];
    if (!handlerPath) {
      return withCors(errorResponse(404, 'Unknown source', 'NOT_FOUND'));
    }

    // Note: The cron handlers use Vercel's (req, res) pattern.
    // This requires a compatibility shim until cron handlers are migrated.
    return withCors(
      NextResponse.json(
        { error: 'Cron handlers not yet migrated to Next.js route handlers. Use /api/v1/feed/[source]/sync instead.', code: 'NOT_MIGRATED' },
        { status: 501 },
      ),
    );
  } catch (err) {
    console.error(`[sync/${sourceKey}]`, err);
    return withCors(errorResponse(500, 'Feed sync failed', 'SYNC_ERROR'));
  }
}
