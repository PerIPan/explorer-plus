import { NextRequest } from 'next/server';
import { errorResponse } from '../../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../../lib/cors';
import { NextResponse } from 'next/server';
import { verifyCronAuth } from '../../../../cron/lib/auth';

export { OPTIONS };

const VALID_SOURCES = ['otx', 'abuse_ch', 'cisa_kev', 'rss', 'd3fend', 'nvd', 'virustotal'];

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ source: string }> }
) {
  const { source: sourceKey } = await params;

  const authError = verifyCronAuth(req);
  if (authError) return authError;

  if (!VALID_SOURCES.includes(sourceKey)) {
    return withCors(errorResponse(404, 'Unknown source', 'NOT_FOUND'));
  }

  try {
    const cronUrl = new URL(`/api/cron/${sourceKey === 'abuse_ch' ? 'ingest-abuse-ch' : sourceKey === 'cisa_kev' ? 'ingest-cisa-kev' : sourceKey === 'virustotal' ? 'enrich-vt' : sourceKey === 'nvd' ? 'enrich-nvd' : sourceKey === 'd3fend' ? 'sync-d3fend' : `ingest-${sourceKey}`}`, req.nextUrl.origin);
    const cronRes = await fetch(cronUrl.toString(), {
      headers: { 'x-vercel-cron-secret': process.env.CRON_SECRET ?? '' },
    });
    const result = await cronRes.json();
    return withCors(NextResponse.json(result, { status: cronRes.status }));
  } catch (err) {
    console.error(`[sync/${sourceKey}]`, err);
    return withCors(errorResponse(500, 'Feed sync failed', 'SYNC_ERROR'));
  }
}
