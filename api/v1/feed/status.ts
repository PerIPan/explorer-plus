import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../lib/db';
import { withHandler } from '../lib/middleware';

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const result = await query<{
    source: string;
    status: string;
    started_at: string;
    completed_at: string | null;
    records_inserted: number;
    records_skipped: number;
    error_message: string | null;
  }>(
    `SELECT DISTINCT ON (source)
       source,
       status,
       started_at,
       completed_at,
       records_inserted,
       records_skipped,
       error_message
     FROM feed_sync_log
     ORDER BY source, started_at DESC`,
  );

  const data = result.rows.map((row) => ({
    source: row.source,
    lastSync: row.completed_at ?? row.started_at,
    status: row.status,
    recordsInserted: row.records_inserted,
    recordsSkipped: row.records_skipped,
    error: row.error_message ?? null,
    metadata: null,
  }));

  res.status(200).json({ data });
}

export default withHandler(handler);
