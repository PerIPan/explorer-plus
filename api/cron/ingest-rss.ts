import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../v1/lib/db.js';
import { verifyCronAuth } from './lib/auth.js';

const RSS_FEEDS = [
  { url: 'https://thedfirreport.com/feed/', source: 'dfir_report' },
  { url: 'https://unit42.paloaltonetworks.com/feed/', source: 'unit42' },
  { url: 'https://www.microsoft.com/en-us/security/blog/feed/', source: 'microsoft_security' },
  { url: 'https://blog.talosintelligence.com/rss/', source: 'talos' },
];

const TECHNIQUE_RE = /\bT\d{4}(\.\d{3})?\b/g;

interface RssItem {
  title: string;
  link: string;
  pubDate: string | null;
  description: string;
}

function parseRss(xml: string): RssItem[] {
  const items: RssItem[] = [];
  const itemRe = /<item[^>]*>([\s\S]*?)<\/item>/gi;
  let m: RegExpExecArray | null;

  while ((m = itemRe.exec(xml)) !== null) {
    const block = m[1];
    const title = extractTag(block, 'title') ?? '';
    const link = extractTag(block, 'link') ?? extractAtomLink(block) ?? '';
    const pubDate = extractTag(block, 'pubDate') ?? extractTag(block, 'dc:date') ?? null;
    const description =
      extractTag(block, 'description') ?? extractTag(block, 'content:encoded') ?? '';

    if (link) {
      items.push({ title, link, pubDate, description: stripHtml(description) });
    }
  }
  return items;
}

function extractTag(block: string, tag: string): string | null {
  const re = new RegExp(
    `<${tag}[^>]*>(?:<!\\[CDATA\\[)?([\\s\\S]*?)(?:\\]\\]>)?<\\/${tag}>`,
    'i',
  );
  const match = block.match(re);
  return match ? match[1].trim() : null;
}

function extractAtomLink(block: string): string | null {
  const m = block.match(/<link[^>]+href=["']([^"']+)["']/i);
  return m ? m[1] : null;
}

function stripHtml(html: string): string {
  return html.replace(/<[^>]+>/g, ' ').replace(/\s{2,}/g, ' ').trim();
}

function extractTechniqueIds(text: string): string[] {
  const matches = text.match(TECHNIQUE_RE) ?? [];
  return [...new Set(matches)];
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== 'GET' && req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }
  if (!verifyCronAuth(req, res)) return;

  // Clean up stale "running" entries (timed-out previous runs)
  await query(
    `UPDATE feed_sync_log
     SET status = 'error', completed_at = NOW(), error_message = 'Timed out (auto-cleaned)'
     WHERE source = 'rss' AND status = 'running' AND started_at < NOW() - INTERVAL '15 minutes'`,
  );

  const logResult = await query<{ id: string }>(
    `INSERT INTO feed_sync_log (source, status, started_at)
     VALUES ('rss', 'running', NOW())
     RETURNING id`,
  );
  const logId = logResult.rows[0].id;

  let recordsInserted = 0;
  let recordsSkipped = 0;
  const feedSummary: Record<string, { inserted: number; skipped: number; error?: string }> = {};

  try {
    for (const feed of RSS_FEEDS) {
      feedSummary[feed.source] = { inserted: 0, skipped: 0 };
      try {
        const resp = await fetch(feed.url, {
          headers: { 'User-Agent': 'MITRE-ATT&CK-Explorer/1.0' },
          signal: AbortSignal.timeout(15_000),
        });

        if (!resp.ok) {
          feedSummary[feed.source].error = `HTTP ${resp.status}`;
          continue;
        }

        const MAX_XML_BYTES = 5 * 1024 * 1024; // 5 MB
        const contentLength = Number(resp.headers.get('content-length') ?? 0);
        if (contentLength > MAX_XML_BYTES) {
          feedSummary[feed.source].error = `Feed too large (${contentLength} bytes)`;
          continue;
        }
        const rawText = await resp.text();
        if (Buffer.byteLength(rawText, 'utf8') > MAX_XML_BYTES) {
          feedSummary[feed.source].error = 'Feed too large (>5MB)';
          continue;
        }
        const xml = rawText;
        const items = parseRss(xml);

        for (const item of items) {
          if (!item.link) continue;

          const searchText = `${item.title} ${item.description}`;
          const rawIds = extractTechniqueIds(searchText);

          // Resolve technique IDs in one query (returns both id and attack_id)
          let techRows: Array<{ id: string; attack_id: string }> = [];
          let validIds: string[] = [];
          if (rawIds.length > 0) {
            const techResult = await query<{ id: string; attack_id: string }>(
              `SELECT id, attack_id FROM techniques WHERE attack_id = ANY($1::text[])`,
              [rawIds],
            );
            techRows = techResult.rows;
            validIds = techRows.map((r) => r.attack_id);
          }

          try {
            const rptResult = await query<{ id: string; was_inserted: boolean }>(
              `INSERT INTO threat_reports
                 (title, url, source, published_at, summary, extracted_technique_ids)
               VALUES ($1, $2, $3, $4, $5, $6)
               ON CONFLICT (url) DO UPDATE
                 SET title = EXCLUDED.title,
                     updated_at = NOW()
               RETURNING id, (xmax = 0) AS was_inserted`,
              [
                item.title || 'Untitled',
                item.link,
                feed.source,
                item.pubDate ? new Date(item.pubDate).toISOString() : null,
                item.description.slice(0, 2000) || null,
                validIds.length > 0 ? validIds : null,
              ],
            );

            const reportId = rptResult.rows[0].id;
            if (rptResult.rows[0].was_inserted) {
              recordsInserted++;
              feedSummary[feed.source].inserted++;
            }

            if (techRows.length > 0) {
              const values = techRows
                .map((_, i) => `($1, $${i + 2})`)
                .join(', ');
              await query(
                `INSERT INTO report_techniques (report_id, technique_id)
                 VALUES ${values}
                 ON CONFLICT DO NOTHING`,
                [reportId, ...techRows.map((r) => r.id)],
              );
            }
          } catch (upsertErr) {
            const msg = upsertErr instanceof Error ? upsertErr.message : String(upsertErr);
            if (!msg.includes('unique') && !msg.includes('duplicate')) {
              console.error(`RSS upsert error for ${item.link}:`, upsertErr);
            }
            recordsSkipped++;
            feedSummary[feed.source].skipped++;
          }
        }
      } catch (feedErr) {
        console.error(`RSS feed error (${feed.source}):`, feedErr);
        feedSummary[feed.source].error =
          feedErr instanceof Error ? feedErr.message : String(feedErr);
      }
    }

    await query(
      `UPDATE feed_sync_log
       SET status = 'success', completed_at = NOW(),
           records_inserted = $1, records_skipped = $2
       WHERE id = $3`,
      [recordsInserted, recordsSkipped, logId],
    );

    res.status(200).json({ ok: true, source: 'rss', recordsInserted, recordsSkipped, feedSummary });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('RSS ingest error:', err);

    await query(
      `UPDATE feed_sync_log
       SET status = 'error', completed_at = NOW(), error_message = $1
       WHERE id = $2`,
      [msg, logId],
    );

    console.error('[cron] error:', msg);
    res.status(500).json({ ok: false, error: 'Feed sync failed' });
  }
}
