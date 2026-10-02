import { NextRequest, NextResponse } from 'next/server';
import { query } from '../../v1/lib/db';
import { verifyCronAuth } from '../lib/auth';
import { withSoftTimeout, DEFAULT_SOFT_TIMEOUT_MS } from '../lib/softTimeout';

export const maxDuration = 300;

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

/**
 * RSS `<item>` AND Atom `<entry>`.
 *
 * This matched `<item>` only, so a pure Atom feed parsed to ZERO items and the
 * run reported success with nothing ingested — the quietest possible failure,
 * and one that a vendor can cause at any time by changing feed format.
 * `extractAtomLink` below has always been here, which says Atom was meant to be
 * handled; only the block regex and the date/body tag names were missing. Added
 * defensively rather than in response to a measured outage: of the four
 * configured feeds, two (microsoft_security, talos) answer an unattended
 * request with a bot-interstitial page, so their on-the-wire format cannot be
 * checked from a developer machine at all — only in production, where they do
 * deliver (151 and 123 rows).
 *
 * Atom spells every one of these differently: `<entry>` not `<item>`,
 * `<published>`/`<updated>` not `<pubDate>`, `<summary>`/`<content>` not
 * `<description>`, and the link is an href attribute rather than element text.
 *
 * NOTE ON TECHNIQUE EXTRACTION: widening the body text here does NOT recover
 * technique mappings, and it was measured before this change rather than
 * assumed. Across the two feeds that can be fetched unattended (dfir_report 10
 * items, unit42 15), zero items carry a `T####` anywhere in title, description
 * or `content:encoded`; neither feed emits `content:encoded` at all, so the
 * fallback below is dead code for them; fetching the full article HTML (both
 * server-rendered, 33k and 25k characters of visible text) also yields zero;
 * the "MITRE ATT&CK" heading on a DFIR Report post links to an indicators
 * repository that holds 38 KB of pure IOCs and no ATT&CK content; and matching
 * all 534 multi-word live technique names against the article text returns two
 * hits, both false positives ("Browser Fingerprint" in an SEO-poisoning piece,
 * "Email Addresses"). These vendors do not publish machine-readable technique
 * IDs anywhere reachable, so `report_techniques` stays OTX-only by nature and
 * any UI counting it must say OTX rather than "CTI".
 */
function parseRss(xml: string): RssItem[] {
  const items: RssItem[] = [];
  const blockRe = /<(item|entry)[^>]*>([\s\S]*?)<\/\1>/gi;
  let m: RegExpExecArray | null;

  while ((m = blockRe.exec(xml)) !== null) {
    const block = m[2];
    const title = extractTag(block, 'title') ?? '';
    // Atom's <link> carries the URL in an href attribute and has no text, so
    // `extractTag` returns '' for it rather than null — hence the truthiness
    // check instead of `??`, which would accept the empty string and drop the
    // item for want of a link it actually has.
    const link = extractTag(block, 'link') || extractAtomLink(block) || '';
    const pubDate =
      extractTag(block, 'pubDate')
      ?? extractTag(block, 'dc:date')
      ?? extractTag(block, 'published')
      ?? extractTag(block, 'updated')
      ?? null;
    const description =
      extractTag(block, 'description')
      ?? extractTag(block, 'content:encoded')
      ?? extractTag(block, 'summary')
      ?? extractTag(block, 'content')
      ?? '';

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

export async function GET(req: NextRequest) {
  const authError = verifyCronAuth(req);
  if (authError) return authError;

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
    return await withSoftTimeout(async () => {
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
       WHERE id = $3 AND status = 'running'`,
      [recordsInserted, recordsSkipped, logId],
    );

    return NextResponse.json({ ok: true, source: 'rss', recordsInserted, recordsSkipped, feedSummary });
    }, DEFAULT_SOFT_TIMEOUT_MS);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('RSS ingest error:', err);

    await query(
      `UPDATE feed_sync_log
       SET status = 'error', completed_at = NOW(), error_message = $1
       WHERE id = $2 AND status = 'running'`,
      [msg.slice(0, 500), logId],
    );

    console.error('[cron] error:', msg);
    return NextResponse.json({ ok: false, error: 'Feed sync failed' }, { status: 500 });
  }
}
