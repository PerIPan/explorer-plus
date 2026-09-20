import { after } from 'next/server';
import { query } from '../v1/lib/db';

// ---------------------------------------------------------------------------
// MCP tool usage counting
// ---------------------------------------------------------------------------
// Counters, not per-request rows. /api/mcp is anonymous and unrate-limited, so
// there is no quota to enforce and therefore no reason to retain client
// identity -- no IP, not even a salted hash. See
// seed/migrations/2026-09-20-mcp-usage.sql for the schema and the reasoning.
//
// This exists because MCP work is otherwise INVISIBLE: tool calls reach data
// through callInternalApi(), which fetches the public /api/v1 URL, so on a CDN
// miss they land in api_usage under the underlying REST endpoint and are
// indistinguishable from browser traffic.

/**
 * Known MCP clients. `client` comes from a caller-supplied User-Agent on an
 * unauthenticated, unlimited endpoint, so it is NOT stored raw: anything
 * unrecognised collapses to 'other'. Without that, one caller could mint
 * unbounded (tool, day, client) rows. Same bounded-cardinality trick
 * middleware.ts uses when it folds unknown path segments into ':id'.
 *
 * Longest-prefix-first, so 'claude-code' wins over 'claude'. To learn what real
 * callers report, watch the 'other' row grow and add entries here.
 */
const KNOWN_CLIENTS = [
  'claude-code', 'claude-desktop', 'claude-ai', 'claude',
  'cursor', 'windsurf', 'cline', 'continue', 'zed', 'vscode',
  'mcp-inspector', 'mcp-remote', 'goose', 'librechat', 'openai', 'chatgpt',
  'node', 'python-httpx', 'curl',
];

/** Collapse a User-Agent to one of a bounded set of client labels. */
export function normalizeClient(raw: string | null | undefined): string {
  if (!raw) return 'unknown';
  const slug = raw.toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '');
  if (!slug) return 'unknown';
  return KNOWN_CLIENTS.find((k) => slug === k || slug.startsWith(k)) ?? 'other';
}

/**
 * Record one tool call. Deferred with after() so it never blocks or breaks the
 * MCP response, and swallows its own errors for the same reason -- usage
 * counting must never be the thing that fails a tool call.
 */
export function recordMcpUsage(
  tool: string,
  client: string,
  latencyMs: number,
  isError: boolean,
): void {
  try {
    after(async () => {
      try {
        await query(
          `INSERT INTO mcp_usage (tool, day, client, count, error_count, total_latency_ms)
           VALUES ($1, (now() AT TIME ZONE 'utc')::date, $2, 1, $3, $4)
           ON CONFLICT (tool, day, client) DO UPDATE SET
             count            = mcp_usage.count + 1,
             error_count      = mcp_usage.error_count + EXCLUDED.error_count,
             total_latency_ms = mcp_usage.total_latency_ms + EXCLUDED.total_latency_ms,
             updated_at       = now()`,
          [tool.slice(0, 64), client.slice(0, 32), isError ? 1 : 0, Math.max(0, Math.round(latencyMs))],
        );
      } catch (err) {
        console.error('mcp_usage upsert failed:', err);
      }
    });
  } catch {
    // after() outside a request scope — stay defensive, never break a response.
  }
}
