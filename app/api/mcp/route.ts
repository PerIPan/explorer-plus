import { AsyncLocalStorage } from 'node:async_hooks';
import { createMcpHandler } from 'mcp-handler';
import { z } from 'zod';
import { TOOL_DECLARATIONS, executeTool, USAGE_GUIDE, type ToolDeclaration } from '../../../src/lib/tools';
import { normalizeClient, recordMcpUsage } from '../lib/mcp-usage';

/**
 * MCP (Model Context Protocol) endpoint -- Streamable HTTP, stateless.
 *
 * Serves the same tool catalogue as /api/a2a (src/lib/tools) to any MCP client.
 * Anonymous and unrate-limited, matching the public REST API it fronts; the
 * data is already open, and every tool bottoms out in a cached /api/v1 read.
 *
 * Stateless by design: mcp-handler v2 removed the SSE transport, so there is no
 * session store and no Redis -- a fresh server is built per request, which is
 * what makes this work on serverless at all.
 */

// Node runtime, not edge: tool execution reaches the `pg` pool (via the usage
// counter) and uses AsyncLocalStorage.
export const maxDuration = 60;

/**
 * Per-request client label for usage counting.
 *
 * The tool callback's ctx only carries authInfo -- it cannot see HTTP headers
 * -- so the label is captured in the route wrapper and read back inside the
 * callback. A module-scoped variable would race across concurrent requests;
 * AsyncLocalStorage is per-async-context and does not.
 */
const clientStore = new AsyncLocalStorage<string>();

/**
 * Gemini function-declaration schema -> Zod.
 *
 * The catalogue is authored in Gemini's dialect (UPPERCASE type names) because
 * /api/a2a feeds it straight to Gemini. MCP wants a Standard Schema, so convert
 * on the way out rather than changing the source dialect and breaking A2A.
 *
 * Total over the catalogue as it stands: every declaration is a flat OBJECT of
 * STRING / NUMBER / BOOLEAN, with optional inline `enum` and a `required` list.
 * No nesting and no arrays -- verified across all declarations. The `default`
 * arm keeps an unexpected future type from throwing at module load.
 */
function toZodObject(decl: ToolDeclaration) {
  const props = decl.parameters?.properties ?? {};
  const required = new Set(decl.parameters?.required ?? []);
  const shape: Record<string, z.ZodTypeAny> = {};

  for (const [key, raw] of Object.entries(props)) {
    const p = (raw ?? {}) as { type?: string; description?: string; enum?: string[] };
    let field: z.ZodTypeAny;

    if (Array.isArray(p.enum) && p.enum.length > 0) {
      // Case-fold before validating. executeTool normalises case itself
      // (toUpperCase for severity/source, toLowerCase for level/platform/zone),
      // but z.enum() is case-sensitive and rejects first -- which would make MCP
      // stricter than A2A for identical input, failing plausible model output
      // like platform:'Windows' or severity:'critical'.
      const values = p.enum as [string, ...string[]];
      const byLower = new Map(values.map((v) => [v.toLowerCase(), v]));
      field = z.preprocess(
        (v) => (typeof v === 'string' ? byLower.get(v.toLowerCase()) ?? v : v),
        z.enum(values),
      );
    } else {
      // Accept the shapes weaker clients actually emit. Rejecting them here
      // made MCP stricter than the executor behind it: executeTool coerces
      // with String()/Number() and treats 'true'/'false' as booleans, so a
      // schema-level rejection failed calls the tool would have answered.
      switch (String(p.type ?? 'STRING').toUpperCase()) {
        // "10" -> 10.
        case 'NUMBER':
          field = z.coerce.number();
          break;
        // "true" -> true (a JSON-mode model often quotes booleans).
        case 'BOOLEAN':
          field = z.preprocess(
            (v) => (typeof v === 'string' && /^(true|false)$/i.test(v) ? v.toLowerCase() === 'true' : v),
            z.boolean(),
          );
          break;
        // true -> "true": several STRING params (has_cve) are documented as
        // the words "true"/"false" and the executor compares them as strings.
        default:
          field = z.preprocess(
            (v) => (typeof v === 'boolean' || typeof v === 'number' ? String(v) : v),
            z.string(),
          );
          break;
      }
    }

    if (p.description) field = field.describe(p.description);
    // null is how models spell "I am not using this optional filter"; Zod's
    // .optional() accepts only undefined, so map it before validating rather
    // than failing the whole call over an unused argument.
    shape[key] = required.has(key)
      ? field
      : z.preprocess((v) => (v === null ? undefined : v), field.optional());
  }

  return z.object(shape);
}

const handler = createMcpHandler((server) => {
  // Also exposed as a resource, not just the get_usage_guide tool: a resource
  // costs nothing in the default tool context, but some clients surface
  // resources only on explicit user action -- hence both.
  server.registerResource(
    'usage-guide',
    'mitre://guide',
    {
      title: 'MITRE Explorer usage guide',
      description: 'Tool selection, data provenance, pagination, vocabularies and ICS Purdue semantics.',
      mimeType: 'text/markdown',
    },
    async (uri) => ({
      contents: [{ uri: uri.href, mimeType: 'text/markdown', text: USAGE_GUIDE }],
    }),
  );

  for (const decl of TOOL_DECLARATIONS) {
    server.registerTool(
      decl.name,
      { description: decl.description, inputSchema: toZodObject(decl) },
      async (args: Record<string, unknown>) => {
        const started = performance.now();
        const client = clientStore.getStore() ?? 'unknown';
        try {
          const result = await withSlot(() => executeTool(decl.name, args ?? {}));
          // executeTool reports failure in-band as { error: string } (bad
          // argument, or a non-2xx from the internal API) rather than throwing.
          const isError = typeof result?.error === 'string';
          recordMcpUsage(decl.name, client, performance.now() - started, isError);
          return {
            content: [{ type: 'text' as const, text: JSON.stringify(result) }],
            isError,
          };
        } catch (err) {
          recordMcpUsage(decl.name, client, performance.now() - started, true);
          const message = err instanceof Error ? err.message : 'Tool execution failed';
          return {
            content: [{ type: 'text' as const, text: JSON.stringify({ error: message }) }],
            isError: true,
          };
        }
      },
    );
  }
}, {
  // Provisional name — the public one is still being decided.
  serverInfo: { name: 'mitre-explorer', version: '1.0.0' },
  capabilities: { tools: { listChanged: false } },
  // The A2A endpoint steers Gemini with buildSystemInstruction(); MCP clients
  // never see that, so the rules that are not already pushed down into
  // individual tool descriptions are restated here.
  instructions: [
    'This server answers questions about MITRE ATT&CK, CVEs, CAPEC, security advisories, detection content and compliance frameworks.',
    '',
    'Always call a tool before answering — never answer from memory. This data changes and your training data is stale.',
    '',
    'search_* tools return summaries; get_* tools return the full record. For a specific named entity, use the get_* tool; if you only have a name and not an ID, call the matching search_* tool first to resolve the ID.',
    '',
    'For a specific technique, call BOTH get_technique_detail (description, tactics, mitigations, data sources, and the threat groups and malware that use it) and get_technique_intelligence (Sigma rules, Atomic tests, D3FEND, threat reports, linked CVEs and IOCs) — neither is a superset of the other. For regulatory frameworks use get_technique_compliance.',
    '',
    'Dates: compute relative ranges ("last 7 days") from the current date and pass `since` as a full ISO-8601 string. A `since` value that is not a parseable date is rejected with an error naming the field — fix it and retry rather than treating the unfiltered answer as close enough.',
    '',
    'When a list result carries a total larger than the rows returned, say so explicitly ("showing 10 of 47") rather than presenting the page as complete.',
    '',
    'Version filters surface advisories whose affected-range MENTIONS a version. That is not a verdict that the version is vulnerable — say so when reporting.',
    '',
    'Purdue flow rules: directAllowed means topological adjacency, not permission to initiate a session. Always read the accompanying note, which carries the directionality constraint.',
  ].join('\n'),
});

/** Open CORS so browser-based clients (e.g. MCP Inspector) can reach this. */
function withOpenCors(res: Response): Response {
  const headers = new Headers(res.headers);
  headers.set('Access-Control-Allow-Origin', '*');
  headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  // '*' rather than a list: the installed SDK's modern protocol era (2026-07-28)
  // carries per-request metadata in Mcp-Method, Mcp-Name and an open-ended
  // Mcp-Param-* family, which cannot be enumerated ahead of time. A preflight
  // that omits one fails in the browser as an opaque network error with no
  // JSON-RPC diagnostic. Authorization is listed explicitly because the
  // wildcard does not cover it.
  headers.set('Access-Control-Allow-Headers', '*, Authorization');
  headers.set('Access-Control-Expose-Headers', 'Mcp-Session-Id, MCP-Protocol-Version');
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
}

/**
 * Largest JSON-RPC batch we will dispatch.
 *
 * The transport accepts an array of requests and fans every element out
 * CONCURRENTLY, with no cap of its own. Stateless mode also skips the session
 * and protocol-version checks, so a single unauthenticated POST can carry tens
 * of thousands of entries -- each becoming an outbound /api/v1 request (a
 * guaranteed CDN miss if the arguments vary), a Vercel invocation and Neon
 * work, against a pool of max 3 connections.
 *
 * That is an amplification primitive, not merely "the API is open": hitting
 * /api/v1 directly costs an attacker one request per unit of work, whereas this
 * would cost one request per ~40,000 units. Capping the batch removes the
 * amplification without adding auth or a rate limit.
 *
 * 100 is well above what real clients batch (most send one request at a time)
 * and far below a useful attack multiplier. Note the cap alone does not bound
 * pressure: the transport dispatches a batch CONCURRENTLY, so 100 entries means
 * 100 simultaneous internal fetches unless the gate below throttles them.
 */
const MAX_BATCH = 100;

/**
 * Maximum internal API calls in flight at once, per instance.
 *
 * The batch cap bounds how much work one request can ask for; this bounds how
 * much of it happens at the same moment. Without it a 100-entry batch opens 100
 * concurrent fetches into /api/v1, each of which may want one of the `pg` pool's
 * 3 connections (20s connection timeout) -- so a single batched caller could
 * queue out the site's own page queries while doing nothing individually abusive.
 *
 * 6 keeps a full batch draining in well under maxDuration while leaving the pool
 * usable. Single tool calls -- the overwhelmingly common case -- never wait.
 */
const MAX_INFLIGHT = 6;

let inFlight = 0;
const waiting: Array<() => void> = [];

/** Minimal semaphore: acquire a slot, run, always release. */
async function withSlot<T>(fn: () => Promise<T>): Promise<T> {
  if (inFlight >= MAX_INFLIGHT) {
    await new Promise<void>((resolve) => waiting.push(resolve));
  }
  inFlight++;
  try {
    return await fn();
  } finally {
    inFlight--;
    waiting.shift()?.();
  }
}

/** Reject oversized batches before the transport can fan them out. */
function batchTooLarge(body: string): number | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return null; // Not our problem — let the SDK produce its own parse error.
  }
  return Array.isArray(parsed) && parsed.length > MAX_BATCH ? parsed.length : null;
}

async function route(req: Request): Promise<Response> {
  const client = normalizeClient(req.headers.get('user-agent'));

  if (req.method === 'POST') {
    // Buffer once so we can inspect the batch, then hand the SDK an equivalent
    // Request (a body stream can only be consumed a single time).
    const body = await req.text();
    const size = batchTooLarge(body);
    if (size !== null) {
      return withOpenCors(
        new Response(
          JSON.stringify({
            jsonrpc: '2.0',
            id: null,
            error: {
              code: -32600,
              message: `Batch too large: ${size} requests in one call, limit is ${MAX_BATCH}. Send them separately.`,
            },
          }),
          { status: 413, headers: { 'Content-Type': 'application/json' } },
        ),
      );
    }
    req = new Request(req.url, { method: 'POST', headers: req.headers, body });
  }

  return clientStore.run(client, async () => withOpenCors(await handler(req)));
}

export const GET = route;
export const POST = route;
export const DELETE = route;

export function OPTIONS() {
  return withOpenCors(new Response(null, { status: 204 }));
}
