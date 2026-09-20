import { AsyncLocalStorage } from 'node:async_hooks';
import { createMcpHandler } from 'mcp-handler';
import { z } from 'zod';
import { TOOL_DECLARATIONS, executeTool, type ToolDeclaration } from '../../../src/lib/tools';
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
      field = z.enum(p.enum as [string, ...string[]]);
    } else {
      switch (String(p.type ?? 'STRING').toUpperCase()) {
        case 'NUMBER':  field = z.number(); break;
        case 'BOOLEAN': field = z.boolean(); break;
        default:        field = z.string(); break;
      }
    }

    if (p.description) field = field.describe(p.description);
    shape[key] = required.has(key) ? field : field.optional();
  }

  return z.object(shape);
}

const handler = createMcpHandler((server) => {
  for (const decl of TOOL_DECLARATIONS) {
    server.registerTool(
      decl.name,
      { description: decl.description, inputSchema: toZodObject(decl) },
      async (args: Record<string, unknown>) => {
        const started = performance.now();
        const client = clientStore.getStore() ?? 'unknown';
        try {
          const result = await executeTool(decl.name, args ?? {});
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
});

/** Open CORS so browser-based clients (e.g. MCP Inspector) can reach this. */
function withOpenCors(res: Response): Response {
  const headers = new Headers(res.headers);
  headers.set('Access-Control-Allow-Origin', '*');
  headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  headers.set(
    'Access-Control-Allow-Headers',
    'Content-Type, Accept, Authorization, MCP-Protocol-Version, Mcp-Session-Id',
  );
  headers.set('Access-Control-Expose-Headers', 'Mcp-Session-Id, MCP-Protocol-Version');
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
}

async function route(req: Request): Promise<Response> {
  const client = normalizeClient(req.headers.get('user-agent'));
  return clientStore.run(client, async () => withOpenCors(await handler(req)));
}

export const GET = route;
export const POST = route;
export const DELETE = route;

export function OPTIONS() {
  return withOpenCors(new Response(null, { status: 204 }));
}
