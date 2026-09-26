'use client';

import { useMemo, useRef, useState } from 'react';
import Link from 'next/link';
import { PageHeader } from '../components/layout/PageHeader';
import { Badge } from '../components/shared/Badge';
import { Card, Notice } from '../components/profile/BriefingPrimitives';
import { CodeBlock, CopyButton, FactRow, Section } from '../components/api/primitives';
import { ToolModal } from '../components/api/ToolModal';
import { API_FACTS, TOOL_ENDPOINTS, TOOL_GROUPS } from '../lib/api-catalog';
// Import the declarations module DIRECTLY, never `src/lib/tools` — the barrel
// re-exports execute.ts, a 32KB switch that reads process.env.VERCEL_*. Nothing
// in it is Node-only, so it would bundle into this client page in silence rather
// than failing the build. Same for guide.ts below.
import { TOOL_DECLARATIONS } from '../lib/tools/declarations';
import type { ToolDeclaration } from '../lib/tools/declarations';
import { USAGE_GUIDE } from '../lib/tools/guide';

/**
 * /open-mcp — the MCP server and the A2A endpoint, with every tool.
 *
 * Tool text is rendered from `TOOL_DECLARATIONS`: the same bytes an MCP client
 * receives. `src/lib/api-catalog.ts` contributes grouping and the REST route each
 * tool calls, and nothing else — no description is copied across the seam, so
 * this page cannot describe a tool differently from how the server does.
 */
export function OpenMcp() {
  const [selected, setSelected] = useState<ToolDeclaration | null>(null);
  const triggerRef = useRef<HTMLElement | null>(null);

  const byName = useMemo(() => new Map(TOOL_DECLARATIONS.map((t) => [t.name, t])), []);

  return (
    <div className="mx-auto max-w-5xl">
      <PageHeader
        title="Open MCP"
        subtitle={
          <>
            Point Claude, Cursor or any MCP client at this knowledge base and query it in conversation —{' '}
            {TOOL_DECLARATIONS.length} tools over Streamable HTTP, anonymous and unmetered. The same catalogue is
            reachable over A2A for agent-to-agent calls.
          </>
        }
        actions={<Badge label="no auth" variant="teal" />}
      />

      <div className="space-y-5">
        <Card className="px-4 py-4">
          <div className="space-y-1.5">
            <FactRow label="Endpoint" value={API_FACTS.mcpUrl} copy />
            <FactRow label="Transport" value="Streamable HTTP · stateless" />
            <FactRow label="Tools" value={`${TOOL_DECLARATIONS.length}`} />
            <FactRow label="Auth" value={API_FACTS.auth} />
            <FactRow label="Rate limit" value="none on MCP. A2A is 50 requests/day per IP." />
          </div>
        </Card>

        <div className="grid gap-4 md:grid-cols-2">
          <Card className="px-4 py-4">
            <Section title="Add it to Claude Code">
              <CodeBlock wrap>{`claude mcp add --transport http mitre ${API_FACTS.mcpUrl}`}</CodeBlock>
              <div className="mt-2">
                <CopyButton
                  value={`claude mcp add --transport http mitre ${API_FACTS.mcpUrl}`}
                  label="copy command"
                />
              </div>
            </Section>
          </Card>

          <Card className="px-4 py-4">
            <Section title="Or any client that takes a config file">
              <CodeBlock>{`{
  "mcpServers": {
    "mitre": {
      "type": "http",
      "url": "${API_FACTS.mcpUrl}"
    }
  }
}`}</CodeBlock>
              <div className="mt-2">
                <CopyButton
                  value={JSON.stringify(
                    { mcpServers: { mitre: { type: 'http', url: API_FACTS.mcpUrl } } },
                    null,
                    2,
                  )}
                  label="copy config"
                />
              </div>
            </Section>
          </Card>
        </div>

        <Card className="px-4 py-4">
          <Section title="Agent2Agent (A2A)">
            <p className="text-xs leading-relaxed text-[var(--text-secondary)]">
              For agent-to-agent calls rather than an interactive client: an agent reads the Agent Card to learn the
              skills, then sends one natural-language request over JSON-RPC. Gemini function-calling chains the tools and
              returns a structured result plus a rendered summary. This is the one metered surface here — 50 requests
              per day per IP, still no key.
            </p>
            <div className="mt-2 space-y-1.5">
              <FactRow label="Endpoint" value={`POST ${API_FACTS.a2aUrl}`} copy />
              <FactRow label="Agent Card" value={API_FACTS.agentCardPath} />
            </div>
            <p className="mt-2 text-xs">
              <a
                href={API_FACTS.agentCardPath}
                target="_blank"
                rel="noopener noreferrer"
                className="font-semibold text-[var(--accent-teal)] hover:underline"
              >
                Open agent-card.json →
              </a>
            </p>
          </Section>
        </Card>

        <Notice tone="info" title="It is the REST API underneath">
          Every tool call is an HTTP hop to the public{' '}
          <Link href="/open-apis" className="font-semibold text-[var(--accent-teal)] hover:underline">
            /api/v1
          </Link>{' '}
          routes, which is why an MCP answer and a curl answer are the same answer. Each tool below names the route it
          reaches.
        </Notice>

        {/* Tool catalogue */}
        <div className="space-y-5">
          {TOOL_GROUPS.map((group) => {
            const tools = group.tools.map((n) => byName.get(n)).filter((t): t is ToolDeclaration => Boolean(t));
            if (tools.length === 0) return null;
            return (
              <section key={group.key} aria-labelledby={`tools-${group.key}`}>
                <h2
                  id={`tools-${group.key}`}
                  className="mb-1.5 text-[11px] font-bold uppercase tracking-wider text-[var(--accent-teal)]"
                >
                  {group.label}{' '}
                  <span className="font-medium normal-case tracking-normal text-[var(--text-secondary)]">
                    · {tools.length}
                  </span>
                </h2>
                <Card className="divide-y divide-[var(--border-color)] overflow-hidden">
                  {tools.map((tool) => {
                    const argNames = Object.keys(tool.parameters?.properties ?? {});
                    const required = new Set(tool.parameters?.required ?? []);
                    return (
                      <button
                        key={tool.name}
                        type="button"
                        onClick={(ev) => {
                          triggerRef.current = ev.currentTarget;
                          setSelected(tool);
                        }}
                        className="group block w-full px-3 py-2.5 text-left transition-colors hover:bg-[var(--hover-overlay)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[var(--accent-teal)]"
                      >
                        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                          <code className="font-mono text-xs font-semibold text-[var(--text-primary)]">{tool.name}</code>
                          {argNames.length === 0 ? (
                            <Badge label="no arguments" variant="neutral" />
                          ) : (
                            argNames.map((a) => (
                              <Badge
                                key={a}
                                label={a}
                                variant={required.has(a) ? 'orange' : 'neutral'}
                                className="font-mono"
                              />
                            ))
                          )}
                          <span className="ml-auto shrink-0 text-[10px] font-medium uppercase tracking-wider text-[var(--text-secondary)] opacity-0 transition-opacity group-hover:opacity-100 group-focus-visible:opacity-100">
                            schema →
                          </span>
                        </div>
                        <p className="mt-1 line-clamp-2 text-xs leading-snug text-[var(--text-secondary)]">
                          {tool.description}
                        </p>
                        {TOOL_ENDPOINTS[tool.name]?.startsWith('/') && (
                          <code className="mt-1 block font-mono text-[10px] text-[var(--text-secondary)] opacity-70">
                            /api/v1{TOOL_ENDPOINTS[tool.name]}
                          </code>
                        )}
                      </button>
                    );
                  })}
                </Card>
              </section>
            );
          })}
        </div>

        {/* USAGE_GUIDE, verbatim. Shown as the text it is rather than re-rendered
            as prose: it is what an agent receives from get_usage_guide, and a
            human evaluating the API benefits from the same statement of how the
            datasets fit together — provenance, which tool to prefer, the
            controlled vocabularies. Rendering it verbatim also means no markdown
            dependency and no HTML from a string. */}
        <details className="rounded-lg border border-[var(--border-color)] bg-[var(--surface-card)]">
          <summary className="cursor-pointer px-4 py-3 text-xs font-semibold text-[var(--text-primary)]">
            The usage guide the server hands agents
            <span className="ml-2 font-normal text-[var(--text-secondary)]">
              — how the datasets fit together, which of two similar tools to call, what an empty result means, and the
              controlled vocabularies. Served as the <code>get_usage_guide</code> tool and the{' '}
              <code>mitre://guide</code> resource.
            </span>
          </summary>
          <pre className="max-h-[60vh] overflow-auto border-t border-[var(--border-color)] px-4 py-3 font-mono text-[11px] leading-relaxed whitespace-pre-wrap break-words text-[var(--text-secondary)]">
            {USAGE_GUIDE}
          </pre>
        </details>
      </div>

      <ToolModal tool={selected} onClose={() => setSelected(null)} returnFocusTo={triggerRef} />
    </div>
  );
}
