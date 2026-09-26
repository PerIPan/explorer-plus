'use client';

import Link from 'next/link';
import { AGENT_TOOL_COUNT } from '../../lib/site';
import { API_CATALOG, API_FACTS, API_GROUP_META, entriesInGroup } from '../../lib/api-catalog';
import { CodeBlock, FactRow, Section } from './primitives';

/**
 * The top-bar "APIs / MCP" modal, in its QUICK-REFERENCE role: the connection
 * facts, the whole endpoint list to scan, and the way on to the two pages that
 * do more. It no longer owns a catalogue — it renders `API_CATALOG`, which is
 * what ended the 55-of-86 drift.
 *
 * Deliberately not clickable per row: live calls, per-endpoint parameters and the
 * tool schemas live on /open-apis and /open-mcp. A modal opened from a modal is a
 * worse experience than a link to a page built for it.
 *
 * Loaded lazily by AppShell — a static import would put the catalogue in the
 * shell chunk on every page, for a panel almost nobody opens.
 */
export function ApiCatalogPanel({ tab }: { tab: 'rest' | 'mcp' | 'a2a' }) {
  if (tab === 'rest') return <RestReference />;
  if (tab === 'a2a') return <AgentToAgentReference />;
  return <McpReference />;
}

function RestReference() {
  return (
    <div className="space-y-5 px-4 py-4 text-sm leading-relaxed text-[var(--text-primary)] md:px-6 md:py-5">
      <p>
        <strong>Open REST API.</strong> Every page on this site is drawn by a public JSON API you can call yourself —
        <span className="text-[var(--accent-teal)]"> no key, no sign-up, no rate limit</span>, open CORS.
      </p>

      <div className="space-y-1.5 rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-3 py-3">
        <FactRow label="Base URL" value={API_FACTS.baseUrl} copy />
        <FactRow label="Auth" value={API_FACTS.auth} />
        <FactRow label="CORS" value={API_FACTS.cors} />
        <FactRow label="Endpoints" value={`${API_CATALOG.length} documented`} />
      </div>

      <p className="text-xs text-[var(--text-secondary)]">
        Lists return <code className="text-[var(--accent-teal)]">{API_FACTS.pagination.envelope}</code>; detail routes
        return the object. {API_FACTS.pagination.noOffset}
      </p>

      <Section title="Try it now">
        <CodeBlock>{`curl '${API_FACTS.baseUrl}/techniques/T1059'
curl '${API_FACTS.baseUrl}/cves?severity=CRITICAL&limit=5'
curl '${API_FACTS.baseUrl}/search?q=lazarus'`}</CodeBlock>
      </Section>

      <div className="space-y-3">
        {API_GROUP_META.map((g) => {
          const entries = entriesInGroup(g.key);
          if (entries.length === 0) return null;
          return (
            <div key={g.key}>
              <div className="mb-1 text-[11px] font-bold uppercase tracking-wider text-[var(--accent-teal)]">
                {g.label} <span className="font-medium normal-case tracking-normal text-[var(--text-secondary)]">· {entries.length}</span>
              </div>
              <ul className="space-y-0.5">
                {entries.map((e) => (
                  <li key={`${e.method} ${e.path}`} className="flex flex-wrap items-baseline gap-x-2 text-xs">
                    <code className="font-mono text-[var(--text-primary)]">{e.path}</code>
                    <span className="text-[var(--text-secondary)]">{e.summary}</span>
                  </li>
                ))}
              </ul>
            </div>
          );
        })}
      </div>

      <p className="border-t border-[var(--border-color)] pt-3 text-xs text-[var(--text-secondary)]">
        <Link href="/open-apis" className="font-semibold text-[var(--accent-teal)] hover:underline">
          Open APIs →
        </Link>{' '}
        the same list with every parameter, and a Run button that calls the endpoint in front of you.{' '}
        <strong className="text-[var(--text-primary)]">Fair use:</strong> {API_FACTS.rateLimit} Need the whole corpus?
        Ask for a dump rather than crawling.
      </p>
    </div>
  );
}

function McpReference() {
  return (
    <div className="space-y-5 px-4 py-4 text-sm leading-relaxed text-[var(--text-primary)] md:px-6 md:py-5">
      <p>
        <strong>Model Context Protocol.</strong> Point Claude, Cursor or any MCP client at this knowledge base and query
        it in conversation — the same {AGENT_TOOL_COUNT} tools the A2A endpoint uses, over Streamable HTTP.{' '}
        <span className="text-[var(--accent-teal)]">No key, no sign-up, no rate limit.</span>
      </p>

      <div className="space-y-1.5 rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-3 py-3">
        <FactRow label="Endpoint" value={API_FACTS.mcpUrl} copy />
        <FactRow label="Transport" value="Streamable HTTP · stateless" />
        <FactRow label="Tools" value={`${AGENT_TOOL_COUNT} · ATT&CK, CVE, CAPEC, advisories, compliance, ICS/Purdue`} />
        <FactRow label="Auth" value={API_FACTS.auth} />
      </div>

      <Section title="Add it to Claude Code">
        <CodeBlock>{`claude mcp add --transport http mitre ${API_FACTS.mcpUrl}`}</CodeBlock>
      </Section>

      <Section title="Or any client that takes a config file">
        <CodeBlock>{`{
  "mcpServers": {
    "mitre": {
      "type": "http",
      "url": "${API_FACTS.mcpUrl}"
    }
  }
}`}</CodeBlock>
      </Section>

      <Section title="What you can ask once connected">
        <ul className="divide-y divide-[var(--border-color)] rounded-md border border-[var(--border-color)] text-xs italic text-[var(--text-secondary)]">
          <li className="px-3 py-2">&ldquo;Which ATT&amp;CK techniques target a safety instrumented system, and where does it sit in the Purdue model?&rdquo;</li>
          <li className="px-3 py-2">&ldquo;Show critical CVEs affecting nginx published this month, with their EPSS scores.&rdquo;</li>
          <li className="px-3 py-2">&ldquo;Which assets sit on the IT/OT boundary, and what reaches them?&rdquo;</li>
        </ul>
      </Section>

      <p className="border-t border-[var(--border-color)] pt-3 text-xs text-[var(--text-secondary)]">
        <Link href="/open-mcp" className="font-semibold text-[var(--accent-teal)] hover:underline">
          Open MCP →
        </Link>{' '}
        all {AGENT_TOOL_COUNT} tools with their descriptions and argument schemas, the A2A endpoint, and the usage guide
        the server hands agents. A2A is metered at 50 requests/day per IP; MCP and REST are not.
      </p>
    </div>
  );
}

/**
 * A2A. Kept beside the MCP block rather than in AppShell so the endpoint, the
 * tool count and the quota are stated once — AppShell used to carry its own copy
 * with the origin hardcoded.
 */
function AgentToAgentReference() {
  return (
    <div className="space-y-5 px-4 py-4 text-sm leading-relaxed text-[var(--text-primary)] md:px-6 md:py-5">
      <p>
        <strong>Agent2Agent (A2A).</strong> An agent discovers the skills from the Agent Card, sends a
        natural-language request, and gets structured threat intel back. Open and keyless; the same tool catalogue as
        MCP, driven by Gemini function-calling.
      </p>

      <div className="space-y-1.5 rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-3 py-3">
        <FactRow label="Endpoint" value={`POST ${API_FACTS.a2aUrl}`} copy />
        <FactRow label="Agent Card" value={API_FACTS.agentCardPath} />
        <FactRow label="Catalogue" value={`25 skills · ${AGENT_TOOL_COUNT} tools`} />
        <FactRow label="Limit" value="50 requests/day per IP · no auth" />
        <FactRow label="Protocol" value="A2A (JSON-RPC) · Gemini function-calling" />
      </div>

      <Section title="Example">
        <div className="rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-3 py-2.5 text-xs italic text-[var(--text-secondary)]">
          &ldquo;Ask mitre-explorer.org, using the A2A protocol:{' '}
          <span className="not-italic text-[var(--text-primary)]">
            which Applications have been affected by new CVEs published in the previous week? Show the relevant
            ATT&amp;CK techniques, plus the latest 2-day threat reports. Render the result for me.
          </span>
          &rdquo;
        </div>
      </Section>

      <p className="border-t border-[var(--border-color)] pt-3 text-xs text-[var(--text-secondary)]">
        <a
          href={API_FACTS.agentCardPath}
          target="_blank"
          rel="noopener noreferrer"
          className="font-semibold text-[var(--accent-teal)] hover:underline"
        >
          agent-card.json →
        </a>{' '}
        the machine-readable contract. Point any A2A-capable agent at it. The A2A endpoint is the one metered surface
        here; MCP and REST are not.
      </p>
    </div>
  );
}
