'use client';

import { useMemo, useRef, useState } from 'react';
import Link from 'next/link';
import { PageHeader } from '../components/layout/PageHeader';
import { Badge } from '../components/shared/Badge';
import { Card, Notice } from '../components/profile/BriefingPrimitives';
import { CodeBlock, FactRow, MethodPill, Section } from '../components/api/primitives';
import { EndpointModal } from '../components/api/EndpointModal';
import {
  API_CATALOG,
  API_FACTS,
  API_GROUP_META,
  EXECUTABLE_COUNT,
  entryKey,
} from '../lib/api-catalog';
import type { ApiEntry } from '../lib/api-catalog';

/**
 * /open-apis — the REST surface, in full, with a Run button per endpoint.
 *
 * Everything on this page comes from `src/lib/api-catalog.ts`; nothing is typed
 * out twice. The Run button is the point: a pasted sample response goes stale in
 * silence, and the claim this page makes — that the API is open and returns this
 * shape — is one a reader can check in front of us.
 */
export function OpenApis() {
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState<ApiEntry | null>(null);
  /** The row that opened the modal, so focus returns to it on close. */
  const triggerRef = useRef<HTMLElement | null>(null);

  const needle = query.trim().toLowerCase();
  const groups = useMemo(
    () =>
      API_GROUP_META.map((g) => ({
        ...g,
        entries: API_CATALOG.filter(
          (e) =>
            e.group === g.key &&
            (needle === '' ||
              e.path.toLowerCase().includes(needle) ||
              e.summary.toLowerCase().includes(needle)),
        ),
      })).filter((g) => g.entries.length > 0),
    [needle],
  );
  const shown = groups.reduce((n, g) => n + g.entries.length, 0);

  return (
    <div className="mx-auto max-w-5xl">
      <PageHeader
        title="Open APIs"
        subtitle={
          <>
            Every page on this site is drawn by a public JSON API, and you can call the same endpoints — no key, no
            sign-up, no rate limit, open CORS. {API_CATALOG.length} documented endpoints; {EXECUTABLE_COUNT} of them you
            can run from this page.
          </>
        }
        actions={<Badge label="no auth" variant="teal" />}
      />

      <div className="space-y-5">
        <Card className="px-4 py-4">
          <div className="space-y-1.5">
            <FactRow label="Base URL" value={API_FACTS.baseUrl} copy />
            <FactRow label="Auth" value={API_FACTS.auth} />
            <FactRow label="CORS" value={API_FACTS.cors} />
            <FactRow label="Rate limit" value={API_FACTS.rateLimit} />
            <FactRow label="Errors" value={API_FACTS.errors} />
          </div>
        </Card>

        <div className="grid gap-4 md:grid-cols-2">
          <Card className="px-4 py-4">
            <Section title="Pagination — read this once">
              <p className="text-xs leading-relaxed text-[var(--text-secondary)]">
                Every LIST endpoint takes <code className="text-[var(--accent-teal)]">?page=</code> ({API_FACTS.pagination.page})
                and <code className="text-[var(--accent-teal)]">?limit=</code> ({API_FACTS.pagination.limit}), and answers
                with
              </p>
              <div className="mt-2">
                <CodeBlock wrap>{API_FACTS.pagination.envelope}</CodeBlock>
              </div>
              <p className="mt-2 text-xs font-medium leading-relaxed text-[var(--text-primary)]">
                {API_FACTS.pagination.noOffset}
              </p>
            </Section>
          </Card>

          <Card className="px-4 py-4">
            <Section title="The ?version= contract">
              <p className="text-xs leading-relaxed text-[var(--text-secondary)]">{API_FACTS.versionFilter}</p>
            </Section>
          </Card>
        </div>

        <Card className="px-4 py-4">
          <Section title="Three calls to get the feel of it">
            <CodeBlock>{`curl '${API_FACTS.baseUrl}/techniques/T1059'
curl '${API_FACTS.baseUrl}/cves?severity=CRITICAL&limit=5'
curl '${API_FACTS.baseUrl}/sectors/financial/relationships'`}</CodeBlock>
          </Section>
        </Card>

        <Notice tone="info" title="Also open">
          The same data is served to AI clients over <strong>MCP</strong> and to agents over <strong>A2A</strong> —{' '}
          <Link href="/open-mcp" className="font-semibold text-[var(--accent-teal)] hover:underline">
            Open MCP
          </Link>{' '}
          has the tool catalogue. Machine-readable orientation for crawlers and models lives at{' '}
          <a href={API_FACTS.llmsTxtPath} className="text-[var(--accent-teal)] hover:underline">
            /llms.txt
          </a>
          .
        </Notice>

        {/* Endpoint list */}
        <div>
          <div className="mb-3 flex flex-wrap items-center gap-3">
            <label className="flex-1 min-w-[12rem]">
              <span className="sr-only">Filter endpoints</span>
              <input
                type="search"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="filter by path or description — cves, purdue, advisories…"
                className="w-full rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-3 py-2 text-xs text-[var(--text-primary)] placeholder:text-[var(--text-secondary)] focus:border-[var(--teal-dim)] focus:outline-none"
              />
            </label>
            <span className="text-[11px] text-[var(--text-secondary)]">
              {shown} of {API_CATALOG.length} endpoints
            </span>
          </div>

          {groups.length === 0 ? (
            <Card className="px-4 py-6 text-center text-xs text-[var(--text-secondary)]">
              Nothing matches “{query}”.
            </Card>
          ) : (
            <div className="space-y-5">
              {groups.map((g) => (
                <section key={g.key} aria-labelledby={`group-${g.key}`}>
                  <div className="mb-1.5">
                    <h2
                      id={`group-${g.key}`}
                      className="text-[11px] font-bold uppercase tracking-wider text-[var(--accent-teal)]"
                    >
                      {g.label}{' '}
                      <span className="font-medium normal-case tracking-normal text-[var(--text-secondary)]">
                        · {g.entries.length}
                      </span>
                    </h2>
                    <p className="text-[11px] text-[var(--text-secondary)]">{g.blurb}</p>
                  </div>
                  <Card className="divide-y divide-[var(--border-color)] overflow-hidden">
                    {g.entries.map((e) => (
                      <button
                        key={entryKey(e)}
                        type="button"
                        onClick={(ev) => {
                          triggerRef.current = ev.currentTarget;
                          setSelected(e);
                        }}
                        className="group flex w-full flex-wrap items-baseline gap-x-2 gap-y-1 px-3 py-2 text-left transition-colors hover:bg-[var(--hover-overlay)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[var(--accent-teal)]"
                      >
                        <MethodPill method={e.method} />
                        <code className="font-mono text-xs text-[var(--text-primary)]">{e.path}</code>
                        <span className="text-xs text-[var(--text-secondary)]">{e.summary}</span>
                        {/* Persistent, not hover-revealed: an affordance nobody can see is one
                            nobody uses, and on a touch screen there is no hover at all. Orange on
                            row hover because it is the one thing here that leaves the page and
                            makes a real request. */}
                        <span className="ml-auto shrink-0 text-[10px] font-semibold uppercase tracking-wider text-[var(--text-secondary)] transition-colors group-hover:text-[var(--accent-orange)] group-focus-visible:text-[var(--accent-orange)]">
                          {e.executable ? 'run it →' : 'details →'}
                        </span>
                      </button>
                    ))}
                  </Card>
                </section>
              ))}
            </div>
          )}
        </div>
      </div>

      <EndpointModal entry={selected} onClose={() => setSelected(null)} returnFocusTo={triggerRef} />
    </div>
  );
}
