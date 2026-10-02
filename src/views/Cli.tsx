'use client';

import Link from 'next/link';
import { PageHeader } from '../components/layout/PageHeader';
import { Card, Notice } from '../components/profile/BriefingPrimitives';
import { CodeBlock, FactRow, Section } from '../components/api/primitives';
import { API_CATALOG, API_FACTS, API_GROUP_META, entriesInGroup } from '../lib/api-catalog';
import { CLI_COMMAND_NAME } from '../lib/site';
import { invocationFor } from '../lib/cli-command.mjs';

/**
 * /cli — the command list, generated.
 *
 * Every row comes from API_CATALOG through `invocationFor`, the SAME rule
 * scripts/gen-cli.mjs uses to build the table that ships in the package
 * (src/lib/cli-command.mjs). Deriving the commands twice would drift, and the
 * drift would be silent in the worst direction: this page documenting commands
 * the CLI does not have. `npm run check:cli` fails if the shipped table stops
 * matching the catalogue.
 *
 * Grouped by the same API_GROUP_META the /open-apis page uses, so a reader who
 * knows one page can navigate the other.
 *
 * This page is also the package's `homepage` field, which is why it exists
 * before the package does.
 */
export function Cli() {
  const groups = API_GROUP_META.map((g) => ({ ...g, entries: entriesInGroup(g.key) })).filter(
    (g) => g.entries.length > 0,
  );

  return (
    <div>
      <PageHeader
        title="CLI"
        subtitle={
          <>
            <strong>{CLI_COMMAND_NAME}</strong> — this site from the command line. {API_CATALOG.length}{' '}
            commands, one per endpoint, generated from the same catalogue{' '}
            <Link href="/open-apis" className="text-[var(--accent-teal)] hover:underline">
              Open APIs
            </Link>{' '}
            renders, so the two cannot disagree. Read-only, no key, no account.
          </>
        }
      />

      <div className="mb-6">
        <Notice tone="warn" title="Not published yet">
          <code className="font-mono">{CLI_COMMAND_NAME}</code> is not on npm, so there is nothing to install
          today. It is a convenience wrapper over the REST API and adds no capability — every
          command below is a GET you can make right now with{' '}
          <code className="font-mono">curl</code> against{' '}
          <code className="font-mono">{API_FACTS.baseUrl}</code>. This page lists what it will do.
        </Notice>
      </div>

      <Card className="mb-6 p-4">
        <div className="space-y-1.5">
          <FactRow label="Command" value={CLI_COMMAND_NAME} copy />
          <FactRow label="Commands" value={`${API_CATALOG.length}, one per endpoint`} />
          <FactRow label="Runtime" value="Node 22.8+ · zero runtime dependencies" />
          <FactRow label="Scope" value="read-only — every command is a GET" />
          <FactRow label="Auth" value={API_FACTS.auth} />
          <FactRow label="Output" value="aligned table in a terminal, JSON when piped" />
        </div>
      </Card>

      <Section title="Usage">
        <CodeBlock>{`${CLI_COMMAND_NAME} techniques T1059
${CLI_COMMAND_NAME} groups --search lazarus
${CLI_COMMAND_NAME} cves --severity CRITICAL --limit 5 | jq '.data[].cveId'

${CLI_COMMAND_NAME} --help              the resources, with examples
${CLI_COMMAND_NAME} help techniques     every command for one resource, with its flags
${CLI_COMMAND_NAME} ls                  all ${API_CATALOG.length} commands, one per line`}</CodeBlock>
        <p className="mt-2 text-xs text-[var(--text-secondary)] leading-relaxed">
          It detects a terminal and renders a table; it detects a pipe and emits JSON, so{' '}
          <code className="font-mono">jq</code> works without a flag. An unknown command suggests
          the closest real one rather than printing all {API_CATALOG.length}. Shell completion for
          bash, zsh and fish is generated from the same table.
        </p>
      </Section>

      <div className="mt-6 space-y-6">
        {groups.map((g) => (
          <section key={g.key}>
            <h2 className="text-sm font-semibold text-[var(--text-primary)] mb-1">{g.label}</h2>
            <p className="text-xs text-[var(--text-secondary)] mb-2">{g.blurb}</p>
            <Card className="divide-y divide-[var(--border-color)]">
              {g.entries.map((e) => (
                <div
                  key={e.path}
                  className="flex flex-wrap items-baseline gap-x-3 gap-y-1 px-3 py-2"
                >
                  <code className="font-mono text-xs text-[var(--text-primary)] shrink-0">
                    {invocationFor(e, CLI_COMMAND_NAME)}
                  </code>
                  <span className="text-xs text-[var(--text-secondary)] min-w-0">{e.summary}</span>
                </div>
              ))}
            </Card>
          </section>
        ))}
      </div>

      <p className="mt-6 border-t border-[var(--border-color)] pt-3 text-xs text-[var(--text-secondary)]">
        Positional arguments are shown by name — <code className="font-mono">{CLI_COMMAND_NAME}{' '}
        techniques attackId</code> means <code className="font-mono">{CLI_COMMAND_NAME} techniques
        T1059</code>. Flags
        mirror each endpoint&rsquo;s query parameters;{' '}
        <Link href="/open-apis" className="font-semibold text-[var(--accent-teal)] hover:underline">
          Open APIs →
        </Link>{' '}
        documents them per endpoint, with a Run button for each.
      </p>
    </div>
  );
}
