'use client';
import { useCallback, useMemo } from 'react';
import { useSearchParams } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import { useDebouncedSearchParam } from '../hooks/useDebouncedSearchParam';
import { useUpdateParams } from '../hooks/useUpdateParams';
import { apiFetch } from '../lib/api';
import { PageHeader } from '../components/layout/PageHeader';
import { DataTable, type ColumnDef } from '../components/shared/DataTable';
import { Badge } from '../components/shared/Badge';
import { EntityLink } from '../components/shared/EntityLink';

interface ScfControl {
  scfId: string;
  domain: string;
  name: string;
  description: string;
  techniques: string[];
  unresolvedCount: number;
}

interface ScfMeta {
  controls: number;
  domains: number;
  mappedControls: number;
  mappings: number;
  frameworksCrosswalked: number;
  coverageNote: string;
  licence: string;
}

interface ScfResponse {
  data: ScfControl[];
  meta: ScfMeta;
  pagination: { page: number; limit: number; total: number; totalPages: number };
}

const columns: ColumnDef<ScfControl>[] = [
  {
    key: 'scfId',
    header: 'Control',
    width: '130px',
    render: (row) => <span className="font-mono text-sm text-[var(--accent-teal)]">{row.scfId}</span>,
  },
  {
    key: 'name',
    header: 'Control name',
    render: (row) => (
      <div className="min-w-0">
        <div className="text-sm text-[var(--text-primary)]">{row.name}</div>
        <div className="mt-0.5 line-clamp-2 text-[11px] leading-snug text-[var(--text-secondary)]">
          {row.description}
        </div>
      </div>
    ),
  },
  {
    key: 'domain',
    header: 'Domain',
    width: '230px',
    render: (row) => <Badge label={row.domain} variant="blue" />,
  },
  {
    key: 'techniques',
    header: 'ATT&CK',
    width: '220px',
    render: (row) =>
      row.techniques.length === 0 ? (
        // Most SCF controls have no ATT&CK counterpart by nature. An em dash
        // states that without dressing it up as a gap in our data.
        <span className="text-xs text-[var(--text-secondary)]">—</span>
      ) : (
        <div className="flex flex-wrap gap-1">
          {row.techniques.slice(0, 6).map((t) => (
            <EntityLink
              key={t}
              type="technique"
              attackId={t}
              name={t}
              className="font-mono text-[11px] text-[var(--accent-teal)] hover:underline"
            />
          ))}
          {row.techniques.length > 6 && (
            <span className="text-[11px] text-[var(--text-secondary)]">+{row.techniques.length - 6}</span>
          )}
        </div>
      ),
  },
];

export function ScfFramework() {
  const searchParams = useSearchParams();
  const updateParams = useUpdateParams();
  const search = searchParams.get('search') ?? '';
  const domain = searchParams.get('domain') ?? '';
  /**
   * ATT&CK-mapped is ON unless the URL says otherwise.
   *
   * 1,426 of the 1,534 controls have no ATT&CK counterpart, so an unfiltered
   * first page is 50 rows of em dashes — technically the whole catalogue,
   * practically a wall of nothing for anyone who arrived from Compliance.
   * `?mapped=0` turns it off; the param is never FORWARDED as 0, because the
   * route's enum accepts only 1 or true and would 400 on it.
   */
  const mappedParam = searchParams.get('mapped');
  const mappedOnly = mappedParam === null ? true : mappedParam !== '0';
  const page = parseInt(searchParams.get('page') ?? '1', 10);
  const searchBox = useDebouncedSearchParam('search');

  const params = useMemo(() => {
    const p: Record<string, string> = { page: String(page), limit: '50' };
    if (search) p.search = search;
    if (domain) p.domain = domain;
    if (mappedOnly) p.mapped = '1';
    return p;
  }, [page, search, domain, mappedOnly]);

  const { data, isLoading } = useQuery({
    queryKey: ['scf-controls', params],
    queryFn: () => apiFetch<ScfResponse>('/frameworks/scf', params),
  });

  /* The domain list comes from an unfiltered call, so narrowing the table never
     empties the picker you narrowed it with. */
  const { data: domainSource } = useQuery({
    queryKey: ['scf-domains'],
    queryFn: () => apiFetch<ScfResponse>('/frameworks/scf', { limit: '5000' }),
    staleTime: 60 * 60 * 1000,
  });
  const domains = useMemo(
    () => [...new Set((domainSource?.data ?? []).map((c) => c.domain))].sort(),
    [domainSource],
  );

  const setParam = useCallback(
    (key: string, value: string) => {
      const updates: Record<string, string | null> = { [key]: value || null };
      if (key !== 'page') updates.page = null;
      updateParams(updates);
    },
    [updateParams],
  );

  const meta = data?.meta;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Secure Controls Framework"
        subtitle={
          <>
            The control catalogue every framework on{' '}
            <Link href="/compliance" className="text-[var(--accent-teal)] hover:underline">
              Compliance
            </Link>{' '}
            is crosswalked through — {meta?.frameworksCrosswalked ?? 254} of them. Not a regulation
            itself: the common spine that lets one control satisfy many.
          </>
        }
        actions={<Badge label="CC BY 4.0" variant="neutral" />}
      />

      {meta && (
        <div className="grid gap-3 sm:grid-cols-3">
          <Stat value={meta.controls.toLocaleString()} label="controls" sub={`across ${meta.domains} domains`} />
          <Stat
            value={meta.frameworksCrosswalked.toLocaleString()}
            label="frameworks crosswalked"
            sub="NIS2, DORA, PCI DSS, ISO, HIPAA…"
          />
          <Stat
            value={`${meta.mappedControls.toLocaleString()} of ${meta.controls.toLocaleString()}`}
            label="carry an ATT&CK mapping"
            sub={`${meta.mappings.toLocaleString()} mappings in total`}
          />
        </div>
      )}

      {/* Said plainly and up front, because the stat above invites the opposite
          reading: the narrow ATT&CK coverage is a property of the source, not a
          hole in the ingest, and the page should not let anyone assume either. */}
      <p className="rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-3 py-2.5 text-xs leading-relaxed text-[var(--text-secondary)]">
        Showing the controls that bridge to ATT&amp;CK. The other{' '}
        {meta ? (meta.controls - meta.mappedControls).toLocaleString() : '1,426'} have no ATT&amp;CK
        counterpart, and that is correct rather than missing — governance, privacy, procurement and
        personnel controls describe obligations, not adversary behaviour. Switch off{' '}
        <strong className="font-semibold text-[var(--text-primary)]">ATT&amp;CK-mapped only</strong> to
        browse the whole catalogue.
      </p>

      <div className="flex flex-wrap gap-3">
        <input
          type="search"
          placeholder="Search controls, names, descriptions…"
          value={searchBox.value}
          onChange={(e) => searchBox.onChange(e.target.value)}
          className="flex-1 min-w-[200px] max-w-sm rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-3 py-2 text-sm text-[var(--text-primary)] placeholder:text-[var(--text-secondary)] focus:border-[var(--accent-teal)] focus:outline-none focus:ring-1 focus:ring-[var(--accent-teal)]"
        />
        <select
          value={domain}
          onChange={(e) => setParam('domain', e.target.value)}
          className="rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-3 py-2 text-sm text-[var(--text-primary)] focus:border-[var(--accent-teal)] focus:outline-none focus:ring-1 focus:ring-[var(--accent-teal)]"
        >
          <option value="">All {meta?.domains ?? ''} domains</option>
          {domains.map((d) => (
            <option key={d} value={d}>{d}</option>
          ))}
        </select>
        <button
          type="button"
          onClick={() => setParam('mapped', mappedOnly ? '0' : '')}
          aria-pressed={mappedOnly}
          className={`rounded-md border px-3 py-2 text-sm transition-colors ${
            mappedOnly
              ? 'border-[var(--accent-teal)] bg-[var(--teal-faint)] text-[var(--accent-teal)]'
              : 'border-[var(--border-color)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
          }`}
        >
          ATT&amp;CK-mapped only
        </button>
      </div>

      <DataTable
        columns={columns}
        data={data?.data ?? []}
        loading={isLoading}
        pagination={data?.pagination}
        onPageChange={(p) => setParam('page', String(p))}
        rowKey={(row) => row.scfId}
        emptyMessage="No SCF controls match those filters."
      />

      <p className="text-[11px] text-[var(--text-secondary)]">
        Control text ©{' '}
        <a
          href="https://www.securecontrolsframework.com/"
          target="_blank"
          rel="noopener noreferrer"
          className="text-[var(--accent-teal)] hover:underline"
        >
          Secure Controls Framework
        </a>
        , used under CC BY 4.0. See{' '}
        <Link href="/about/attributions" className="text-[var(--accent-teal)] hover:underline">
          data attributions
        </Link>
        .
      </p>
    </div>
  );
}

function Stat({ value, label, sub }: { value: string; label: string; sub: string }) {
  return (
    <div className="rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-4 py-3">
      <div className="text-xl font-bold text-[var(--accent-teal)]">{value}</div>
      <div className="text-xs font-medium text-[var(--text-primary)]">{label}</div>
      <div className="mt-0.5 text-[11px] text-[var(--text-secondary)]">{sub}</div>
    </div>
  );
}
