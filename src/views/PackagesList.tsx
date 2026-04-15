'use client';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { useUpdateParams } from '../hooks/useUpdateParams';
import { usePackages, usePackageDetail } from '../hooks/useApi';
import { formatDate } from '../lib/formatDate';
import { PageHeader } from '../components/layout/PageHeader';
import { DataTable, type ColumnDef } from '../components/shared/DataTable';
import { Badge } from '../components/shared/Badge';
import { EntityLink } from '../components/shared/EntityLink';
import type { PackageListEntry } from '../lib/types';

const ECOSYSTEMS = ['npm', 'pypi', 'go', 'maven', 'rubygems', 'nuget', 'composer', 'rust', 'erlang', 'pub', 'swift', 'actions'];

const SEVERITY_VARIANTS: Record<string, 'pink' | 'orange' | 'yellow' | 'blue' | 'neutral'> = {
  CRITICAL: 'pink',
  HIGH: 'orange',
  MEDIUM: 'yellow',
  LOW: 'blue',
};

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

function highestSeverity(severities: string[]): string | null {
  for (const s of SEVERITY_ORDER) if (severities.includes(s)) return s;
  return severities[0] ?? null;
}

/** Popover fired from the techniques-count cell — lazy-loads the package detail
 *  and shows the linked ATT&CK techniques. */
function TechniquesPopover({ row, onClose }: { row: PackageListEntry; onClose: () => void }) {
  const { data, isLoading } = usePackageDetail(row.ecosystem, encodeURIComponent(row.packageName));
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const onDocClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    };
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('mousedown', onDocClick);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDocClick);
      document.removeEventListener('keydown', onKey);
    };
  }, [onClose]);

  return (
    <div
      ref={ref}
      role="dialog"
      aria-label={`Techniques linked to ${row.packageName}`}
      onClick={(e) => e.stopPropagation()}
      className="absolute right-0 top-full mt-1 z-20 w-[340px] max-h-[320px] overflow-y-auto bg-[var(--surface-card)] border border-[var(--border-color)] rounded-md shadow-xl p-3 text-left"
    >
      <div className="flex items-center justify-between mb-2">
        <span className="text-[10px] uppercase tracking-wider text-[var(--text-secondary)]">
          {row.ecosystem}/{row.packageName} — techniques
        </span>
        <button
          type="button"
          onClick={onClose}
          className="text-[var(--text-secondary)] hover:text-[var(--text-primary)] text-xs"
        >
          ✕
        </button>
      </div>
      {isLoading ? (
        <div className="text-xs text-[var(--text-secondary)] py-2">Loading techniques…</div>
      ) : !data || data.linkedTechniques.length === 0 ? (
        <div className="text-xs text-[var(--text-secondary)] py-2">No techniques linked.</div>
      ) : (
        <div className="flex flex-wrap gap-1.5">
          {data.linkedTechniques.map((t) => (
            <EntityLink key={t.attackId} type="technique" attackId={t.attackId} name={t.name} useMap />
          ))}
        </div>
      )}
    </div>
  );
}

function TechniquesCell({ row }: { row: PackageListEntry }) {
  const [open, setOpen] = useState(false);
  if (!row.techniqueCount) {
    return <span className="text-xs text-[var(--text-secondary)]">—</span>;
  }
  return (
    <div className="relative inline-block">
      <button
        type="button"
        onClick={(e) => { e.stopPropagation(); setOpen((v) => !v); }}
        aria-expanded={open}
        aria-haspopup="dialog"
        className="text-xs font-mono text-[var(--accent-teal)] hover:underline cursor-pointer"
        title="View linked ATT&CK techniques"
      >
        {row.techniqueCount}
      </button>
      {open && <TechniquesPopover row={row} onClose={() => setOpen(false)} />}
    </div>
  );
}

const columns: ColumnDef<PackageListEntry>[] = [
  {
    key: 'ecosystem',
    header: 'Ecosystem',
    width: '110px',
    render: (row) => <Badge label={row.ecosystem} variant="blue" />,
  },
  {
    key: 'packageName',
    header: 'Package',
    render: (row) => (
      <span className="text-sm text-[var(--text-primary)] font-medium break-all">{row.packageName}</span>
    ),
  },
  {
    key: 'advisoryCount',
    header: 'Advisories',
    width: '100px',
    align: 'center',
    render: (row) => <Badge label={String(row.advisoryCount)} variant="pink" />,
  },
  {
    key: 'severities',
    header: 'Severity',
    tooltip: 'Highest severity across active advisories',
    width: '110px',
    render: (row) => {
      const top = highestSeverity(row.severities);
      return top ? (
        <Badge label={top} variant={SEVERITY_VARIANTS[top] ?? 'neutral'} />
      ) : (
        <span className="text-[var(--text-secondary)] text-xs">—</span>
      );
    },
  },
  {
    key: 'latestPublished',
    header: 'Latest',
    width: '100px',
    render: (row) => (
      <span className="text-[10px] text-[var(--text-secondary)]">
        {row.latestPublished ? formatDate(row.latestPublished) : '—'}
      </span>
    ),
  },
  {
    key: 'techniqueCount',
    header: 'Techniques',
    tooltip: 'ATT&CK techniques reachable via advisories\' CWE→CAPEC bridge — click count to list',
    width: '110px',
    align: 'center',
    render: (row) => <TechniquesCell row={row} />,
  },
];

export function PackagesList() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const updateParams = useUpdateParams();
  const page = parseInt(searchParams.get('page') ?? '1', 10);
  const ecosystem = searchParams.get('ecosystem') ?? '';
  const q = searchParams.get('q') ?? '';

  const setParam = useCallback(
    (key: string, value: string) => {
      const updates: Record<string, string | null> = { [key]: value || null };
      if (key !== 'page') updates.page = '1';
      updateParams(updates);
    },
    [updateParams],
  );

  const [qInput, setQInput] = useState(q);
  const debounceRef = useRef<ReturnType<typeof setTimeout>>(undefined);
  useEffect(() => { setQInput(q); }, [q]);
  useEffect(() => () => clearTimeout(debounceRef.current), []);

  const params = useMemo(() => {
    const p: Record<string, string> = { page: String(page), limit: '50' };
    if (ecosystem) p.ecosystem = ecosystem;
    if (q) p.q = q;
    return p;
  }, [page, ecosystem, q]);

  const { data, isLoading } = usePackages(params);

  return (
    <div className="space-y-4">
      <PageHeader
        title="Packages"
        subtitle="Library and dependency packages with GitHub Security Advisories — parallel to Applications (which are vendor products)"
      />

      <div className="flex flex-wrap gap-3 items-center">
        <input
          type="search"
          placeholder="Search package name..."
          value={qInput}
          aria-label="Search package name"
          onChange={(e) => {
            setQInput(e.target.value);
            clearTimeout(debounceRef.current);
            debounceRef.current = setTimeout(() => setParam('q', e.target.value), 300);
          }}
          className="min-w-[260px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent-teal)]"
        />

        <select
          value={ecosystem}
          onChange={(e) => setParam('ecosystem', e.target.value)}
          className="px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)]"
        >
          <option value="">All ecosystems</option>
          {ECOSYSTEMS.map((eco) => (
            <option key={eco} value={eco}>{eco}</option>
          ))}
        </select>
      </div>

      <DataTable
        columns={columns}
        data={data?.data ?? []}
        loading={isLoading}
        pagination={data?.pagination}
        onPageChange={(p) => setParam('page', String(p))}
        onRowClick={(row) =>
          router.push(`/packages/${row.ecosystem}/${encodeURIComponent(row.packageName)}`)
        }
        rowKey={(row) => row.packageId}
        emptyMessage="No packages found. First GHSA sync may not have run yet."
      />
    </div>
  );
}
