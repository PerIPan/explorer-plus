'use client';
import { useCallback, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { useUpdateParams } from '../hooks/useUpdateParams';
import { useQuery } from '@tanstack/react-query';
import { useNistControls } from '../hooks/useApi';
import { apiFetch } from '../lib/api';
import { PageHeader } from '../components/layout/PageHeader';
import { DataTable, type ColumnDef } from '../components/shared/DataTable';
import { Badge } from '../components/shared/Badge';
import { EntityLink } from '../components/shared/EntityLink';
import type { NistControlSummary } from '../lib/types';

const NIST_FAMILIES = [
  'Access Control',
  'Audit and Accountability',
  'Assessment, Authorization, and Monitoring',
  'Awareness and Training',
  'Configuration Management',
  'Contingency Planning',
  'Identification and Authentication',
  'Incident Response',
  'Maintenance',
  'Media Protection',
  'Personally Identifiable Information Processing and Transparency',
  'Physical and Environmental Protection',
  'Planning',
  'Program Management',
  'Personnel Security',
  'Risk Assessment',
  'System and Services Acquisition',
  'System and Communications Protection',
  'System and Information Integrity',
  'Supply Chain Risk Management',
];

function TechniquePopover({ controlId, count }: { controlId: string; count: number }) {
  const [open, setOpen] = useState(false);
  const { data, isLoading } = useQuery({
    queryKey: ['nist-techniques', controlId],
    queryFn: () => apiFetch<{ data: Array<{ attackId: string; name: string }> }>(`/frameworks/nist/${controlId}/techniques`),
    enabled: open,
  });

  return (
    <div className="relative">
      <button
        type="button"
        onClick={(e) => { e.stopPropagation(); setOpen(!open); }}
        className="cursor-pointer"
      >
        <Badge label={String(count)} variant="teal" />
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
          <div className="absolute right-0 top-8 z-50 bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg shadow-2xl p-3 min-w-[240px] max-h-[300px] overflow-y-auto">
            <div className="text-[10px] text-[var(--text-secondary)] uppercase tracking-wider mb-2">
              Linked Techniques ({count})
            </div>
            {isLoading && (
              <div className="flex items-center gap-2 text-[var(--text-secondary)] text-xs py-2">
                <span className="inline-block w-3 h-3 border-2 border-[var(--teal-dim)] border-t-[var(--accent-teal)] rounded-full animate-spin" />
                Loading...
              </div>
            )}
            {data?.data && (
              <div className="flex flex-col gap-1">
                {data.data.map((t) => (
                  <EntityLink key={t.attackId} type="technique" attackId={t.attackId} name={t.name} />
                ))}
              </div>
            )}
            {!isLoading && data?.data?.length === 0 && (
              <span className="text-xs text-[var(--text-secondary)]">No techniques found.</span>
            )}
          </div>
        </>
      )}
    </div>
  );
}

const columns: ColumnDef<NistControlSummary>[] = [
  {
    key: 'controlId',
    header: 'Control ID',
    width: '120px',
    render: (row) => (
      <a
        href={`https://csf.tools/reference/nist-sp-800-53/r5/${row.controlId.split('-')[0].toLowerCase()}/${row.controlId.replace(/-0+/g, '-').toLowerCase()}/`}
        target="_blank"
        rel="noopener noreferrer"
        className="font-mono text-sm text-[var(--accent-teal)] hover:underline"
      >
        {row.controlId}
      </a>
    ),
  },
  {
    key: 'controlName',
    header: 'Control Name',
    render: (row) => (
      <span className="text-[var(--text-primary)] text-sm">{row.controlName ?? '—'}</span>
    ),
  },
  {
    key: 'controlFamily',
    header: 'Family',
    width: '240px',
    render: (row) =>
      row.controlFamily ? (
        <Badge label={row.controlFamily} variant="blue" />
      ) : (
        <span className="text-[var(--text-secondary)] text-xs">—</span>
      ),
  },
  {
    key: 'techniqueCount',
    header: 'Techniques',
    width: '100px',
    align: 'center',
    render: (row) =>
      row.techniqueCount > 0 ? (
        <TechniquePopover controlId={row.controlId} count={row.techniqueCount} />
      ) : (
        <span className="text-[var(--text-secondary)] text-xs">—</span>
      ),
  },
];

export function NistControls() {

  const searchParams = useSearchParams();
  const updateParams = useUpdateParams();
  const search = searchParams.get('search') ?? '';
  const family = searchParams.get('family') ?? '';
  const page = parseInt(searchParams.get('page') ?? '1', 10);

  const params: Record<string, string> = { page: String(page), limit: '50' };
  if (search) params.search = search;
  if (family) params.family = family;

  const { data, isLoading } = useNistControls(params);

  const setParam = useCallback(
    (key: string, value: string) => {
      const updates: Record<string, string | null> = {
        [key]: value || null,
      };
      if (key !== 'page') updates.page = null;
      updateParams(updates);
    },
    [updateParams],
  );

  return (
    <div className="space-y-6">
      <PageHeader
        title="NIST 800-53 Controls"
        subtitle={`${data?.pagination?.total ?? 0} unique controls mapped to ATT&CK techniques`}
      />

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <input
          type="search"
          placeholder="Search controls..."
          value={search}
          onChange={(e) => setParam('search', e.target.value)}
          className="
            flex-1 min-w-[200px] max-w-sm px-3 py-2 rounded-md text-sm
            bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)]
            placeholder:text-[var(--text-secondary)]
            focus:outline-none focus:ring-1 focus:ring-[var(--accent-teal)] focus:border-[var(--accent-teal)]
          "
        />
        <select
          value={family}
          onChange={(e) => setParam('family', e.target.value)}
          className="
            px-3 py-2 rounded-md text-sm
            bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)]
            focus:outline-none focus:ring-1 focus:ring-[var(--accent-teal)] focus:border-[var(--accent-teal)]
          "
        >
          <option value="">All families</option>
          {NIST_FAMILIES.map((f) => (
            <option key={f} value={f}>{f}</option>
          ))}
        </select>
      </div>

      <DataTable
        columns={columns}
        data={data?.data ?? []}
        loading={isLoading}
        pagination={data?.pagination}
        onPageChange={(p) => setParam('page', String(p))}
        rowKey={(row) => row.controlId}
        emptyMessage="No NIST controls found. Run the sync script to populate data."
      />
    </div>
  );
}
