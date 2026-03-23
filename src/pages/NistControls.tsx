import { useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useNistControls } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { DataTable, type ColumnDef } from '../components/shared/DataTable';
import { Badge } from '../components/shared/Badge';
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

const columns: ColumnDef<NistControlSummary>[] = [
  {
    key: 'controlId',
    header: 'Control ID',
    width: '120px',
    render: (row) => (
      <span className="font-mono text-sm text-[var(--accent-teal)]">{row.controlId}</span>
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
    render: (row) => (
      <span className="text-[var(--text-primary)] text-sm font-medium">{row.techniqueCount}</span>
    ),
  },
];

export function NistControls() {
  const [searchParams, setSearchParams] = useSearchParams();
  const search = searchParams.get('search') ?? '';
  const family = searchParams.get('family') ?? '';
  const page = parseInt(searchParams.get('page') ?? '1', 10);

  const params: Record<string, string> = { page: String(page), limit: '50' };
  if (search) params.search = search;
  if (family) params.family = family;

  const { data, isLoading } = useNistControls(params);

  const setParam = useCallback(
    (key: string, value: string) => {
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        if (value) next.set(key, value);
        else next.delete(key);
        if (key !== 'page') next.delete('page');
        return next;
      });
    },
    [setSearchParams],
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
