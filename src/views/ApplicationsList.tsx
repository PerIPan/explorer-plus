'use client';
import { useCallback, useEffect, useRef, useState } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { useUpdateParams } from '../hooks/useUpdateParams';
import { useQuery } from '@tanstack/react-query';
import { apiFetch } from '../lib/api';
import { PageHeader } from '../components/layout/PageHeader';
import { DataTable, type ColumnDef } from '../components/shared/DataTable';
import { Badge } from '../components/shared/Badge';

interface Application {
  id: string;
  vendor: string;
  product: string;
  normalized: string;
  cpePrefix: string | null;
  cveCount: number;
  topSeverity: string | null;
  techniqueCount: number;
  groupCount: number;
}

interface PaginatedResponse {
  data: Application[];
  pagination: { page: number; limit: number; total: number; totalPages: number };
}

const SEVERITY_VARIANTS: Record<string, 'pink' | 'orange' | 'yellow' | 'blue' | 'neutral'> = {
  CRITICAL: 'pink',
  HIGH: 'orange',
  MEDIUM: 'yellow',
  LOW: 'blue',
};

const columns: ColumnDef<Application>[] = [
  {
    key: 'vendor',
    header: 'Vendor',
    render: (row) => (
      <span className="text-sm text-[var(--text-primary)] font-medium">{row.vendor}</span>
    ),
  },
  {
    key: 'product',
    header: 'Product',
    render: (row) => (
      <span className="text-sm text-[var(--text-primary)]">{row.product}</span>
    ),
  },
  {
    key: 'cveCount',
    header: 'CVEs',
    width: '80px',
    align: 'center',
    render: (row) => <Badge label={String(row.cveCount)} variant="pink" />,
  },
  {
    key: 'topSeverity',
    header: 'Top Severity',
    width: '110px',
    render: (row) =>
      row.topSeverity ? (
        <Badge label={row.topSeverity} variant={SEVERITY_VARIANTS[row.topSeverity] ?? 'neutral'} />
      ) : (
        <span className="text-[var(--text-secondary)] text-xs">—</span>
      ),
  },
  {
    key: 'techniqueCount',
    header: 'Techniques',
    tooltip: 'ATT&CK techniques reachable via CVE→CWE→CAPEC chain',
    width: '100px',
    align: 'center',
    render: (row) => (
      <span className="text-xs text-[var(--accent-teal)] font-mono">{row.techniqueCount || '—'}</span>
    ),
  },
  {
    key: 'groupCount',
    header: 'Groups',
    tooltip: 'Threat groups using reachable techniques',
    width: '80px',
    align: 'center',
    render: (row) => (
      <span className="text-xs text-[var(--accent-orange)] font-mono">{row.groupCount || '—'}</span>
    ),
  },
];

export function ApplicationsList() {

  const router = useRouter();
  const searchParams = useSearchParams();
  const updateParams = useUpdateParams();
  const page = parseInt(searchParams.get('page') ?? '1', 10);
  const search = searchParams.get('search') ?? '';
  const [searchInput, setSearchInput] = useState(search);
  const debounceRef = useRef<ReturnType<typeof setTimeout>>(undefined);
  useEffect(() => { setSearchInput(search); }, [search]);
  useEffect(() => () => clearTimeout(debounceRef.current), []);

  const setParam = useCallback(
    (key: string, value: string) => {
      const updates: Record<string, string | null> = {
        [key]: value || null,
      };
      if (key !== 'page') updates.page = '1';
      updateParams(updates);
    },
    [updateParams],
  );

  const params: Record<string, string> = { page: String(page), limit: '50' };
  if (search) params.search = search;

  const { data, isLoading } = useQuery({
    queryKey: ['applications', params],
    queryFn: () => apiFetch<PaginatedResponse>('/applications', params),
  });

  return (
    <div className="space-y-4">
      <PageHeader
        title="Applications"
        subtitle="Vendor products with known CVEs mapped to ATT&CK techniques via CWE→CAPEC bridge"
      />

      <div className="flex flex-wrap gap-3">
        <input
          type="search"
          placeholder="Search vendor or product..."
          value={searchInput}
          aria-label="Search vendor or product"
          onChange={(e) => {
            setSearchInput(e.target.value);
            clearTimeout(debounceRef.current);
            debounceRef.current = setTimeout(() => setParam('search', e.target.value), 300);
          }}
          className="min-w-[250px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent-teal)]"
        />
      </div>

      <DataTable
        columns={columns}
        data={data?.data ?? []}
        loading={isLoading}
        pagination={data?.pagination}
        onPageChange={(p) => setParam('page', String(p))}
        onRowClick={(row) => router.push(`/?entity=${encodeURIComponent(row.normalized)}&tab=application-map`)}
        rowKey={(row) => row.id}
        emptyMessage="No applications found."
      />
    </div>
  );
}
