'use client';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { useUpdateParams } from '../hooks/useUpdateParams';
import { useCapecPatterns } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { DataTable, type ColumnDef } from '../components/shared/DataTable';
import { Badge } from '../components/shared/Badge';
import type { CapecListEntry } from '../lib/types';

const SEVERITY_VARIANTS: Record<string, 'pink' | 'orange' | 'yellow' | 'blue' | 'neutral'> = {
  'Very High': 'pink',
  'High': 'orange',
  'Medium': 'yellow',
  'Low': 'blue',
  'Very Low': 'neutral',
};

const LIKELIHOOD_VARIANTS: Record<string, 'orange' | 'yellow' | 'blue' | 'neutral'> = {
  High: 'orange',
  Medium: 'yellow',
  Low: 'blue',
};

const ABSTRACTIONS = ['Meta', 'Standard', 'Detailed'] as const;
const SEVERITIES = ['Very High', 'High', 'Medium', 'Low', 'Very Low'] as const;
const LIKELIHOODS = ['High', 'Medium', 'Low'] as const;

const columns: ColumnDef<CapecListEntry>[] = [
  {
    key: 'capecId',
    header: 'CAPEC',
    width: '110px',
    render: (row) => <span className="font-mono text-xs text-[var(--accent-yellow)]">{row.capecId}</span>,
  },
  {
    key: 'name',
    header: 'Pattern',
    render: (row) => (
      <span className="text-sm text-[var(--text-primary)] font-medium">{row.name}</span>
    ),
  },
  {
    key: 'abstraction',
    header: 'Abstraction',
    width: '100px',
    render: (row) =>
      row.abstraction ? (
        <Badge label={row.abstraction} variant="neutral" />
      ) : (
        <span className="text-xs text-[var(--text-secondary)]">—</span>
      ),
  },
  {
    key: 'severity',
    header: 'Severity',
    width: '100px',
    render: (row) =>
      row.severity ? (
        <Badge label={row.severity} variant={SEVERITY_VARIANTS[row.severity] ?? 'neutral'} />
      ) : (
        <span className="text-xs text-[var(--text-secondary)]">—</span>
      ),
  },
  {
    key: 'likelihood',
    header: 'Likelihood',
    width: '100px',
    render: (row) =>
      row.likelihood ? (
        <Badge label={row.likelihood} variant={LIKELIHOOD_VARIANTS[row.likelihood] ?? 'neutral'} />
      ) : (
        <span className="text-xs text-[var(--text-secondary)]">—</span>
      ),
  },
  {
    key: 'techniqueCount',
    header: 'Techniques',
    width: '100px',
    align: 'center',
    tooltip: 'ATT&CK techniques linked via CAPEC mappings bridge',
    render: (row) => (
      <span className="text-xs text-[var(--accent-teal)] font-mono">{row.techniqueCount || '—'}</span>
    ),
  },
  {
    key: 'mitigationCount',
    header: 'Mitigations',
    width: '100px',
    align: 'center',
    render: (row) => (
      <span className="text-xs text-[var(--accent-green)] font-mono">{row.mitigationCount || '—'}</span>
    ),
  },
];

export function CapecList() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const updateParams = useUpdateParams();
  const page = parseInt(searchParams.get('page') ?? '1', 10);
  const q = searchParams.get('q') ?? '';
  const abstraction = searchParams.get('abstraction') ?? '';
  const severity = searchParams.get('severity') ?? '';
  const likelihood = searchParams.get('likelihood') ?? '';

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
    if (q) p.q = q;
    if (abstraction) p.abstraction = abstraction;
    if (severity) p.severity = severity;
    if (likelihood) p.likelihood = likelihood;
    return p;
  }, [page, q, abstraction, severity, likelihood]);

  const { data, isLoading } = useCapecPatterns(params);

  return (
    <div className="space-y-4">
      <PageHeader
        title="CAPEC Attack Patterns"
        subtitle="MITRE Common Attack Pattern Enumeration and Classification — 615 patterns with severity, likelihood, prerequisites, consequences, and mitigations"
      />

      <div className="flex flex-wrap gap-3 items-center">
        <input
          type="search"
          placeholder="Search pattern name or CAPEC ID..."
          value={qInput}
          aria-label="Search CAPEC patterns"
          onChange={(e) => {
            setQInput(e.target.value);
            clearTimeout(debounceRef.current);
            debounceRef.current = setTimeout(() => setParam('q', e.target.value), 300);
          }}
          className="min-w-[260px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent-teal)]"
        />
        <select
          value={abstraction}
          aria-label="Filter by abstraction"
          onChange={(e) => setParam('abstraction', e.target.value)}
          className="px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)]"
        >
          <option value="">All abstractions</option>
          {ABSTRACTIONS.map((a) => <option key={a} value={a}>{a}</option>)}
        </select>
        <select
          value={severity}
          aria-label="Filter by severity"
          onChange={(e) => setParam('severity', e.target.value)}
          className="px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)]"
        >
          <option value="">All severities</option>
          {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select
          value={likelihood}
          aria-label="Filter by likelihood"
          onChange={(e) => setParam('likelihood', e.target.value)}
          className="px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)]"
        >
          <option value="">All likelihoods</option>
          {LIKELIHOODS.map((l) => <option key={l} value={l}>{l}</option>)}
        </select>
      </div>

      <DataTable
        columns={columns}
        data={data?.data ?? []}
        loading={isLoading}
        pagination={data?.pagination}
        onPageChange={(p) => setParam('page', String(p))}
        onRowClick={(row) => router.push(`/cti/capec/${row.capecId}`)}
        rowKey={(row) => row.capecId}
        emptyMessage="No CAPEC patterns match your filters."
      />
    </div>
  );
}
