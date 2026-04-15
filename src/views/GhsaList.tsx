'use client';
import { useCallback, useEffect, useRef, useState } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { useUpdateParams } from '../hooks/useUpdateParams';
import { useGhsa } from '../hooks/useApi';
import { formatDate } from '../lib/formatDate';
import { PageHeader } from '../components/layout/PageHeader';
import { DataTable, type ColumnDef } from '../components/shared/DataTable';
import { Badge } from '../components/shared/Badge';
import type { GhsaEntry } from '../lib/types';

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const ECOSYSTEMS = ['npm', 'pypi', 'go', 'maven', 'rubygems', 'nuget', 'composer', 'rust'];

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'bg-[var(--pink-faint)] text-[var(--accent-pink)] border-[var(--pink-dim)]',
  HIGH: 'bg-[var(--orange-faint)] text-[var(--accent-orange)] border-[var(--orange-dim)]',
  MEDIUM: 'bg-[var(--yellow-faint)] text-[var(--accent-yellow)] border-[var(--yellow-dim)]',
  LOW: 'bg-[var(--blue-faint)] text-[var(--accent-blue)] border-[var(--blue-dim)]',
};

function SeverityBadge({ severity }: { severity: string | null }) {
  if (!severity) return <span className="text-[var(--text-secondary)] text-xs">—</span>;
  const classes = SEVERITY_COLORS[severity] ?? 'bg-[var(--hover-overlay)] text-[var(--text-secondary)] border-[var(--border-color)]';
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${classes}`}>
      {severity}
    </span>
  );
}

const columns: ColumnDef<GhsaEntry>[] = [
  {
    key: 'severity',
    header: 'Severity',
    tooltip: 'GHSA severity (LOW | MEDIUM | HIGH | CRITICAL)',
    width: '100px',
    render: (row) => <SeverityBadge severity={row.severity} />,
  },
  {
    key: 'ghsaId',
    header: 'GHSA ID',
    tooltip: 'GitHub Security Advisory identifier',
    render: (row) => (
      <Link href={`/cti/ghsa/${row.ghsaId}`} className="font-mono text-xs text-[var(--accent-teal)] hover:underline">
        {row.ghsaId}
      </Link>
    ),
  },
  {
    key: 'cveId',
    header: 'CVE alias',
    tooltip: 'Linked CVE ID, if GitHub assigned one',
    width: '140px',
    render: (row) =>
      row.cveId ? (
        <Link href={`/cti/cves/${row.cveId}`} className="font-mono text-xs text-[var(--accent-pink)] hover:underline">
          {row.cveId}
        </Link>
      ) : (
        <span className="text-[var(--text-secondary)] text-xs">—</span>
      ),
  },
  {
    key: 'summary',
    header: 'Summary',
    tooltip: 'Short title from GitHub Security Lab',
    render: (row) =>
      row.summary ? (
        <span className="text-xs text-[var(--text-secondary)] max-w-[440px] line-clamp-2 block leading-relaxed">
          {row.summary}
        </span>
      ) : (
        <span className="text-[var(--text-secondary)] text-xs">—</span>
      ),
  },
  {
    key: 'ecosystems',
    header: 'Ecosystems',
    tooltip: 'Package ecosystems affected',
    width: '150px',
    render: (row) =>
      row.ecosystems.length > 0 ? (
        <div className="flex flex-wrap gap-1">
          {row.ecosystems.slice(0, 3).map((eco) => (
            <Badge key={eco} label={eco} variant="blue" />
          ))}
          {row.ecosystems.length > 3 && (
            <span className="text-[10px] text-[var(--text-secondary)]">+{row.ecosystems.length - 3}</span>
          )}
        </div>
      ) : (
        <span className="text-[var(--text-secondary)] text-xs">—</span>
      ),
  },
  {
    key: 'packageCount',
    header: 'Packages',
    width: '80px',
    align: 'center',
    render: (row) => (
      <span className="text-xs text-[var(--accent-blue)] font-mono">{row.packageCount || '—'}</span>
    ),
  },
  {
    key: 'cvssScore',
    header: 'CVSS',
    tooltip: 'CVSS v3.1 base score',
    width: '70px',
    render: (row) => (
      <span className="text-xs text-[var(--text-primary)] font-mono">
        {row.cvssScore != null ? row.cvssScore.toFixed(1) : '—'}
      </span>
    ),
  },
  {
    key: 'techniqueCount',
    header: 'Techniques',
    tooltip: 'ATT&CK techniques via CWE→CAPEC bridge',
    width: '100px',
    align: 'center',
    render: (row) => (
      <span className="text-xs text-[var(--accent-teal)] font-mono">{row.techniqueCount || '—'}</span>
    ),
  },
  {
    key: 'publishedAt',
    header: 'Published',
    width: '100px',
    render: (row) => (
      <span className="text-[10px] text-[var(--text-secondary)] shrink-0">{formatDate(row.publishedAt)}</span>
    ),
  },
];

export function GhsaList() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const updateParams = useUpdateParams();
  const page = parseInt(searchParams.get('page') ?? '1', 10);
  const severity = searchParams.get('severity') ?? '';
  const ecosystem = searchParams.get('ecosystem') ?? '';
  const q = searchParams.get('q') ?? '';
  const hasCve = searchParams.get('has_cve') ?? '';
  const defaultSince = new Date(Date.now() - 30 * 86400000).toISOString().split('T')[0];
  const since = searchParams.has('since') ? (searchParams.get('since') ?? '') : defaultSince;

  const setParam = useCallback(
    (key: string, value: string) => {
      const updates: Record<string, string | null> = {};
      if (value) updates[key] = value;
      else if (key === 'since') updates[key] = '';
      else updates[key] = null;
      if (key !== 'page') updates.page = '1';
      updateParams(updates);
    },
    [updateParams],
  );

  const [qInput, setQInput] = useState(q);
  const debounceRef = useRef<ReturnType<typeof setTimeout>>(undefined);
  useEffect(() => { setQInput(q); }, [q]);
  useEffect(() => () => clearTimeout(debounceRef.current), []);

  const params: Record<string, string> = { page: String(page), limit: '50' };
  if (severity) params.severity = severity;
  if (ecosystem) params.ecosystem = ecosystem;
  if (q) params.q = q;
  if (hasCve) params.has_cve = hasCve;
  if (since) params.since = since;

  const { data, isLoading } = useGhsa(params);

  return (
    <div className="space-y-4">
      <PageHeader
        title="GitHub Security Advisories"
        subtitle="Library-level vulnerabilities for npm, PyPI, Go, Maven, RubyGems, NuGet, Composer, Rust — mapped to ATT&CK via CWE→CAPEC bridge"
      />

      <div className="flex flex-wrap gap-3 items-center">
        <input
          type="search"
          placeholder="Search GHSA, CVE, or summary..."
          value={qInput}
          aria-label="Search"
          onChange={(e) => {
            setQInput(e.target.value);
            clearTimeout(debounceRef.current);
            debounceRef.current = setTimeout(() => setParam('q', e.target.value), 300);
          }}
          className="min-w-[240px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent-teal)]"
        />

        <select
          value={severity}
          onChange={(e) => setParam('severity', e.target.value)}
          className="px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)]"
        >
          <option value="">All severities</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>

        <select
          value={ecosystem}
          onChange={(e) => setParam('ecosystem', e.target.value)}
          className="px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)]"
        >
          <option value="">All ecosystems</option>
          {ECOSYSTEMS.map((e) => (
            <option key={e} value={e}>{e}</option>
          ))}
        </select>

        <select
          value={hasCve}
          onChange={(e) => setParam('has_cve', e.target.value)}
          className="px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)]"
          title="Filter by CVE alias presence"
        >
          <option value="">With/without CVE</option>
          <option value="true">Has CVE</option>
          <option value="false">GHSA-only</option>
        </select>

        <input
          type="date"
          value={since}
          onChange={(e) => setParam('since', e.target.value)}
          aria-label="Published since"
          className="px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)]"
        />
      </div>

      <DataTable
        columns={columns}
        data={data?.data ?? []}
        loading={isLoading}
        pagination={data?.pagination}
        onPageChange={(p) => setParam('page', String(p))}
        onRowClick={(row) => router.push(`/cti/ghsa/${row.ghsaId}`)}
        rowKey={(row) => row.ghsaId}
        emptyMessage="No GHSA advisories found. First sync may not have run yet."
      />
    </div>
  );
}
