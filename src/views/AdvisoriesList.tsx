'use client';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { useUpdateParams } from '../hooks/useUpdateParams';
import { useAdvisories } from '../hooks/useApi';
import { formatDate } from '../lib/formatDate';
import { PageHeader } from '../components/layout/PageHeader';
import { DataTable, type ColumnDef } from '../components/shared/DataTable';
import { Badge } from '../components/shared/Badge';
import type { AdvisoryListEntry } from '../lib/types';
import {
  ADVISORY_CATEGORY_KEYS,
  ADVISORY_ECOSYSTEM_CATEGORIES,
  type AdvisoryEcosystemCategory,
} from '../lib/advisoryEcosystems';

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

// Ecosystem options surface as-typed by the backend filter:
//   - GHSA ecosystems are lower-cased internally, so we match lowercase values
//   - OSV ecosystems are case-preserved by the ingest, so we match exact labels
// The API handles both: `LOWER(p.ecosystem) = $n` on the GHSA side,
// `o.ecosystem = $n` on the OSV side.
const ECOSYSTEMS: Array<{ label: string; value: string }> = [
  { label: 'npm (GHSA)', value: 'npm' },
  { label: 'PyPI (GHSA)', value: 'pypi' },
  { label: 'Go (GHSA)', value: 'go' },
  { label: 'Maven (GHSA)', value: 'maven' },
  { label: 'RubyGems (GHSA)', value: 'rubygems' },
  { label: 'NuGet (GHSA)', value: 'nuget' },
  { label: 'Composer (GHSA)', value: 'composer' },
  { label: 'crates.io (GHSA)', value: 'rust' },
  { label: 'Linux kernel (OSV)', value: 'Linux' },
  { label: 'Debian (OSV)', value: 'Debian' },
  { label: 'Ubuntu (OSV)', value: 'Ubuntu' },
  { label: 'Alpine (OSV)', value: 'Alpine' },
  { label: 'Android (OSV)', value: 'Android' },
  { label: 'Red Hat (OSV)', value: 'Red Hat' },
  { label: 'Rocky Linux (OSV)', value: 'Rocky Linux' },
  { label: 'AlmaLinux (OSV)', value: 'AlmaLinux' },
  { label: 'SUSE (OSV)', value: 'SUSE' },
  { label: 'openSUSE (OSV)', value: 'openSUSE' },
  { label: 'openEuler (OSV)', value: 'openEuler' },
  { label: 'Bitnami (OSV)', value: 'Bitnami' },
  { label: 'Chainguard (OSV)', value: 'Chainguard' },
  { label: 'Wolfi (OSV)', value: 'Wolfi' },
  { label: 'OSS-Fuzz (OSV)', value: 'OSS-Fuzz' },
  { label: 'Haskell Hackage (OSV)', value: 'Hackage' },
  { label: 'CRAN (OSV)', value: 'CRAN' },
  { label: 'Julia (OSV)', value: 'Julia' },
];

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'bg-[var(--pink-faint)] text-[var(--accent-pink)] border-[var(--pink-dim)]',
  HIGH: 'bg-[var(--orange-faint)] text-[var(--accent-orange)] border-[var(--orange-dim)]',
  MEDIUM: 'bg-[var(--yellow-faint)] text-[var(--accent-yellow)] border-[var(--yellow-dim)]',
  LOW: 'bg-[var(--blue-faint)] text-[var(--accent-blue)] border-[var(--blue-dim)]',
};

function SeverityBadge({ severity }: { severity: string | null }) {
  if (!severity) return <span className="text-[var(--text-secondary)] text-xs">—</span>;
  const classes =
    SEVERITY_COLORS[severity] ??
    'bg-[var(--hover-overlay)] text-[var(--text-secondary)] border-[var(--border-color)]';
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${classes}`}>
      {severity}
    </span>
  );
}

function SourceBadge({ source }: { source: 'GHSA' | 'OSV' }) {
  const classes =
    source === 'GHSA'
      ? 'bg-[var(--teal-faint)] text-[var(--accent-teal)] border-[var(--teal-dim)]'
      : 'bg-[var(--yellow-faint)] text-[var(--accent-yellow)] border-[var(--yellow-dim)]';
  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 rounded-full text-[10px] font-semibold border ${classes}`}>
      {source}
    </span>
  );
}

function advisoryHref(row: AdvisoryListEntry): string {
  return row.source === 'GHSA'
    ? `/cti/ghsa/${row.advisoryId}`
    : `/cti/osv/${encodeURIComponent(row.advisoryId)}`;
}

const columns: ColumnDef<AdvisoryListEntry>[] = [
  {
    key: 'severity',
    header: 'Severity',
    tooltip: 'CVSS severity bucket (CRITICAL | HIGH | MEDIUM | LOW)',
    width: '100px',
    render: (row) => <SeverityBadge severity={row.severity} />,
  },
  {
    key: 'source',
    header: 'Source',
    tooltip: 'GHSA = GitHub Security Advisory (OSS packages). OSV = Open Source Vulnerabilities (OS, distros, kernel).',
    width: '80px',
    render: (row) => <SourceBadge source={row.source} />,
  },
  {
    key: 'advisoryId',
    header: 'Advisory',
    tooltip: 'Advisory identifier — GHSA-xxxx-xxxx-xxxx or OSV native id (DSA-*, USN-*, LBSEC-*, …)',
    render: (row) => (
      <Link href={advisoryHref(row)} className="font-mono text-xs text-[var(--accent-teal)] hover:underline">
        {row.advisoryId}
      </Link>
    ),
  },
  {
    key: 'cveId',
    header: 'CVE alias',
    tooltip: 'Linked CVE (from advisory aliases)',
    width: '140px',
    render: (row) =>
      row.cveId ? (
        <Link
          href={`/cti/cves/${row.cveId}`}
          className="font-mono text-xs text-[var(--accent-pink)] hover:underline"
        >
          {row.cveId}
        </Link>
      ) : (
        <span className="text-[var(--text-secondary)] text-xs">—</span>
      ),
  },
  {
    key: 'summary',
    header: 'Summary',
    tooltip: 'Advisory headline',
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
    tooltip: 'Affected ecosystems',
    width: '160px',
    render: (row) =>
      row.ecosystems.length > 0 ? (
        <div className="flex flex-wrap gap-1">
          {row.ecosystems.slice(0, 3).map((eco) => (
            <Badge key={eco} label={eco} variant="blue" />
          ))}
          {row.ecosystems.length > 3 && (
            <span className="text-[10px] text-[var(--text-secondary)]">
              +{row.ecosystems.length - 3}
            </span>
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
    tooltip: 'Base score (v3.x)',
    width: '70px',
    render: (row) => (
      <span className="text-xs text-[var(--text-primary)] font-mono">
        {row.cvssScore != null ? row.cvssScore.toFixed(1) : '—'}
      </span>
    ),
  },
  {
    key: 'publishedAt',
    header: 'Published',
    width: '100px',
    render: (row) =>
      row.publishedAt ? (
        <span className="text-[10px] text-[var(--text-secondary)] shrink-0">
          {formatDate(row.publishedAt)}
        </span>
      ) : (
        <span className="text-[var(--text-secondary)] text-xs">—</span>
      ),
  },
];

export function AdvisoriesList() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const updateParams = useUpdateParams();
  const page = parseInt(searchParams.get('page') ?? '1', 10);
  // Default landing filter: CRITICAL only. Combined with the fixed
  // severity-DESC + published_at-DESC sort, the list opens with "newest
  // critical first" — matches the SOC's "what hit me this week" intent.
  // Empty string (user-selected "All severities") is respected; we only
  // fall back to the default when the param is entirely absent from the URL.
  const severity = searchParams.has('severity') ? (searchParams.get('severity') ?? '') : 'CRITICAL';
  const source = searchParams.get('source') ?? '';
  const ecosystem = searchParams.get('ecosystem') ?? '';
  const category = searchParams.get('category') ?? '';
  const q = searchParams.get('q') ?? '';
  const hasCve = searchParams.get('has_cve') ?? '';
  // Default the date floor to "last 14 days" so the landing query hits a
  // tight slice instead of paginating through hundreds of thousands of
  // rows. Empty-string (user-selected "No date filter") still preserved
  // via the URL param — see setParam. 14 days gives enough room for weekly
  // review without burning DB on historical scans.
  const defaultSince = new Date(Date.now() - 14 * 86400000).toISOString().split('T')[0];
  const since = searchParams.has('since') ? (searchParams.get('since') ?? '') : defaultSince;

  const setParam = useCallback(
    (key: string, value: string) => {
      const updates: Record<string, string | null> = {};
      if (value) {
        updates[key] = value;
      } else if (key === 'severity' || key === 'since') {
        // Both default-applied params (severity=CRITICAL, since=last-14d)
        // need an explicit empty-string in the URL to mean "user opted out
        // of the default". Otherwise deleting the param re-applies the
        // default on the next render.
        updates[key] = '';
      } else {
        updates[key] = null;
      }
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
    // Sort is fixed server-side to severity DESC + published_at DESC; no
    // `order` param needed. Critical/new always surfaces at the top.
    const p: Record<string, string> = { page: String(page), limit: '50' };
    if (severity) p.severity = severity;
    if (source) p.source = source;
    if (ecosystem) p.ecosystem = ecosystem;
    if (category) p.category = category;
    if (q && q.length >= 3) p.q = q;
    if (hasCve) p.has_cve = hasCve;
    if (since) p.since = since;
    return p;
  }, [page, severity, source, ecosystem, category, q, hasCve, since]);

  const { data, isLoading } = useAdvisories(params);

  return (
    <div className="space-y-4">
      <PageHeader
        title="Advisories"
        subtitle="GitHub Security Advisories (OSS packages) + OSV (Linux kernel, Debian, Ubuntu, Alpine, Android, OSS-Fuzz, …) — one unified list with source badges"
      />

      <div className="flex flex-wrap gap-3 items-center">
        <input
          type="search"
          placeholder="Search advisory ID, CVE, summary…"
          value={qInput}
          aria-label="Search"
          onChange={(e) => {
            setQInput(e.target.value);
            clearTimeout(debounceRef.current);
            debounceRef.current = setTimeout(() => setParam('q', e.target.value), 300);
          }}
          className="min-w-[260px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent-teal)]"
        />

        <select
          value={category}
          onChange={(e) => setParam('category', e.target.value)}
          aria-label="Ecosystem category"
          title="Group ecosystems into curated buckets. Container-image distros (Chainguard/Wolfi/MinimOS/…) publish tens of thousands of rebuild advisories — use this to opt in/out."
          className="px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)]"
        >
          <option value="">All categories</option>
          {ADVISORY_CATEGORY_KEYS.map((k) => (
            <option key={k} value={k}>
              {ADVISORY_ECOSYSTEM_CATEGORIES[k as AdvisoryEcosystemCategory].label}
            </option>
          ))}
        </select>

        <select
          value={source}
          onChange={(e) => setParam('source', e.target.value)}
          aria-label="Filter by source"
          title="Filter by source — GHSA for OSS packages, OSV for OS & distros. Category filter above usually makes this redundant."
          className="px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)]"
        >
          <option value="">All sources</option>
          <option value="GHSA">GHSA (OSS packages)</option>
          <option value="OSV">OSV (OS & distros)</option>
        </select>

        <select
          value={severity}
          onChange={(e) => setParam('severity', e.target.value)}
          aria-label="Filter by severity"
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
          aria-label="Filter by specific ecosystem"
          className="px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)]"
        >
          <option value="">All ecosystems</option>
          <optgroup label="OSS package ecosystems (GHSA)">
            {ECOSYSTEMS.filter((e) => e.label.includes('(GHSA)')).map((e) => (
              <option key={e.value} value={e.value}>{e.label}</option>
            ))}
          </optgroup>
          <optgroup label="OS / distro / kernel (OSV)">
            {ECOSYSTEMS.filter((e) => e.label.includes('(OSV)')).map((e) => (
              <option key={e.value} value={e.value}>{e.label}</option>
            ))}
          </optgroup>
        </select>

        <select
          value={hasCve}
          onChange={(e) => setParam('has_cve', e.target.value)}
          aria-label="Filter by CVE alias presence"
          className="px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)]"
          title="Filter by CVE alias presence"
        >
          <option value="">With/without CVE</option>
          <option value="true">Has CVE</option>
          <option value="false">No CVE alias</option>
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
        onRowClick={(row) => router.push(advisoryHref(row))}
        rowKey={(row) => `${row.source}:${row.advisoryId}`}
        emptyMessage="No advisories match the current filters."
      />
    </div>
  );
}
