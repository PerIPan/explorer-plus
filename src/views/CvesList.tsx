'use client';
import { useCallback, useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { useSearchParams } from 'next/navigation';
import { useUpdateParams } from '../hooks/useUpdateParams';
import Link from 'next/link';
import { useQuery } from '@tanstack/react-query';
import { useCves } from '../hooks/useApi';
import { useSector } from '../contexts/SectorContext';
import { apiFetch } from '../lib/api';
import { formatDate } from '../lib/formatDate';
import { PageHeader } from '../components/layout/PageHeader';
import { DataTable, type ColumnDef } from '../components/shared/DataTable';
import { EntityLink } from '../components/shared/EntityLink';
import { Badge } from '../components/shared/Badge';
import type { CveEntry } from '../lib/types';

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const SOURCES = ['otx', 'cisa_kev'];

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'bg-[var(--pink-faint)] text-[var(--accent-pink)] border-[var(--pink-dim)]',
  HIGH: 'bg-[var(--orange-faint)] text-[var(--accent-orange)] border-[var(--orange-dim)]',
  MEDIUM: 'bg-[var(--yellow-faint)] text-[var(--accent-yellow)] border-[var(--yellow-dim)]',
  LOW: 'bg-[var(--blue-faint)] text-[var(--accent-blue)] border-[var(--blue-dim)]',
};

const SOURCE_VARIANTS: Record<string, 'teal' | 'orange' | 'purple' | 'blue' | 'green' | 'pink'> = {
  otx: 'teal',
  cisa_kev: 'blue',
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

/** Clipboard copy button */
function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  function handleCopy() {
    navigator.clipboard.writeText(value).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }).catch(() => {/* silent */});
  }
  return (
    <button
      type="button"
      onClick={handleCopy}
      title="Copy to clipboard"
      className={`ml-1.5 flex-shrink-0 transition-colors duration-150 ${copied ? 'text-[var(--accent-teal)]' : 'text-[var(--text-secondary)] hover:text-[var(--accent-teal)]'}`}
      aria-label="Copy value"
    >
      {copied ? (
        <span className="text-[10px] font-medium">Copied!</span>
      ) : (
        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-4 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
        </svg>
      )}
    </button>
  );
}

/** Clickable technique count with popover */
function TechniquePopover({ cveId, count }: { cveId: string; count: number }) {
  const [open, setOpen] = useState(false);
  const { data, isLoading } = useQuery({
    queryKey: ['cve-detail', cveId],
    queryFn: () => apiFetch<{ techniques: Array<{ attackId: string; name: string }> }>(`/cves/${cveId}`),
    enabled: open,
    staleTime: 5 * 60 * 1000,
  });

  const btnRef = useRef<HTMLButtonElement>(null);
  const rect = open && btnRef.current ? btnRef.current.getBoundingClientRect() : null;

  return (
    <span>
      <button
        ref={btnRef}
        type="button"
        onClick={(e) => { e.stopPropagation(); setOpen((prev) => !prev); }}
        aria-label={`Show ${count} linked techniques`}
        aria-expanded={open}
        className="cursor-pointer"
      >
        <Badge label={String(count)} variant="teal" />
      </button>
      {open && rect && createPortal(
        <>
          <div
            className="fixed inset-0 z-40"
            onClick={() => setOpen(false)}
            onKeyDown={(e) => { if (e.key === 'Escape') setOpen(false); }}
            role="button"
            aria-label="Close popover"
            tabIndex={-1}
          />
          <div
            className="fixed z-50 bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg shadow-2xl p-3 min-w-[240px] max-h-[300px] overflow-y-auto"
            style={{ top: rect.bottom + 4, left: Math.max(8, rect.right - 240) }}
          >
            <div className="text-[10px] text-[var(--text-secondary)] uppercase tracking-wider mb-2">
              Linked Techniques ({count})
            </div>
            {isLoading && (
              <div className="flex items-center gap-2 text-[var(--text-secondary)] text-xs py-2">
                <span className="inline-block w-3 h-3 border-2 border-[var(--teal-dim)] border-t-[var(--accent-teal)] rounded-full animate-spin" />
                Loading...
              </div>
            )}
            {data?.techniques && (
              <div className="flex flex-col gap-1">
                {data.techniques.map((t) => (
                  <EntityLink key={t.attackId} type="technique" attackId={t.attackId} name={t.name} useMap />
                ))}
              </div>
            )}
            {!isLoading && data?.techniques?.length === 0 && (
              <span className="text-xs text-[var(--text-secondary)]">No techniques found.</span>
            )}
          </div>
        </>,
        document.body,
      )}
    </span>
  );
}

const columns: ColumnDef<CveEntry>[] = [
  {
    key: 'cvssSeverity',
    header: 'Severity',
    tooltip: 'CVSS v3.1 severity rating from NVD',
    width: '100px',
    render: (row) => <SeverityBadge severity={row.cvssSeverity} />,
  },
  {
    key: 'cveId',
    header: 'CVE ID',
    tooltip: 'Common Vulnerabilities and Exposures identifier',
    render: (row) => (
      <div className="flex items-center gap-0.5">
        <Link
          href={`/cti/cves/${row.cveId}`}
          className="font-mono text-xs text-[var(--accent-teal)] hover:underline"
        >
          {row.cveId}
        </Link>
        <CopyButton value={row.cveId} />
      </div>
    ),
  },
  {
    key: 'description',
    header: 'Description',
    tooltip: 'Vulnerability description from NVD',
    render: (row) =>
      row.description ? (
        <span className="text-xs text-[var(--text-secondary)] max-w-[400px] line-clamp-2 block leading-relaxed">
          {row.description}
        </span>
      ) : (
        <span className="text-[var(--text-secondary)] text-xs">—</span>
      ),
  },
  {
    key: 'applications',
    header: 'Applications',
    tooltip: 'Affected products from NVD. Application mappings are typically added days after CVE publication — recent CVEs may show empty until enriched.',
    render: (row) =>
      row.applications ? (
        <span className="text-[10px] text-[var(--accent-blue)] max-w-[200px] line-clamp-2 block leading-relaxed">
          {row.applications}
        </span>
      ) : (
        <span className="text-[var(--text-secondary)] text-xs">—</span>
      ),
  },
  {
    key: 'cvssScore',
    header: 'CVSS',
    tooltip: 'Common Vulnerability Scoring System v3.1 base score (0–10)',
    width: '70px',
    render: (row) => (
      <span className="text-xs text-[var(--text-primary)] font-mono">
        {row.cvssScore != null ? row.cvssScore.toFixed(1) : '—'}
      </span>
    ),
  },
  {
    key: 'cweId',
    header: 'CWE',
    tooltip: 'Common Weakness Enumeration — vulnerability category',
    width: '90px',
    render: (row) =>
      row.cweId ? (
        <a
          href={`https://cwe.mitre.org/data/definitions/${row.cweId.replace('CWE-', '')}.html`}
          target="_blank"
          rel="noopener noreferrer"
          className="text-xs text-[var(--accent-blue)] font-mono hover:underline"
        >
          {row.cweId}
        </a>
      ) : (
        <span className="text-[var(--text-secondary)] text-xs">—</span>
      ),
  },
  {
    key: 'sources',
    header: 'Sources',
    tooltip: 'Feed sources that reported this CVE (OTX, CISA KEV)',
    width: '140px',
    render: (row) => {
      const srcs = row.sources.length > 0 ? row.sources : ['NVD'];
      return (
        <div className="flex flex-wrap gap-1">
          {srcs.map((s) => (
            <Badge key={s} label={s} variant={SOURCE_VARIANTS[s] ?? 'neutral'} />
          ))}
        </div>
      );
    },
  },
  {
    key: 'techniqueCount',
    header: 'Techniques',
    tooltip: 'ATT&CK techniques linked via CAPEC bridge + IOC feeds',
    width: '90px',
    align: 'center',
    render: (row) =>
      row.techniqueCount > 0 ? (
        <TechniquePopover cveId={row.cveId} count={row.techniqueCount} />
      ) : (
        <span className="text-[var(--text-secondary)] text-xs">—</span>
      ),
  },
  {
    key: 'publishedAt',
    header: 'Published',
    tooltip: 'CVE publication date',
    width: '100px',
    render: (row) => (
      <span className="text-[10px] text-[var(--text-secondary)] shrink-0">
        {row.publishedAt ? formatDate(row.publishedAt) : '—'}
      </span>
    ),
  },
];

export function CvesList() {

  const searchParams = useSearchParams();
  const updateParams = useUpdateParams();
  const { sectorParam } = useSector();

  const page = parseInt(searchParams.get('page') ?? '1', 10);
  const severity = searchParams.get('severity') ?? '';
  const source = searchParams.get('source') ?? '';
  const q = searchParams.get('q') ?? '';
  const technique = searchParams.get('technique') ?? '';
  const app = searchParams.get('app') ?? '';
  const defaultSince = new Date(Date.now() - 30 * 86400000).toISOString().split('T')[0];
  const since = searchParams.has('since') ? (searchParams.get('since') ?? '') : defaultSince;

  const setParam = useCallback(
    (key: string, value: string) => {
      const updates: Record<string, string | null> = {};
      if (value) {
        updates[key] = value;
      } else if (key === 'since') {
        updates[key] = ''; // keep empty to represent "all time"
      } else {
        updates[key] = null;
      }
      if (key !== 'page') updates.page = '1';
      updateParams(updates);
    },
    [updateParams],
  );

  const [qInput, setQInput] = useState(q);
  const [techInput, setTechInput] = useState(technique);
  const [appInput, setAppInput] = useState(app);
  const debounceRef = useRef<ReturnType<typeof setTimeout>>(undefined);
  const techDebounceRef = useRef<ReturnType<typeof setTimeout>>(undefined);
  useEffect(() => { setQInput(q); }, [q]);
  useEffect(() => { setTechInput(technique); }, [technique]);
  useEffect(() => { setAppInput(app); }, [app]);
  const handleQChange = useCallback((value: string) => {
    setQInput(value);
    clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => setParam('q', value), 300);
  }, [setParam]);
  const handleTechChange = useCallback((value: string) => {
    setTechInput(value);
    clearTimeout(techDebounceRef.current);
    techDebounceRef.current = setTimeout(() => setParam('technique', value.trim()), 500);
  }, [setParam]);
  const appDebounceRef = useRef<ReturnType<typeof setTimeout>>(undefined);
  const handleAppChange = useCallback((value: string) => {
    setAppInput(value);
    clearTimeout(appDebounceRef.current);
    appDebounceRef.current = setTimeout(() => setParam('app', value.trim()), 500);
  }, [setParam]);
  useEffect(() => () => { clearTimeout(debounceRef.current); clearTimeout(techDebounceRef.current); clearTimeout(appDebounceRef.current); }, []);

  const params: Record<string, string> = { page: String(page), limit: '100', ...sectorParam };
  if (severity) params.severity = severity;
  if (source) params.source = source;
  if (q) params.q = q;
  if (technique) params.technique = technique;
  if (app) params.app = app;
  if (since) params.since = since;

  const { data, isLoading } = useCves(params);

  return (
    <div className="space-y-4">
      <PageHeader
        title="Vulnerabilities"
        subtitle={technique ? `CVEs linked to technique ${technique}` : 'Known CVEs from OTX and CISA KEV, enriched with NVD data. Application mappings are typically added days after publication.'}
      />

      {technique && (
        <div className="flex items-center gap-2">
          <Badge label={`Technique: ${technique}`} variant="teal" />
          <button
            onClick={() => setParam('technique', '')}
            className="text-xs text-[var(--text-secondary)] hover:text-[var(--accent-teal)]"
          >
            Clear filter
          </button>
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <input
          type="search"
          placeholder="Search CVEs..."
          value={qInput}
          onChange={(e) => handleQChange(e.target.value)}
          className="min-w-[200px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent-teal)]"
        />
        <input
          type="text"
          placeholder="Technique"
          value={techInput}
          onChange={(e) => handleTechChange(e.target.value)}
          className="min-w-[120px] max-w-[140px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent-teal)]"
        />
        <input
          type="text"
          placeholder="Application"
          value={appInput}
          onChange={(e) => handleAppChange(e.target.value)}
          className="min-w-[140px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent-teal)]"
        />
        <select
          value={severity}
          onChange={(e) => setParam('severity', e.target.value)}
          className="min-w-[140px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent-teal)]"
        >
          <option value="">All Severities</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <select
          value={source}
          onChange={(e) => setParam('source', e.target.value)}
          className="min-w-[140px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent-teal)]"
        >
          <option value="">All Sources</option>
          {SOURCES.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <label className="flex flex-col gap-1">
          <span className="text-xs font-medium text-[var(--text-secondary)]">Since:</span>
          <input
            type="date"
            value={since}
            onChange={(e) => setParam('since', e.target.value)}
            className="px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent-teal)]"
          />
        </label>
        <div className="flex gap-1.5 items-end">
          {[
            { label: 'This week', days: 7 },
            { label: 'This month', days: 30 },
            { label: '6 months', days: 180 },
            { label: 'All time', days: 0 },
          ].map((f) => {
            const sinceDate = f.days > 0
              ? new Date(Date.now() - f.days * 86400000).toISOString().split('T')[0]
              : '';
            const isActive = since === sinceDate;
            return (
              <button
                key={f.label}
                type="button"
                onClick={() => setParam('since', sinceDate)}
                className={`px-2.5 py-1.5 text-xs rounded-md border transition-colors ${
                  isActive
                    ? 'border-[var(--accent-teal)] text-[var(--accent-teal)] bg-[var(--teal-faint)]'
                    : 'border-[var(--border-color)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-[var(--teal-dim)]'
                }`}
              >
                {f.label}
              </button>
            );
          })}
        </div>
      </div>

      <DataTable
        columns={columns}
        data={data?.data ?? []}
        loading={isLoading}
        pagination={data?.pagination}
        onPageChange={(p) => setParam('page', String(p))}
        rowKey={(row) => row.cveId}
        emptyMessage="No CVEs found. Trigger a feed sync to populate data."
      />
    </div>
  );
}
