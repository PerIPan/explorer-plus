'use client';
import { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { apiFetch } from '../lib/api';
import { PageHeader } from '../components/layout/PageHeader';
import { EntityLink } from '../components/shared/EntityLink';
import { Badge } from '../components/shared/Badge';
import { ctidCloudUrl } from '../lib/urlSafety';

interface CloudControlRow {
  provider: string;
  controlId: string;
  controlName: string;
  mappingType: string | null;
  techniqueCount: string;
  techniques: string[];
}

interface CloudControlsResponse {
  data: CloudControlRow[];
  stats: { provider: string; count: string }[];
  total: number;
}

const PROVIDER_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  azure: { bg: 'var(--blue-faint)', text: 'var(--accent-blue)', border: 'var(--blue-dim)' },
  gcp: { bg: 'var(--teal-faint)', text: 'var(--accent-teal)', border: 'var(--teal-dim)' },
  aws: { bg: 'var(--orange-faint)', text: 'var(--accent-orange)', border: 'var(--orange-dim)' },
};

const PROVIDER_LABELS: Record<string, string> = {
  azure: 'Azure',
  gcp: 'GCP',
  aws: 'AWS',
};

const TYPE_COLORS: Record<string, string> = {
  detect: 'purple',
  protect: 'green',
  respond: 'orange',
};

export function CloudControls() {

  const [search, setSearch] = useState('');
  const [provider, setProvider] = useState('');

  const { data, isLoading } = useQuery({
    queryKey: ['cloud-controls', provider, search],
    queryFn: () => {
      const params: Record<string, string> = {};
      if (provider) params.provider = provider;
      if (search) params.q = search;
      return apiFetch<CloudControlsResponse>('/frameworks/cloud-controls', params);
    },
  });

  const grouped = useMemo(() => {
    if (!data?.data) return new Map<string, CloudControlRow[]>();
    const map = new Map<string, CloudControlRow[]>();
    for (const row of data.data) {
      if (!map.has(row.provider)) map.set(row.provider, []);
      map.get(row.provider)!.push(row);
    }
    return map;
  }, [data]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Cloud Security Controls"
        subtitle="AWS, Azure, and GCP security controls mapped to ATT&CK techniques — from MITRE CTID Mappings Explorer"
        actions={
          <span className="text-sm text-[var(--text-secondary)]">
            {data?.total ?? '...'} controls
          </span>
        }
      />

      <div className="flex flex-wrap gap-3">
        <input
          type="search"
          placeholder="Search controls or techniques..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="min-w-[200px] px-3 py-2 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] placeholder:text-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent-teal)] focus:ring-1 focus:ring-[var(--accent-teal)]"
        />
        <select
          value={provider}
          onChange={(e) => setProvider(e.target.value)}
          aria-label="Filter by provider"
          className="px-3 py-2 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent-teal)] focus:ring-1 focus:ring-[var(--accent-teal)]"
        >
          <option value="">All Providers</option>
          {(data?.stats ?? []).map((s) => (
            <option key={s.provider} value={s.provider}>
              {PROVIDER_LABELS[s.provider] ?? s.provider} ({s.count})
            </option>
          ))}
        </select>
      </div>

      {isLoading && (
        <div className="space-y-2">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="h-12 rounded-lg bg-[var(--border-color)] animate-pulse" />
          ))}
        </div>
      )}

      {!isLoading && [...grouped.entries()].map(([prov, controls]) => (
        <section key={prov} className="space-y-3">
          <div className="flex items-center gap-2">
            <h2
              className="text-sm font-semibold uppercase tracking-wider"
              style={{ color: PROVIDER_COLORS[prov]?.text ?? 'var(--text-primary)' }}
            >
              {PROVIDER_LABELS[prov] ?? prov}
            </h2>
            <span className="text-xs text-[var(--text-secondary)]">{controls.length} controls</span>
          </div>

          <div className="space-y-1">
            {controls.map((ctrl) => (
              <details
                key={`${ctrl.provider}-${ctrl.controlId}`}
                className="group rounded-lg border border-[var(--border-color)] bg-[var(--surface-card)] overflow-hidden"
              >
                <summary className="flex items-center gap-3 px-4 py-2.5 cursor-pointer hover:bg-[var(--teal-ghost)] transition-colors">
                  <svg className="w-3 h-3 text-[var(--text-secondary)] transition-transform group-open:rotate-90 shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
                  </svg>
                  <a
                    href={ctidCloudUrl(prov, ctrl.controlId)}
                    target="_blank"
                    rel="noopener noreferrer"
                    onClick={(e) => e.stopPropagation()}
                    className="font-mono text-xs w-32 sm:w-48 shrink-0 truncate hover:underline"
                    style={{ color: PROVIDER_COLORS[prov]?.text ?? 'var(--accent-teal)' }}
                    title={`View ${ctrl.controlId} on CTID Mappings Explorer`}
                  >
                    {ctrl.controlId} ↗
                  </a>
                  <span className="text-sm text-[var(--text-primary)] flex-1 truncate">{ctrl.controlName}</span>
                  {ctrl.mappingType && (
                    <Badge label={ctrl.mappingType} variant={(TYPE_COLORS[ctrl.mappingType] ?? 'neutral') as 'purple' | 'green' | 'orange' | 'neutral'} />
                  )}
                  <span className="text-xs text-[var(--text-secondary)] shrink-0">{ctrl.techniqueCount} techniques</span>
                </summary>
                <div className="px-4 pb-3 pt-1 border-t border-[var(--border-color)]">
                  <div className="flex flex-wrap gap-1.5">
                    {ctrl.techniques.map((tid) => (
                      <EntityLink key={tid} type="technique" attackId={tid} name={tid} />
                    ))}
                  </div>
                </div>
              </details>
            ))}
          </div>
        </section>
      ))}

      {!isLoading && (data?.total ?? 0) === 0 && (
        <div className="text-center py-16 text-[var(--text-secondary)]">
          No controls found{search ? ` matching "${search}"` : ''}.
        </div>
      )}
    </div>
  );
}
