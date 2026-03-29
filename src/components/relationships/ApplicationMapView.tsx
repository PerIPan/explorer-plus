import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { apiFetch } from '../../lib/api';
import { EntityLink } from '../shared/EntityLink';
import { Badge } from '../shared/Badge';
import { formatDate } from '../../lib/formatDate';
import { DiamondLoader } from '../shared/FoldingDiamond';

// ── Types ────────────────────────────────────────────────────────────────────

interface ApplicationDetail {
  id: string;
  vendor: string;
  product: string;
  normalized: string;
  cveCount: number;
  cves: Array<{
    cveId: string; description: string | null;
    cvssScore: number | null; cvssSeverity: string | null;
    publishedAt: string | null; isKev: boolean;
  }>;
  cvePagination: { page: number; limit: number; total: number; totalPages: number };
  techniques: Array<{ attackId: string; name: string; groupCount: number }>;
  groups: Array<{ attackId: string; name: string; techniqueCount: number }>;
  weaknesses: Array<{ cweId: string; count: number }>;
}

// ── Reusable MapCard ─────────────────────────────────────────────────────────

function MapCard({ label, icon, count, defaultOpen = true, children }: {
  label: string; icon: React.ReactNode; count?: number; defaultOpen?: boolean; children: React.ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="border border-[var(--border-color)] rounded-lg overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between px-4 py-3 bg-[var(--surface-card)] hover:bg-[var(--surface-base)] transition-colors text-left gap-3"
      >
        <div className="flex items-center gap-2">
          <span className="text-[var(--accent-teal)] w-4 h-4 shrink-0">{icon}</span>
          <span className="text-sm font-bold text-[var(--text-secondary)] uppercase tracking-wider">{label}</span>
          {count !== undefined && <span className="text-xs text-[var(--text-secondary)]">({count})</span>}
        </div>
        <svg className={`w-4 h-4 text-[var(--text-secondary)] shrink-0 transition-transform duration-200 ${open ? 'rotate-180' : ''}`}
          fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {open && <div className="px-4 py-4 bg-[var(--surface-alt)] space-y-3">{children}</div>}
    </div>
  );
}

// ── Icons ────────────────────────────────────────────────────────────────────

const IconShield = (<svg fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true"><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>);
const IconCode = (<svg fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true"><path strokeLinecap="round" strokeLinejoin="round" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" /></svg>);
const IconTechnique = (<svg fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true"><path strokeLinecap="round" strokeLinejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>);
const IconPeople = (<svg fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true"><path strokeLinecap="round" strokeLinejoin="round" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z" /></svg>);

const SEVERITY_VARIANTS: Record<string, 'pink' | 'orange' | 'yellow' | 'blue' | 'neutral'> = {
  CRITICAL: 'pink', HIGH: 'orange', MEDIUM: 'yellow', LOW: 'blue',
};

// ── Component ────────────────────────────────────────────────────────────────

export function ApplicationMapView({ appSlug }: { appSlug: string }) {
  const { data, isLoading, error } = useQuery({
    queryKey: ['application-detail', appSlug],
    queryFn: () => apiFetch<ApplicationDetail>(`/applications/${appSlug}`),
    enabled: Boolean(appSlug),
    staleTime: 2 * 60 * 1000,
  });

  if (isLoading) {
    return <DiamondLoader text="Loading application map..." />;
  }

  if (error || !data) {
    return <div className="text-[var(--text-secondary)] text-sm py-8 text-center">Application not found.</div>;
  }

  return (
    <div className="space-y-3">
      {/* Header */}
      <div className="pb-1">
        <h2 className="text-lg font-semibold text-[var(--text-primary)]">{data.vendor} / {data.product}</h2>
        <div className="flex flex-wrap items-center gap-2 mt-1">
          <Badge label="application" variant="blue" />
          <Badge label={`${data.cveCount} CVEs`} variant="pink" />
          <Badge label={`${data.techniques.length} techniques`} variant="teal" />
          <Badge label={`${data.groups.length} threat groups`} variant="orange" />
        </div>
      </div>

      {/* VULNERABILITIES */}
      <MapCard label="Vulnerabilities" icon={IconShield} count={data.cvePagination.total}>
        {data.cves.length > 0 ? (
          <div className="space-y-1.5">
            <div className="flex items-center gap-2 mb-1">
              <span className="text-[10px] font-semibold text-[var(--text-secondary)] uppercase tracking-wider">Latest CVEs</span>
              <a href={`/cti/cves?app=${encodeURIComponent(data.product)}&since=`} target="_blank" rel="noopener noreferrer" className="ml-auto text-[10px] text-[var(--accent-teal)] hover:underline">View CVEs →</a>
            </div>
            {data.cves.slice(0, 7).map((cve) => (
              <div key={cve.cveId} className="flex items-center gap-2 py-1.5 px-3 rounded-md bg-[var(--surface-card)] border border-[var(--border-color)]">
                <a
                  href={`/cti/cves?q=${encodeURIComponent(cve.cveId)}&since=`}
                  className="text-xs text-[var(--text-primary)] hover:text-[var(--accent-teal)] truncate flex-1"
                  data-tooltip={cve.description ?? cve.cveId}
                >
                  {cve.description
                    ? (cve.description.length > 120 ? cve.description.slice(0, 120) + '...' : cve.description)
                    : cve.cveId}
                </a>
                {cve.cvssSeverity && <Badge label={cve.cvssSeverity} variant={SEVERITY_VARIANTS[cve.cvssSeverity] ?? 'neutral'} />}
                {cve.isKev && <Badge label="KEV" variant="pink" />}
                <span className="font-mono text-[10px] text-[var(--accent-pink)] shrink-0">{cve.cveId}</span>
                {cve.publishedAt && <span className="text-[10px] text-[var(--text-secondary)] shrink-0">{formatDate(cve.publishedAt)}</span>}
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-[var(--text-secondary)]">No CVEs linked.</p>
        )}
      </MapCard>

      {/* WEAKNESS PROFILE */}
      {data.weaknesses.length > 0 && (
        <MapCard label="Weakness Profile" icon={IconCode} count={data.weaknesses.length}>
          <div className="flex flex-wrap gap-1.5">
            {data.weaknesses.map((w) => (
              <a
                key={w.cweId}
                href={`https://cwe.mitre.org/data/definitions/${w.cweId.replace('CWE-', '')}.html`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-medium bg-[var(--blue-faint)] text-[var(--accent-blue)] border border-[var(--blue-dim)] hover:bg-[var(--blue-dim)] transition-colors"
              >
                {w.cweId} <span className="text-[var(--text-secondary)]">({w.count})</span>
              </a>
            ))}
          </div>
        </MapCard>
      )}

      {/* ATTACK SURFACE — techniques */}
      <MapCard label="Attack Surface" icon={IconTechnique} count={data.techniques.length}>
        {data.techniques.length > 0 ? (
          <div className="space-y-1">
            {data.techniques.map((t) => (
              <div key={t.attackId} className="flex items-center gap-2 py-1 px-3 rounded-md bg-[var(--surface-card)] border border-[var(--border-color)]">
                <EntityLink type="technique" attackId={t.attackId} name={t.name} useMap />
                <span className="ml-auto text-[10px] text-[var(--text-secondary)] shrink-0">
                  {t.groupCount} {t.groupCount === 1 ? 'group' : 'groups'}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-[var(--text-secondary)]">No techniques linked.</p>
        )}
      </MapCard>

      {/* THREAT ACTORS */}
      <MapCard label="Threat Actors" icon={IconPeople} count={data.groups.length}>
        {data.groups.length > 0 ? (
          <div className="flex flex-wrap gap-1.5 max-h-48 overflow-y-auto" tabIndex={0} aria-label="Threat actors list">
            {data.groups.map((g) => (
              <div key={g.attackId} className="flex items-center gap-1">
                <EntityLink type="group" attackId={g.attackId} name={g.name} useMap />
                <span className="text-[9px] text-[var(--text-secondary)]">({g.techniqueCount})</span>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-[var(--text-secondary)]">No threat groups linked.</p>
        )}
      </MapCard>
    </div>
  );
}
