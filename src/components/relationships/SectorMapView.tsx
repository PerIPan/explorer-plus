import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { apiFetch } from '../../lib/api';
import { EntityLink } from '../shared/EntityLink';
import { Badge } from '../shared/Badge';
import { formatDate } from '../../lib/formatDate';
import { DiamondLoader } from '../shared/FoldingDiamond';

// ── Types ────────────────────────────────────────────────────────────────────

interface SectorRelationships {
  id: string;
  name: string;
  slug: string | null;
  groups: Array<{ attackId: string; name: string; aliases: string[] | null; source: string }>;
  campaigns: Array<{ attackId: string; name: string; firstSeen: string | null; lastSeen: string | null }>;
  software: Array<{ attackId: string; name: string; type: string | null }>;
  techniques: Array<{ attackId: string; name: string; groupCount: number }>;
  cves: Array<{ cveId: string; description: string | null; cvssSeverity: string | null; publishedAt: string | null }>;
}

// ── Collapsible card (same pattern as TechniqueMapView) ──────────────────────

interface MapCardProps {
  label: string;
  icon: React.ReactNode;
  count?: number;
  defaultOpen?: boolean;
  children: React.ReactNode;
}

function MapCard({ label, icon, count, defaultOpen = true, children }: MapCardProps) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="border border-[var(--border-color)] rounded-lg overflow-visible">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between px-4 py-3 bg-[var(--surface-card)] hover:bg-[var(--surface-base)] transition-colors text-left gap-3"
      >
        <div className="flex items-center gap-2">
          <span className="text-[var(--accent-teal)] w-4 h-4 shrink-0">{icon}</span>
          <span className="text-sm font-bold text-[var(--text-secondary)] uppercase tracking-wider">{label}</span>
          {count !== undefined && (
            <span className="text-xs text-[var(--text-secondary)]">({count})</span>
          )}
        </div>
        <svg
          className={`w-4 h-4 text-[var(--text-secondary)] shrink-0 transition-transform duration-200 ${open ? 'rotate-180' : ''}`}
          fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {open && (
        <div className="px-4 py-4 bg-[var(--surface-alt)] space-y-3">
          {children}
        </div>
      )}
    </div>
  );
}

// ── Icons ────────────────────────────────────────────────────────────────────

const IconPeople = (
  <svg fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
    <path strokeLinecap="round" strokeLinejoin="round" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z" />
  </svg>
);
const IconCampaign = (
  <svg fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
    <path strokeLinecap="round" strokeLinejoin="round" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
  </svg>
);
const IconSoftware = (
  <svg fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
    <path strokeLinecap="round" strokeLinejoin="round" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
  </svg>
);
const IconTechnique = (
  <svg fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
    <path strokeLinecap="round" strokeLinejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
    <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
  </svg>
);
const IconShield = (
  <svg fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
    <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
  </svg>
);

const SEVERITY_VARIANTS: Record<string, 'pink' | 'orange' | 'yellow' | 'blue' | 'neutral'> = {
  CRITICAL: 'pink',
  HIGH: 'orange',
  MEDIUM: 'yellow',
  LOW: 'blue',
};

// ── Component ────────────────────────────────────────────────────────────────

interface SectorMapViewProps {
  sectorSlug: string;
}

export function SectorMapView({ sectorSlug }: SectorMapViewProps) {
  const { data, isLoading, error } = useQuery({
    queryKey: ['sector-relationships', sectorSlug],
    queryFn: () => apiFetch<SectorRelationships>(`/sectors/${sectorSlug}/relationships`),
    enabled: Boolean(sectorSlug),
    staleTime: 2 * 60 * 1000,
  });

  if (isLoading) {
    return <DiamondLoader text="Loading sector map..." />;
  }

  if (error || !data) {
    return (
      <div className="text-[var(--text-secondary)] text-sm py-8 text-center">
        Sector not found.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Header */}
      <div className="pb-1">
        <h2 className="text-lg font-semibold text-[var(--text-primary)]">{data.name}</h2>
        <div className="flex flex-wrap items-center gap-2 mt-1">
          <Badge label="sector" variant="yellow" />
          <Badge label={`${data.groups.length} groups`} variant="orange" />
          {data.campaigns.length > 0 && <Badge label={`${data.campaigns.length} campaigns`} variant="blue" />}
          {data.software.length > 0 && <Badge label={`${data.software.length} software`} variant="purple" />}
          {data.techniques.length > 0 && <Badge label={`${data.techniques.length} techniques`} variant="teal" />}
        </div>
      </div>

      {/* THREAT ACTORS */}
      <MapCard label="Threat Actors" icon={IconPeople} count={data.groups.length}>
        {data.groups.length > 0 ? (
          <div className="flex flex-wrap gap-1.5 max-h-48 overflow-y-auto">
            {data.groups.map((g) => (
              <EntityLink key={g.attackId} type="group" attackId={g.attackId} name={g.name} useMap />
            ))}
          </div>
        ) : (
          <p className="text-xs text-[var(--text-secondary)]">No groups targeting this sector.</p>
        )}
      </MapCard>

      {/* CAMPAIGNS */}
      <MapCard label="Campaigns" icon={IconCampaign} count={data.campaigns.length}>
        {data.campaigns.length > 0 ? (
          <div className="space-y-1.5">
            {data.campaigns.map((c) => (
              <div
                key={c.attackId}
                className="flex items-center gap-2 py-1.5 px-3 rounded-md bg-[var(--surface-card)] border border-[var(--border-color)]"
              >
                <EntityLink type="campaign" attackId={c.attackId} name={c.name} useMap />
                {c.firstSeen && (
                  <span className="text-[10px] text-[var(--text-secondary)] shrink-0 ml-auto">
                    {formatDate(c.firstSeen)} — {c.lastSeen ? formatDate(c.lastSeen) : 'ongoing'}
                  </span>
                )}
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-[var(--text-secondary)]">No campaigns linked to this sector.</p>
        )}
      </MapCard>

      {/* SOFTWARE */}
      <MapCard label="Software" icon={IconSoftware} count={data.software.length}>
        {data.software.length > 0 ? (
          <div className="flex flex-wrap gap-1.5 max-h-48 overflow-y-auto">
            {data.software.map((s) => (
              <div key={s.attackId} className="flex items-center gap-1">
                <EntityLink type="software" attackId={s.attackId} name={s.name} useMap />
                {s.type && <Badge label={s.type} variant="neutral" />}
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-[var(--text-secondary)]">No software linked yet.</p>
        )}
      </MapCard>

      {/* CVEs */}
      {data.cves.length > 0 && (
        <MapCard label="Related CVEs" icon={IconShield} count={data.cves.length}>
          <div className="space-y-1.5">
            <div className="flex items-center gap-2 mb-1">
              <span className="text-[10px] font-semibold text-[var(--text-secondary)] uppercase tracking-wider">Latest CVEs</span>
              <a href={`/cti/cves?sector=${encodeURIComponent(sectorSlug)}&since=`} target="_blank" rel="noopener noreferrer" className="ml-auto text-[10px] text-[var(--accent-teal)] hover:underline">View CVEs →</a>
            </div>
            {data.cves.slice(0, 7).map((cve) => (
              <div
                key={cve.cveId}
                className="flex items-center gap-2 py-1.5 px-3 rounded-md bg-[var(--surface-card)] border border-[var(--border-color)]"
              >
                <a
                  href={`/cti/cves?q=${encodeURIComponent(cve.cveId)}&since=`}
                  className="text-xs text-[var(--text-primary)] hover:text-[var(--accent-teal)] truncate flex-1"
                >
                  {cve.description
                    ? (cve.description.length > 120 ? cve.description.slice(0, 120) + '...' : cve.description)
                    : cve.cveId}
                </a>
                {cve.cvssSeverity && (
                  <Badge label={cve.cvssSeverity} variant={SEVERITY_VARIANTS[cve.cvssSeverity] ?? 'neutral'} />
                )}
                <span className="font-mono text-[10px] text-[var(--accent-pink)] shrink-0">{cve.cveId}</span>
                {cve.publishedAt && (
                  <span className="text-[10px] text-[var(--text-secondary)] shrink-0">
                    {formatDate(cve.publishedAt)}
                  </span>
                )}
              </div>
            ))}
          </div>
        </MapCard>
      )}

      {/* TECHNIQUES — closed by default */}
      <MapCard label="Top Techniques" icon={IconTechnique} count={data.techniques.length} defaultOpen={false}>
        {data.techniques.length > 0 ? (
          <div className="space-y-1">
            {data.techniques.map((t) => (
              <div
                key={t.attackId}
                className="flex items-center gap-2 py-1 px-3 rounded-md bg-[var(--surface-card)] border border-[var(--border-color)]"
              >
                <EntityLink type="technique" attackId={t.attackId} name={t.name} useMap />
                <span className="ml-auto text-[10px] text-[var(--text-secondary)] shrink-0">
                  {t.groupCount} {t.groupCount === 1 ? 'group' : 'groups'}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-[var(--text-secondary)]">No techniques linked yet.</p>
        )}
      </MapCard>
    </div>
  );
}
