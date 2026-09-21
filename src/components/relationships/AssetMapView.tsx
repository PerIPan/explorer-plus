import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import { apiFetch } from '../../lib/api';
import { useFrameworksByTechniques } from '../../hooks/useApi';
import { EntityLink } from '../shared/EntityLink';
import { Badge } from '../shared/Badge';
import { DiamondLoader } from '../shared/FoldingDiamond';

// ── Types ────────────────────────────────────────────────────────────────────

interface AssetMapData {
  attackId: string;
  name: string;
  description: string | null;
  url: string | null;
  sectors: string[];
  platforms: string[];
  primaryLevel: string | null;
  primaryLevelLabel: string | null;
  primaryLevelDescription: string | null;
  zone: string | null;
  spansLevels: string[];
  isBoundary: boolean;
  rationale: string | null;
  placementSource: string | null;
  levels: Array<{ levelKey: string; label: string; zone: string; sortOrder: number }>;
  techniques: Array<{ attackId: string; name: string; description: string | null; url: string | null }>;
  techniqueCount: number;
  relatedAssets: Array<{ name: string; sectors: string[]; description: string | null }>;
  countermeasures: Array<{ d3fendId: string; d3fendName: string | null; d3fendTactic: string | null; techniqueCount: number }>;
  countermeasureCount: number;
  countermeasuresByTactic: Record<string, number>;
}

// ── Collapsible card (same local pattern as SectorMapView / ApplicationMapView) ─

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
        <svg
          className={`w-4 h-4 text-[var(--text-secondary)] shrink-0 transition-transform duration-200 ${open ? 'rotate-180' : ''}`}
          fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {open && <div className="px-4 py-4 bg-[var(--surface-alt)] space-y-3">{children}</div>}
    </div>
  );
}

// ── Icons ────────────────────────────────────────────────────────────────────

const IconPurdue = (
  <svg fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
    <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" />
  </svg>
);
const IconTechnique = (
  <svg fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
    <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
  </svg>
);
const IconShield = (
  <svg fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
    <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
  </svg>
);
const IconOwasp = (
  <svg fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
    <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01M5 19h14a2 2 0 001.84-2.75L13.74 4a2 2 0 00-3.5 0l-7.1 12.25A2 2 0 004.99 19z" />
  </svg>
);
const IconAlias = (
  <svg fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
    <path strokeLinecap="round" strokeLinejoin="round" d="M7 7h.01M7 3h5a1.99 1.99 0 011.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.99 1.99 0 013 12V7a4 4 0 014-4z" />
  </svg>
);

/** OT plant floor, the DMZ between, and corporate IT. */
const ZONE_VARIANT: Record<string, 'orange' | 'yellow' | 'blue'> = {
  ot: 'orange',
  dmz: 'yellow',
  it: 'blue',
};

/** Matches the D3FEND framework page so a tactic keeps one colour site-wide. */
const TACTIC_VARIANT: Record<string, 'teal' | 'orange' | 'purple' | 'green' | 'blue' | 'yellow' | 'neutral'> = {
  Model: 'purple',
  Harden: 'blue',
  Detect: 'teal',
  Isolate: 'yellow',
  Deceive: 'orange',
  Evict: 'green',
  Restore: 'neutral',
};
const TACTIC_ORDER = ['Model', 'Harden', 'Detect', 'Isolate', 'Deceive', 'Evict', 'Restore'];

interface AssetMapViewProps {
  attackId: string;
}

/**
 * 360 map for an ATT&CK for ICS asset (A0001-A0018).
 *
 * The question this answers and the asset detail page does not: where does this
 * device sit in the plant, what can be done to it, and what defends it. The
 * countermeasure roll-up is the reason it exists -- D3FEND publishes ICS
 * mappings, so an RTU or a historian can now be read defensively, not just as a
 * list of attacks.
 */
export function AssetMapView({ attackId }: AssetMapViewProps) {
  const { data, isLoading, error } = useQuery({
    // The asset endpoint wraps its payload in { data: ... }, unlike the sector
    // and application endpoints which spread the entity at the top level.
    queryKey: ['asset-map', attackId],
    queryFn: () => apiFetch<{ data: AssetMapData }>(`/assets/${attackId}`).then((r) => r.data),
    enabled: Boolean(attackId),
    staleTime: 2 * 60 * 1000,
  });

  const techniqueIds = data?.techniques?.map((t) => t.attackId) ?? [];
  const fwResult = useFrameworksByTechniques(techniqueIds);
  const owaspCategories = fwResult.data?.owasp ?? [];

  if (isLoading) return <DiamondLoader text="Loading asset map..." />;
  if (error || !data) {
    return <div className="text-[var(--text-secondary)] text-sm py-8 text-center">Asset not found.</div>;
  }

  const tactics = Object.entries(data.countermeasuresByTactic ?? {}).sort(
    (a, b) => TACTIC_ORDER.indexOf(a[0]) - TACTIC_ORDER.indexOf(b[0]),
  );

  return (
    <div className="space-y-3">
      {/* Header */}
      <div className="pb-1">
        <div className="flex items-baseline gap-2 flex-wrap">
          <h2 className="text-lg font-semibold text-[var(--text-primary)]">{data.name}</h2>
          <Link
            href={`/assets/${data.attackId}`}
            className="font-mono text-xs text-[var(--accent-teal)] hover:underline"
          >
            {data.attackId}
          </Link>
        </div>
        <div className="flex flex-wrap items-center gap-2 mt-1">
          <Badge label="asset" variant="purple" />
          {data.primaryLevelLabel && (
            <Badge
              label={`${(data.primaryLevel ?? '').toUpperCase().replace('_', '.')} ${data.primaryLevelLabel}`}
              variant={ZONE_VARIANT[data.zone ?? ''] ?? 'neutral'}
            />
          )}
          {data.isBoundary && <Badge label="IT/OT boundary" variant="yellow" />}
          {data.techniqueCount > 0 && <Badge label={`${data.techniqueCount} techniques`} variant="teal" />}
          {data.countermeasureCount > 0 && (
            <Badge label={`${data.countermeasureCount} countermeasures`} variant="green" />
          )}
        </div>
        {data.description && (
          <p className="text-sm text-[var(--text-secondary)] mt-2 line-clamp-3">{data.description}</p>
        )}
      </div>

      {/* WHERE IT SITS */}
      <MapCard label="Where it sits" icon={IconPurdue} count={data.levels.length}>
        {data.levels.length > 0 ? (
          <>
            <div className="flex flex-wrap gap-1.5">
              {data.levels.map((l) => (
                <Badge
                  key={l.levelKey}
                  label={`${l.levelKey.toUpperCase().replace('_', '.')} ${l.label}`}
                  variant={ZONE_VARIANT[l.zone] ?? 'neutral'}
                />
              ))}
            </div>
            {data.primaryLevelDescription && (
              <p className="text-xs text-[var(--text-secondary)]">{data.primaryLevelDescription}</p>
            )}
            {data.rationale && (
              <p className="text-xs text-[var(--text-secondary)] italic">{data.rationale}</p>
            )}
            <p className="text-[10px] text-[var(--text-secondary)]">
              Purdue placement is curated by this project from NIST SP 800-82r3 and ISA-95
              {data.placementSource ? ` (${data.placementSource.replace(/^curated:/, '')})` : ''}, not published by
              MITRE.{' '}
              <Link href="/frameworks/purdue" className="text-[var(--accent-teal)] hover:underline">
                Purdue model →
              </Link>
            </p>
          </>
        ) : (
          <p className="text-xs text-[var(--text-secondary)]">No Purdue placement curated for this asset.</p>
        )}
      </MapCard>

      {/* HOW IT IS ATTACKED */}
      <MapCard label="How it is attacked" icon={IconTechnique} count={data.techniqueCount}>
        {data.techniques.length > 0 ? (
          <div className="flex flex-wrap gap-1.5 max-h-64 overflow-y-auto">
            {data.techniques.map((t) => (
              <EntityLink key={t.attackId} type="technique" attackId={t.attackId} name={t.name} useMap />
            ))}
          </div>
        ) : (
          <p className="text-xs text-[var(--text-secondary)]">No techniques mapped to this asset.</p>
        )}
      </MapCard>

      {/* HOW IT IS DEFENDED */}
      <MapCard label="How it is defended" icon={IconShield} count={data.countermeasureCount}>
        {data.countermeasures.length > 0 ? (
          <>
            <div className="flex flex-wrap gap-1.5">
              {tactics.map(([tactic, n]) => (
                <Badge key={tactic} label={`${tactic} ${n}`} variant={TACTIC_VARIANT[tactic] ?? 'neutral'} />
              ))}
            </div>
            <div className="space-y-1 max-h-64 overflow-y-auto">
              {data.countermeasures.map((c) => (
                <Link
                  key={c.d3fendId}
                  href={`/frameworks/d3fend/${c.d3fendId}`}
                  className="flex items-center gap-2 py-1.5 px-3 rounded-md bg-[var(--surface-card)] border border-[var(--border-color)] hover:border-[var(--teal-dim)] transition-colors min-w-0"
                >
                  <span className="font-mono text-[11px] text-[var(--accent-teal)] shrink-0 w-24">{c.d3fendId}</span>
                  <span className="text-xs text-[var(--text-primary)] truncate flex-1">
                    {c.d3fendName ?? c.d3fendId}
                  </span>
                  {c.d3fendTactic && (
                    <Badge label={c.d3fendTactic} variant={TACTIC_VARIANT[c.d3fendTactic] ?? 'neutral'} />
                  )}
                  <span className="text-[10px] text-[var(--text-secondary)] shrink-0">
                    {c.techniqueCount} tech
                  </span>
                </Link>
              ))}
            </div>
            <p className="text-[10px] text-[var(--text-secondary)]">
              D3FEND countermeasures reaching this asset through the techniques that target it. Mappings indicate
              defensive intent, not verified mitigation.
            </p>
          </>
        ) : (
          <p className="text-xs text-[var(--text-secondary)]">
            No D3FEND countermeasures reach this asset&apos;s techniques yet.
          </p>
        )}
      </MapCard>

      {/* OWASP */}
      {owaspCategories.length > 0 && (
        <MapCard label="OWASP Risk Categories" icon={IconOwasp} count={owaspCategories.length}>
          <div className="flex flex-wrap gap-1.5">
            {owaspCategories.map((c) => (
              <EntityLink key={c.categoryId} type="owasp" attackId={c.categoryId} name={c.name} useMap />
            ))}
          </div>
        </MapCard>
      )}

      {/* ALIASES + CONTEXT */}
      {(data.relatedAssets.length > 0 || data.sectors.length > 0 || data.platforms.length > 0) && (
        <MapCard label="Also known as" icon={IconAlias} count={data.relatedAssets.length} defaultOpen={false}>
          {data.relatedAssets.length > 0 && (
            <div className="space-y-1.5">
              {data.relatedAssets.map((r) => (
                <div
                  key={r.name}
                  className="py-1.5 px-3 rounded-md bg-[var(--surface-card)] border border-[var(--border-color)]"
                >
                  <div className="text-xs text-[var(--text-primary)]">{r.name}</div>
                  {r.description && (
                    <div className="text-[11px] text-[var(--text-secondary)] mt-0.5 line-clamp-2">{r.description}</div>
                  )}
                </div>
              ))}
            </div>
          )}
          {data.sectors.length > 0 && (
            <div className="flex flex-wrap items-center gap-1.5">
              {/* MITRE's own ICS sector labels. Deliberately not links: this is a
                  different vocabulary from the sector pages (Financial, Energy, ...). */}
              <span className="text-[10px] text-[var(--text-secondary)] uppercase tracking-wider">Sectors</span>
              {data.sectors.map((s) => (
                <Badge key={s} label={s} variant="neutral" />
              ))}
            </div>
          )}
          {data.platforms.length > 0 && (
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-[10px] text-[var(--text-secondary)] uppercase tracking-wider">Platforms</span>
              {data.platforms.map((p) => (
                <Badge key={p} label={p} variant="neutral" />
              ))}
            </div>
          )}
        </MapCard>
      )}
    </div>
  );
}
