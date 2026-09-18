'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { PageHeader } from '../components/layout/PageHeader';

interface TechniqueRef {
  attackId: string;
  name: string;
  description: string | null;
  url: string | null;
}

interface RelatedAsset {
  name: string;
  sectors: string[];
  description: string | null;
}

interface LevelRef {
  levelKey: string;
  label: string;
  zone: 'ot' | 'dmz' | 'it';
  sortOrder: number;
}

interface AssetDetailData {
  attackId: string;
  name: string;
  description: string | null;
  url: string | null;
  sectors: string[];
  platforms: string[];
  isRevoked: boolean;
  isDeprecated: boolean;
  primaryLevel: string | null;
  primaryLevelLabel: string | null;
  zone: 'ot' | 'dmz' | 'it' | null;
  primaryLevelDescription: string | null;
  spansLevels: string[];
  isBoundary: boolean;
  rationale: string | null;
  placementSource: string | null;
  levels: LevelRef[];
  techniques: TechniqueRef[];
  techniqueCount: number;
  relatedAssets: RelatedAsset[];
}

const ZONE_CHIP: Record<string, string> = {
  ot:  'bg-[var(--orange-faint)] text-[var(--accent-orange)] border-[var(--orange-dim)]',
  dmz: 'bg-[var(--yellow-faint)] text-[var(--accent-yellow)] border-[var(--yellow-dim)]',
  it:  'bg-[var(--blue-faint)] text-[var(--accent-blue)] border-[var(--blue-dim)]',
};

const fmtLevel = (k: string) => k.replace('_', '.').toUpperCase();

export function AssetDetail({ attackId }: { attackId: string }) {
  const [data, setData] = useState<AssetDetailData | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const ctrl = new AbortController();
    fetch(`/api/v1/assets/${encodeURIComponent(attackId)}`, { signal: ctrl.signal })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(r.status === 404 ? 'not found' : `HTTP ${r.status}`))))
      .then((d: { data: AssetDetailData }) => { if (!ctrl.signal.aborted) setData(d.data); })
      .catch((e) => { if (!ctrl.signal.aborted) setError(e.message); });
    return () => ctrl.abort();
  }, [attackId]);

  if (error) {
    return (
      <>
        <PageHeader title={attackId} breadcrumb={[{ label: 'ICS Assets', href: '/assets' }, { label: attackId }]} />
        <p className="text-sm text-[var(--text-secondary)]">
          {error === 'not found'
            ? `No ICS asset with ID ${attackId}. `
            : `Could not load this asset: ${error}. `}
          <Link href="/assets" className="text-[var(--accent-teal)] hover:underline">Browse all assets</Link>
        </p>
      </>
    );
  }
  if (!data) {
    return (
      <>
        <PageHeader title={attackId} breadcrumb={[{ label: 'ICS Assets', href: '/assets' }, { label: attackId }]} />
        <p className="text-sm text-[var(--text-secondary)]">Loading…</p>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title={data.name}
        breadcrumb={[{ label: 'ICS Assets', href: '/assets' }, { label: data.attackId }]}
        subtitle={
          <span className="flex items-center gap-2 flex-wrap">
            <span className="font-mono text-xs">{data.attackId}</span>
            {data.zone && data.primaryLevel && (
              <span className={`text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded border ${ZONE_CHIP[data.zone]}`}>
                {fmtLevel(data.primaryLevel)} {data.primaryLevelLabel}
              </span>
            )}
            {data.isBoundary && (
              <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded border bg-[var(--yellow-faint)] text-[var(--accent-yellow)] border-[var(--yellow-dim)]">
                IT/OT boundary
              </span>
            )}
            {(data.isRevoked || data.isDeprecated) && (
              <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded border border-[var(--border-color)] text-[var(--text-secondary)]">
                {data.isRevoked ? 'revoked' : 'deprecated'}
              </span>
            )}
          </span>
        }
        actions={
          data.url ? (
            <a
              href={data.url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs px-2.5 py-1.5 rounded border border-[var(--border-color)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-[var(--border-hover)] transition-colors"
            >
              View on attack.mitre.org
            </a>
          ) : undefined
        }
      />

      {data.description && (
        <p className="text-sm text-[var(--text-primary)] leading-relaxed mb-6 max-w-3xl">{data.description}</p>
      )}

      <div className="grid gap-6 lg:grid-cols-[2fr_1fr] items-start">
        <div>
          <h2 className="text-sm font-medium text-[var(--text-primary)] mb-1">
            Techniques that target this asset
          </h2>
          <p className="text-[11px] text-[var(--text-secondary)] mb-3">
            Published by MITRE as ATT&CK for ICS <code>targets</code> relationships.
          </p>
          {data.techniques.length === 0 ? (
            <p className="text-xs text-[var(--text-secondary)] border border-[var(--border-color)] rounded px-3 py-2.5">
              No technique links are loaded. This database has no ATT&CK for ICS techniques yet —
              run the ICS ingest to populate them.
            </p>
          ) : (
            <ul className="divide-y divide-[var(--border-color)] border border-[var(--border-color)] rounded overflow-hidden">
              {data.techniques.map((t) => (
                <li key={t.attackId}>
                  <Link
                    href={`/techniques/${t.attackId}`}
                    className="flex items-baseline gap-3 px-3 py-2 hover:bg-[var(--hover-overlay)] transition-colors"
                  >
                    <span className="font-mono text-xs text-[var(--text-secondary)] w-16 shrink-0">{t.attackId}</span>
                    <span className="text-sm text-[var(--text-primary)] truncate">{t.name}</span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </div>

        <aside className="space-y-6">
          <section>
            <h2 className="text-sm font-medium text-[var(--text-primary)] mb-2">Where it sits</h2>
            <ol className="space-y-px">
              {[...data.levels].sort((a, b) => b.sortOrder - a.sortOrder).map((l) => (
                <li
                  key={l.levelKey}
                  className={`flex items-center gap-2 px-2.5 py-1.5 border text-xs ${
                    l.levelKey === data.primaryLevel
                      ? 'border-[var(--border-hover)] bg-[var(--surface-card)]'
                      : 'border-[var(--border-color)] bg-[var(--surface-alt)]'
                  }`}
                >
                  <span className="font-mono text-[var(--text-secondary)] w-10">{fmtLevel(l.levelKey)}</span>
                  <span className="text-[var(--text-primary)] flex-1">{l.label}</span>
                  {l.levelKey === data.primaryLevel && (
                    <span className="text-[10px] uppercase tracking-wider text-[var(--text-secondary)]">primary</span>
                  )}
                </li>
              ))}
            </ol>
            {data.rationale && (
              <p className="mt-2 text-[11px] text-[var(--text-secondary)] leading-relaxed">
                {data.rationale}
              </p>
            )}
            {data.placementSource && (
              <p className="mt-1.5 text-[10px] text-[var(--text-secondary)]">
                Placement is curated, not MITRE data — derived from {data.placementSource.replace('curated:', '')}.
              </p>
            )}
          </section>

          {(data.sectors.length > 0 || data.platforms.length > 0) && (
            <section>
              <h2 className="text-sm font-medium text-[var(--text-primary)] mb-2">Details</h2>
              <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1.5 text-xs">
                {data.sectors.length > 0 && (
                  <>
                    <dt className="text-[var(--text-secondary)] uppercase tracking-wider text-[10px]">Sectors</dt>
                    <dd className="text-[var(--text-primary)]">{data.sectors.join(', ')}</dd>
                  </>
                )}
                {data.platforms.length > 0 && (
                  <>
                    <dt className="text-[var(--text-secondary)] uppercase tracking-wider text-[10px]">Platforms</dt>
                    <dd className="text-[var(--text-primary)]">{data.platforms.join(', ')}</dd>
                  </>
                )}
              </dl>
            </section>
          )}

          {data.relatedAssets.length > 0 && (
            <section>
              <h2 className="text-sm font-medium text-[var(--text-primary)] mb-2">Also known as</h2>
              <ul className="space-y-1.5">
                {data.relatedAssets.map((r) => (
                  <li key={r.name} className="text-xs">
                    <span className="text-[var(--text-primary)]">{r.name}</span>
                    {r.description && (
                      <span className="block text-[11px] text-[var(--text-secondary)] leading-relaxed">
                        {r.description}
                      </span>
                    )}
                  </li>
                ))}
              </ul>
            </section>
          )}
        </aside>
      </div>
    </>
  );
}
