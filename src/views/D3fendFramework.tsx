'use client';

import { useState, useMemo, useEffect } from 'react';
import { useParams } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import { apiFetch } from '../lib/api';
import { PageHeader } from '../components/layout/PageHeader';
import { Badge } from '../components/shared/Badge';
import { EntityLink } from '../components/shared/EntityLink';
import { DiamondLoader } from '../components/shared/FoldingDiamond';
import type { D3fendTacticGroup, D3fendDetail } from '../lib/types';

type BadgeVariant = 'teal' | 'orange' | 'purple' | 'green' | 'blue' | 'yellow' | 'neutral';

/**
 * The seven D3FEND tactics in matrix order: model the system, harden it,
 * detect what gets through, isolate it, deceive the adversary, evict them,
 * restore. Descriptions are D3FEND's own framing of each tactic.
 *
 * Pink is deliberately unused -- it is reserved elsewhere in the palette.
 */
const TACTICS: { id: string; description: string; variant: BadgeVariant }[] = [
  { id: 'Model',   description: 'Inventory and map the system so you know what you are defending.', variant: 'purple' },
  { id: 'Harden',  description: 'Reduce attack surface before contact, through configuration and design.', variant: 'blue' },
  { id: 'Detect',  description: 'Identify adversary activity already under way.', variant: 'teal' },
  { id: 'Isolate',  description: 'Limit what an adversary can reach once inside.', variant: 'yellow' },
  { id: 'Deceive', description: 'Present a false environment to reveal and study the adversary.', variant: 'orange' },
  { id: 'Evict',   description: 'Remove the adversary and what they left behind.', variant: 'green' },
  { id: 'Restore',  description: 'Return the system to a known-good operating state.', variant: 'neutral' },
];

const TACTIC_META = new Map(TACTICS.map((t) => [t.id, t]));

const DOMAIN_LABEL: Record<string, string> = {
  'enterprise-attack': 'Enterprise',
  'ics-attack': 'ICS',
  'mobile-attack': 'Mobile',
  'atlas-attack': 'ATLAS',
};

/**
 * D3FEND's site addresses a countermeasure by its ontology class name, never by
 * its D3-XX id: D3-AM lives at /technique/d3f:AccessModeling/, while
 * /technique/d3-am/ is a 404. The class name is the fragment of the ontology
 * IRI already stored in d3fend_url (…/d3fend.owl#AccessModeling), so derive the
 * link from there. Checked against all 153 countermeasures — every one resolves,
 * including the hyphenated classes (d3f:Application-basedProcessIsolation).
 */
function d3fendSiteUrl(ontologyIri: string): string {
  const className = ontologyIri.split('#')[1]?.trim();
  return className ? `https://d3fend.mitre.org/technique/d3f:${className}/` : 'https://d3fend.mitre.org/';
}

export function D3fendFramework() {
  const { d3fendId: urlId } = useParams<{ d3fendId?: string }>();
  const [expanded, setExpanded] = useState<string | null>(() => urlId?.toUpperCase() ?? null);
  const [filter, setFilter] = useState<string>('');
  const [tacticFilter, setTacticFilter] = useState<string | null>(null);

  useEffect(() => {
    if (urlId) setExpanded(urlId.toUpperCase());
  }, [urlId]);

  const { data, isLoading } = useQuery({
    queryKey: ['d3fend-list'],
    queryFn: () =>
      apiFetch<{ data: D3fendTacticGroup[]; total: number; meta?: { countermeasures: number; tactics: number } }>(
        '/frameworks/d3fend',
      ),
    staleTime: 10 * 60 * 1000,
  });

  // Scroll a deep-linked countermeasure into view once the list has arrived,
  // rather than on a fixed timer that races a slow query.
  useEffect(() => {
    if (!urlId || isLoading || !data) return;
    const id = urlId.toUpperCase();
    const t = setTimeout(() => {
      document.getElementById(`d3f-${id}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }, 50);
    return () => clearTimeout(t);
  }, [urlId, isLoading, data]);

  const { data: detail, isLoading: detailLoading } = useQuery({
    queryKey: ['d3fend-detail', expanded],
    queryFn: () => apiFetch<D3fendDetail>(`/frameworks/d3fend/${expanded}`),
    enabled: !!expanded,
    staleTime: 5 * 60 * 1000,
  });

  const filteredGroups = useMemo(() => {
    const groups = data?.data ?? [];
    const q = filter.toLowerCase().trim();
    return groups
      .filter((g) => !tacticFilter || g.tactic === tacticFilter)
      .map((g) => ({
        ...g,
        countermeasures: g.countermeasures.filter(
          (c) =>
            !q ||
            c.d3fendId.toLowerCase().includes(q) ||
            (c.d3fendName ?? '').toLowerCase().includes(q),
        ),
      }))
      .filter((g) => g.countermeasures.length > 0);
  }, [data, filter, tacticFilter]);

  if (isLoading) return <DiamondLoader text="Loading D3FEND..." />;

  const total = data?.total ?? 0;
  const visibleCount = filteredGroups.reduce((sum, g) => sum + g.countermeasures.length, 0);

  return (
    <div className="space-y-6">
      <PageHeader
        title="MITRE D3FEND"
        subtitle="Defensive countermeasures mapped to the ATT&CK techniques they counter, across Enterprise and ICS"
        actions={
          <span className="text-[var(--text-secondary)] text-sm">
            {visibleCount} of {total} countermeasures
          </span>
        }
      />

      <div className="flex items-center gap-2 flex-wrap">
        <button
          type="button"
          onClick={() => setTacticFilter(null)}
          className={`px-3 py-1.5 text-xs rounded-md border transition-colors ${
            tacticFilter === null
              ? 'border-[#6366f1] text-[#6366f1] bg-[#6366f1]/10'
              : 'border-[var(--border-color)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
          }`}
        >
          All
        </button>
        {TACTICS.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTacticFilter(t.id)}
            title={t.description}
            className={`px-3 py-1.5 text-xs rounded-md border transition-colors ${
              tacticFilter === t.id
                ? 'border-[#6366f1] text-[#6366f1] bg-[#6366f1]/10'
                : 'border-[var(--border-color)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
            }`}
          >
            {t.id}
          </button>
        ))}
        <input
          type="search"
          placeholder="Filter by ID or name..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="ml-auto px-3 py-1.5 text-sm rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none focus:border-[#6366f1] min-w-[220px]"
        />
      </div>

      <div className="space-y-6">
        {filteredGroups.map((group) => {
          const meta = TACTIC_META.get(group.tactic);
          return (
            <div key={group.tactic}>
              <h3 className="text-sm font-bold text-[#6366f1] uppercase tracking-wider mb-1">
                {group.tactic} ({group.countermeasures.length})
              </h3>
              {meta && <p className="text-xs text-[var(--text-secondary)] mb-2">{meta.description}</p>}
              <div className="space-y-1">
                {group.countermeasures.map((cm) => {
                  const isOpen = expanded === cm.d3fendId;
                  return (
                    <div
                      key={cm.d3fendId}
                      id={`d3f-${cm.d3fendId}`}
                      className="border border-[var(--border-color)] rounded-lg overflow-hidden"
                    >
                      <div className="flex items-center gap-3 px-4 py-2 bg-[var(--surface-card)] hover:bg-[var(--hover-subtle)] transition-colors min-w-0">
                        <button
                          type="button"
                          onClick={() => setExpanded(isOpen ? null : cm.d3fendId)}
                          aria-label={isOpen ? 'Collapse' : 'Expand'}
                          aria-expanded={isOpen}
                          aria-controls={`d3f-body-${cm.d3fendId}`}
                          className="shrink-0"
                        >
                          <svg
                            aria-hidden="true"
                            className={`w-4 h-4 text-[var(--text-secondary)] transition-transform duration-200 ${isOpen ? 'rotate-90' : ''}`}
                            fill="none"
                            stroke="currentColor"
                            viewBox="0 0 24 24"
                          >
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                          </svg>
                        </button>
                        <button
                          type="button"
                          onClick={() => setExpanded(isOpen ? null : cm.d3fendId)}
                          aria-expanded={isOpen}
                          aria-controls={`d3f-body-${cm.d3fendId}`}
                          className="flex-1 flex items-center gap-3 text-left min-w-0"
                        >
                          <span className="font-mono text-xs font-bold text-[#6366f1] w-24 shrink-0">
                            {cm.d3fendId}
                          </span>
                          <span className="flex-1 min-w-0 text-sm text-[var(--text-primary)] truncate">
                            {cm.d3fendName ?? cm.d3fendId}
                          </span>
                          {cm.domains.includes('ics-attack') && <Badge label="ICS" variant="orange" />}
                          <Badge label={`${cm.techniqueCount} tech`} variant={meta?.variant ?? 'teal'} />
                        </button>
                      </div>
                      {isOpen && (
                        <div
                          id={`d3f-body-${cm.d3fendId}`}
                          role="region"
                          aria-label={`${cm.d3fendId} details`}
                          className="px-4 py-4 bg-[var(--surface-alt)] space-y-3 border-t border-[var(--border-color)]"
                        >
                          {detailLoading && expanded === cm.d3fendId ? (
                            <DiamondLoader text="Loading..." />
                          ) : detail && detail.countermeasure.d3fendId === cm.d3fendId ? (
                            <>
                              <div className="flex flex-wrap items-center gap-3 text-xs text-[var(--text-secondary)]">
                                <span>
                                  <span className="font-semibold">Tactic:</span> {detail.countermeasure.d3fendTactic}
                                </span>
                                {Object.entries(detail.techniquesByDomain).map(([d, n]) => (
                                  <span key={d}>
                                    <span className="font-semibold">{DOMAIN_LABEL[d] ?? d}:</span> {n}
                                  </span>
                                ))}
                                {detail.countermeasure.d3fendUrl && (
                                  <a
                                    href={d3fendSiteUrl(detail.countermeasure.d3fendUrl)}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-[var(--accent-teal)] hover:underline"
                                  >
                                    D3FEND reference →
                                  </a>
                                )}
                              </div>

                              {detail.techniques.length > 0 && (
                                <div>
                                  <div className="text-xs font-semibold text-[var(--text-secondary)] mb-1.5">
                                    Counters {detail.techniqueCount} technique{detail.techniqueCount === 1 ? '' : 's'}
                                  </div>
                                  <div className="flex flex-wrap gap-1.5">
                                    {detail.techniques.map((t) => (
                                      <EntityLink
                                        key={t.attackId}
                                        type="technique"
                                        attackId={t.attackId}
                                        name={t.name ?? t.attackId}
                                      />
                                    ))}
                                  </div>
                                </div>
                              )}

                              {detail.related.length > 0 && (
                                <div>
                                  <div className="text-xs font-semibold text-[var(--text-secondary)] mb-1.5">
                                    Overlapping countermeasures
                                  </div>
                                  <div className="flex flex-wrap gap-1.5">
                                    {detail.related.map((r) => (
                                      <button
                                        key={r.d3fendId}
                                        type="button"
                                        onClick={() => setExpanded(r.d3fendId)}
                                        title={`${r.d3fendName ?? r.d3fendId} — shares ${r.sharedCount} techniques`}
                                        className="font-mono text-[11px] px-1.5 py-0.5 rounded border border-[var(--border-color)] text-[var(--text-secondary)] hover:text-[var(--accent-teal)] hover:border-[var(--teal-dim)] transition-colors"
                                      >
                                        {r.d3fendId} · {r.sharedCount}
                                      </button>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </>
                          ) : null}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>

      <div className="text-xs text-[var(--text-secondary)] pt-2">
        <p>
          Source:{' '}
          <a
            href="https://d3fend.mitre.org/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-[var(--accent-teal)] hover:underline"
          >
            MITRE D3FEND
          </a>
          . D3FEND maps countermeasures to Enterprise and ICS ATT&amp;CK only; Mobile and ATLAS techniques have no
          countermeasures upstream, so their absence here is not missing data.
        </p>
      </div>
    </div>
  );
}
