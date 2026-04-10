'use client';

import { useState, useMemo, useEffect } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { useQuery } from '@tanstack/react-query';
import { apiFetch } from '../lib/api';
import { PageHeader } from '../components/layout/PageHeader';
import { Badge } from '../components/shared/Badge';
import { EntityLink } from '../components/shared/EntityLink';
import { DiamondLoader } from '../components/shared/FoldingDiamond';
import type { CsfFunctionGroup, CsfDetail } from '../lib/types';

const FUNCTIONS = [
  { id: 'GV', name: 'Govern' },
  { id: 'ID', name: 'Identify' },
  { id: 'PR', name: 'Protect' },
  { id: 'DE', name: 'Detect' },
  { id: 'RS', name: 'Respond' },
  { id: 'RC', name: 'Recover' },
];

export function CsfFramework() {
  const { subcategoryId: urlSubId } = useParams<{ subcategoryId?: string }>();
  const [expanded, setExpanded] = useState<string | null>(() => urlSubId?.toUpperCase() ?? null);
  const [filter, setFilter] = useState<string>('');
  const [functionFilter, setFunctionFilter] = useState<string | null>(null);

  // Sync expanded state from URL param
  useEffect(() => {
    if (urlSubId) setExpanded(urlSubId.toUpperCase());
  }, [urlSubId]);

  const { data, isLoading } = useQuery({
    queryKey: ['csf-list'],
    queryFn: () => apiFetch<{ data: CsfFunctionGroup[]; total: number }>('/frameworks/csf'),
    staleTime: 10 * 60 * 1000,
  });

  // Auto-scroll to expanded item ONCE after list loads. Runs after data is present,
  // not on a fixed timeout, so it works even when the query is slow.
  useEffect(() => {
    if (!urlSubId || isLoading || !data) return;
    const id = urlSubId.toUpperCase();
    const t = setTimeout(() => {
      document.getElementById(`csf-sub-${id}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }, 50);
    return () => clearTimeout(t);
  }, [urlSubId, isLoading, data]);

  const { data: detail, isLoading: detailLoading } = useQuery({
    queryKey: ['csf-detail', expanded],
    queryFn: () => apiFetch<CsfDetail>(`/frameworks/csf/${expanded}`),
    enabled: !!expanded,
    staleTime: 5 * 60 * 1000,
  });

  const filteredGroups = useMemo(() => {
    const groups = data?.data ?? [];
    const q = filter.toLowerCase().trim();
    return groups
      .filter((g) => !functionFilter || g.function === functionFilter)
      .map((g) => ({
        ...g,
        subcategories: g.subcategories.filter((s) =>
          !q ||
          s.subcategoryId.toLowerCase().includes(q) ||
          s.name.toLowerCase().includes(q),
        ),
      }))
      .filter((g) => g.subcategories.length > 0);
  }, [data, filter, functionFilter]);

  if (isLoading) return <DiamondLoader text="Loading NIST CSF v2..." />;

  const total = data?.total ?? 0;
  const visibleCount = filteredGroups.reduce((sum, g) => sum + g.subcategories.length, 0);

  return (
    <div className="space-y-4">
      <PageHeader
        title="NIST CSF v2"
        subtitle="NIST Cybersecurity Framework v2 subcategories mapped to ATT&CK techniques via CTID's CRI Profile direct mappings"
        actions={
          <span className="text-[var(--text-secondary)] text-sm">
            {visibleCount} of {total} subcategories
          </span>
        }
      />

      <div className="flex items-center gap-2 flex-wrap">
        <button
          type="button"
          onClick={() => setFunctionFilter(null)}
          className={`px-3 py-1.5 text-xs rounded-md border transition-colors ${
            functionFilter === null
              ? 'border-[#6366f1] text-[#6366f1] bg-[#6366f1]/10'
              : 'border-[var(--border-color)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
          }`}
        >
          All
        </button>
        {FUNCTIONS.map((f) => (
          <button
            key={f.id}
            type="button"
            onClick={() => setFunctionFilter(f.id)}
            className={`px-3 py-1.5 text-xs rounded-md border font-mono transition-colors ${
              functionFilter === f.id
                ? 'border-[#6366f1] text-[#6366f1] bg-[#6366f1]/10'
                : 'border-[var(--border-color)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
            }`}
          >
            {f.id} {f.name}
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
        {filteredGroups.map((group) => (
          <div key={group.function}>
            <h3 className="text-sm font-bold text-[#6366f1] uppercase tracking-wider mb-2">
              {group.function} — {group.functionName} ({group.subcategories.length})
            </h3>
            <div className="space-y-1">
              {group.subcategories.map((sub) => {
                const isOpen = expanded === sub.subcategoryId;
                return (
                  <div
                    key={sub.subcategoryId}
                    id={`csf-sub-${sub.subcategoryId}`}
                    className="border border-[var(--border-color)] rounded-lg overflow-hidden"
                  >
                    <div className="flex items-center gap-3 px-4 py-2 bg-[var(--surface-card)] hover:bg-[var(--hover-subtle)] transition-colors">
                      <button
                        type="button"
                        onClick={() => setExpanded(isOpen ? null : sub.subcategoryId)}
                        aria-expanded={isOpen}
                        aria-controls={`csf-body-${sub.subcategoryId}`}
                        className="flex-1 flex items-center gap-3 text-left min-w-0"
                      >
                        <span className="font-mono text-xs font-bold text-[#6366f1] w-20 shrink-0">
                          {sub.subcategoryId}
                        </span>
                        <span className="flex-1 text-sm text-[var(--text-primary)] truncate">{sub.name}</span>
                        <Badge label={`${sub.techniqueCount} tech`} variant="teal" />
                      </button>
                      <Link
                        href={`/?entity=${encodeURIComponent(sub.subcategoryId)}&tab=csf-map`}
                        prefetch={false}
                        className="text-[10px] text-[#6366f1] hover:underline shrink-0"
                        title="Open 360 map view"
                      >
                        360 →
                      </Link>
                      <button
                        type="button"
                        onClick={() => setExpanded(isOpen ? null : sub.subcategoryId)}
                        aria-label={isOpen ? 'Collapse' : 'Expand'}
                        className="shrink-0"
                      >
                        <svg
                          className={`w-4 h-4 text-[var(--text-secondary)] transition-transform duration-200 ${isOpen ? 'rotate-180' : ''}`}
                          fill="none"
                          stroke="currentColor"
                          viewBox="0 0 24 24"
                        >
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                        </svg>
                      </button>
                    </div>
                    {isOpen && (
                      <div
                        id={`csf-body-${sub.subcategoryId}`}
                        role="region"
                        className="px-4 py-4 bg-[var(--surface-alt)] space-y-3 border-t border-[var(--border-color)]"
                      >
                        {detailLoading && expanded === sub.subcategoryId ? (
                          <DiamondLoader text="Loading..." />
                        ) : detail && detail.subcategoryId === sub.subcategoryId ? (
                          <>
                            {detail.description && detail.description !== detail.name && (
                              <p className="text-sm text-[var(--text-secondary)]">{detail.description}</p>
                            )}
                            <div className="text-xs text-[var(--text-secondary)]">
                              <span className="font-semibold">Category:</span> {detail.categoryName}
                            </div>

                            {detail.techniques.length > 0 ? (
                              <div>
                                <h4 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider mb-2">
                                  ATT&CK Techniques ({detail.techniques.length})
                                </h4>
                                <div className="flex flex-wrap gap-1.5">
                                  {detail.techniques.map((t) => (
                                    <EntityLink
                                      key={t.attackId}
                                      type="technique"
                                      attackId={t.attackId}
                                      name={t.name ?? t.attackId}
                                      useMap
                                    />
                                  ))}
                                </div>
                              </div>
                            ) : (
                              <p className="text-xs text-[var(--text-secondary)] italic">
                                No ATT&CK technique mappings yet. Mappings come from CTID's CRI Profile dataset, which covers a subset of CSF subcategories.
                              </p>
                            )}

                            {detail.relatedSubcategories.length > 0 && (
                              <div>
                                <h4 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider mb-2">
                                  Related Subcategories
                                </h4>
                                <div className="flex flex-wrap gap-1.5">
                                  {detail.relatedSubcategories.map((r) => (
                                    <button
                                      key={r.subcategoryId}
                                      type="button"
                                      onClick={() => {
                                        setExpanded(r.subcategoryId);
                                        setTimeout(() => {
                                          document.getElementById(`csf-sub-${r.subcategoryId}`)
                                            ?.scrollIntoView({ behavior: 'smooth', block: 'center' });
                                        }, 50);
                                      }}
                                      className="text-[10px] px-2 py-0.5 rounded bg-[var(--surface-card)] border border-[var(--border-color)] text-[#6366f1] hover:border-[#6366f1] transition-colors"
                                      title={`${r.subcategoryId} — ${r.name} (shares ${r.sharedCount} techniques)`}
                                    >
                                      <span className="font-mono">{r.subcategoryId}</span>
                                      <span className="ml-1 text-[var(--text-secondary)]">({r.sharedCount})</span>
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
        ))}
      </div>
    </div>
  );
}
