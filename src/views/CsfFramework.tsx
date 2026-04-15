'use client';

import { useState, useMemo, useEffect } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import { apiFetch } from '../lib/api';
import { PageHeader } from '../components/layout/PageHeader';
import { Badge } from '../components/shared/Badge';
import { EntityLink } from '../components/shared/EntityLink';
import { DiamondLoader } from '../components/shared/FoldingDiamond';
import type { CsfFunctionGroup, CsfDetail } from '../lib/types';

const FUNCTIONS = [
  { id: 'GV', name: 'Govern',   description: 'Establish and monitor the cybersecurity risk management strategy, expectations, and policy.' },
  { id: 'ID', name: 'Identify', description: 'Help determine the current cybersecurity risk to the organization.' },
  { id: 'PR', name: 'Protect',  description: 'Use safeguards to prevent or reduce cybersecurity risk.' },
  { id: 'DE', name: 'Detect',   description: 'Find and analyze possible cybersecurity attacks and compromises.' },
  { id: 'RS', name: 'Respond',  description: 'Take action regarding a detected cybersecurity incident.' },
  { id: 'RC', name: 'Recover',  description: 'Restore assets and operations affected by a cybersecurity incident.' },
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
            title={f.description}
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
                    <div className="flex items-center gap-3 px-4 py-2 bg-[var(--surface-card)] hover:bg-[var(--hover-subtle)] transition-colors min-w-0">
                      <button
                        type="button"
                        onClick={() => setExpanded(isOpen ? null : sub.subcategoryId)}
                        aria-label={isOpen ? 'Collapse' : 'Expand'}
                        aria-expanded={isOpen}
                        aria-controls={`csf-body-${sub.subcategoryId}`}
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
                        onClick={() => setExpanded(isOpen ? null : sub.subcategoryId)}
                        aria-expanded={isOpen}
                        aria-controls={`csf-body-${sub.subcategoryId}`}
                        className="flex-1 flex items-center gap-3 text-left min-w-0"
                      >
                        <span className="font-mono text-xs font-bold text-[#6366f1] w-20 shrink-0">
                          {sub.subcategoryId}
                        </span>
                        <span className="flex-1 min-w-0 text-sm text-[var(--text-primary)] truncate">{sub.name}</span>
                        <Badge label={`${sub.techniqueCount} tech`} variant="teal" />
                      </button>
                    </div>
                    {isOpen && (
                      <div
                        id={`csf-body-${sub.subcategoryId}`}
                        role="region"
                        aria-label={`${sub.subcategoryId} details`}
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
                              {detail.categoryDescription && (
                                <span className="block mt-1 italic opacity-90">{detail.categoryDescription}</span>
                              )}
                            </div>

                            {(detail.techniques ?? []).length > 0 && (
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
                            )}

                            {(detail.implementationExamples ?? []).length > 0 && (
                              <CsfExamplesSection
                                key={sub.subcategoryId}
                                examples={detail.implementationExamples}
                                defaultOpen={(detail.techniques ?? []).length === 0}
                                parentId={sub.subcategoryId}
                              />
                            )}

                            {(detail.informativeReferences ?? []).length > 0 && (
                              <CsfInformativeReferencesSection
                                key={`${sub.subcategoryId}-refs`}
                                references={detail.informativeReferences}
                                parentId={sub.subcategoryId}
                              />
                            )}

                            {(detail.techniques ?? []).length === 0 && (detail.implementationExamples ?? []).length === 0 && (
                              <p className="text-xs text-[var(--text-secondary)] italic">
                                No ATT&CK technique mappings yet. CTID's CRI Profile covers a subset of CSF subcategories focused on Protect and Detect.
                              </p>
                            )}

                            {(detail.relatedSubcategories ?? []).length > 0 && (
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

/** Collapsible "Implementation Examples" block, shown per expanded CSF subcategory. */
function CsfExamplesSection({
  examples,
  defaultOpen,
  parentId,
}: {
  examples: Array<{ exampleId: string; ordinal: number; text: string }>;
  defaultOpen: boolean;
  parentId: string;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const listId = `csf-examples-${parentId}`;
  return (
    <div>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        aria-controls={listId}
        className="flex items-center gap-2 text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider mb-2 hover:text-[var(--text-primary)]"
      >
        <svg
          aria-hidden="true"
          className={`w-3 h-3 transition-transform duration-200 ${open ? 'rotate-90' : ''}`}
          fill="none"
          stroke="currentColor"
          strokeWidth={2}
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
        </svg>
        Implementation Examples ({examples.length})
      </button>
      {open && (
        <ul id={listId} className="space-y-1.5 pl-4 list-disc marker:text-[#6366f1]">
          {examples.map((ex) => (
            <li key={ex.exampleId} className="text-xs text-[var(--text-secondary)] leading-relaxed">
              {ex.text}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

const REF_FRAMEWORK_META: Record<string, { label: string; colorClass: string; detailHref?: (id: string) => string }> = {
  '800-53r5': {
    label: 'NIST 800-53 r5',
    colorClass: 'text-[var(--accent-teal)] border-[var(--teal-dim)] bg-[var(--teal-faint)]',
    detailHref: (id) => {
      // Deep-link into the NIST Controls list pre-filtered to this control.
      // Only the bare `FAMILY-NN` form matches cleanly; enhancements like
      // `(01)` are rendered as plain text.
      const m = id.match(/^[A-Z]{2}-\d{2}$/);
      return m ? `/frameworks/nist?search=${id}` : '';
    },
  },
  'iso-27001-2022': {
    label: 'ISO 27001:2022',
    colorClass: 'text-[var(--accent-blue)] border-[var(--blue-dim)] bg-[var(--blue-faint)]',
  },
};

/** Collapsible block that groups Informative References by target framework. */
function CsfInformativeReferencesSection({
  references,
  parentId,
}: {
  references: Array<{ framework: string; id: string; text: string | null; relationship: string | null }>;
  parentId: string;
}) {
  const [open, setOpen] = useState(true);
  const listId = `csf-refs-${parentId}`;

  const grouped = new Map<string, Array<{ id: string }>>();
  for (const r of references) {
    const arr = grouped.get(r.framework) ?? [];
    arr.push({ id: r.id });
    grouped.set(r.framework, arr);
  }

  return (
    <div>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        aria-controls={listId}
        className="flex items-center gap-2 text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider mb-2 hover:text-[var(--text-primary)]"
      >
        <svg
          aria-hidden="true"
          className={`w-3 h-3 transition-transform duration-200 ${open ? 'rotate-90' : ''}`}
          fill="none"
          stroke="currentColor"
          strokeWidth={2}
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
        </svg>
        Informative References ({references.length})
      </button>
      {open && (
        <div id={listId} className="space-y-2 pl-4">
          {Array.from(grouped.entries()).map(([framework, items]) => {
            const meta = REF_FRAMEWORK_META[framework] ?? {
              label: framework,
              colorClass: 'text-[var(--text-secondary)] border-[var(--border-color)] bg-[var(--surface-card)]',
            };
            return (
              <div key={framework}>
                <div className="text-[10px] font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-1">
                  {meta.label} ({items.length})
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {items.map((ref) => {
                    const href = meta.detailHref?.(ref.id);
                    const className = `inline-block text-[10px] font-mono px-2 py-0.5 rounded border ${meta.colorClass}`;
                    return href ? (
                      <Link key={ref.id} href={href} className={`${className} hover:underline`}>
                        {ref.id}
                      </Link>
                    ) : (
                      <span key={ref.id} className={className}>{ref.id}</span>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
