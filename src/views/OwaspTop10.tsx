'use client';
import { useState, useEffect } from 'react';
import { useParams } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import { apiFetch } from '../lib/api';
import { PageHeader } from '../components/layout/PageHeader';
import { Badge } from '../components/shared/Badge';
import { EntityLink } from '../components/shared/EntityLink';
import { DiamondLoader } from '../components/shared/FoldingDiamond';
import { formatDate } from '../lib/formatDate';

interface OwaspCategory {
  categoryId: string;
  name: string;
  description: string | null;
  url: string | null;
  framework: string;
  isDraft: boolean;
  atlasCount: number;
  cweCount: number;
  techniqueCount: number;
  cveCount: number;
}

interface OwaspDetail {
  categoryId: string;
  name: string;
  description: string | null;
  url: string | null;
  framework: string;
  isDraft: boolean;
  cwes: string[];
  techniques: Array<{ attackId: string; name: string; cweId: string }>;
  atlasTechniques: Array<{ attackId: string; name: string }>;
  relatedCategories: Array<{ categoryId: string; name: string; framework: string }>;
  cves: Array<{ cveId: string; description: string | null; cvssScore: number | null; cvssSeverity: string | null; publishedAt: string | null; isKev: boolean }>;
  applications: Array<{ normalized: string; vendor: string; product: string; cveCount: number }>;
}

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: 'text-pink-500',
  HIGH: 'text-orange-500',
  MEDIUM: 'text-yellow-500',
  LOW: 'text-blue-400',
};

export function OwaspTop10() {
  const { categoryId: urlCategoryId } = useParams<{ categoryId?: string }>();
  const [expanded, setExpanded] = useState<string | null>(urlCategoryId?.toUpperCase() ?? null);
  const [framework, setFramework] = useState<string | null>(null);

  // Auto-expand when navigating via URL param (e.g. /frameworks/owasp/A01)
  useEffect(() => {
    if (urlCategoryId) setExpanded(urlCategoryId.toUpperCase());
  }, [urlCategoryId]);

  const { data, isLoading } = useQuery({
    queryKey: ['owasp-top10', framework],
    queryFn: () => apiFetch<{ data: OwaspCategory[]; frameworks: string[] }>(
      '/frameworks/owasp' + (framework ? `?framework=${framework}` : '')
    ),
  });

  const { data: detail, isLoading: detailLoading } = useQuery({
    queryKey: ['owasp-detail', expanded, framework],
    queryFn: () => apiFetch<OwaspDetail>(`/frameworks/owasp/${expanded}`),
    enabled: !!expanded,
  });

  if (isLoading) return <DiamondLoader text="Loading OWASP Top 10..." />;

  const categories = data?.data ?? [];

  return (
    <div className="space-y-4">
      <PageHeader
        title={
          framework === 'ml-2023' ? 'OWASP Top 10 for ML (2023)'
          : framework === 'llm-2025' ? 'OWASP Top 10 for LLM (2025)'
          : framework === 'web-2021' ? 'OWASP Top 10 (2021)'
          : 'OWASP Top 10'
        }
        subtitle={
          framework === 'ml-2023' ? 'Machine learning security risks mapped to ATLAS techniques'
          : framework === 'llm-2025' ? 'LLM application security risks mapped to ATT&CK + ATLAS techniques'
          : 'Web application security risks mapped to ATT&CK techniques via CWE → CAPEC bridge'
        }
      />

      <div className="flex gap-2">
        {[null, 'web-2021', 'ml-2023', 'llm-2025'].map(fw => (
          <button key={fw ?? 'all'}
            type="button"
            onClick={() => { setFramework(fw); setExpanded(null); }}
            className={`px-3 py-1.5 text-xs rounded-md border transition-colors ${
              framework === fw
                ? 'border-[var(--accent-teal)] text-[var(--accent-teal)] bg-[var(--teal-ghost)]'
                : 'border-[var(--border-color)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
            }`}
          >
            {fw === null ? 'All' : fw === 'web-2021' ? 'Web (2021)' : fw === 'ml-2023' ? 'ML (2023)' : 'LLM (2025)'}
          </button>
        ))}
      </div>

      <div className="space-y-2">
        {categories.map((cat) => {
          const isOpen = expanded === cat.categoryId;
          return (
            <div key={cat.categoryId} className="border border-[var(--border-color)] rounded-lg overflow-hidden">
              {/* Category header */}
              <div className="flex items-center gap-3 px-4 py-3 bg-[var(--surface-card)] hover:bg-[var(--hover-subtle)] transition-colors min-w-0">
                <button
                  type="button"
                  onClick={() => setExpanded(isOpen ? null : cat.categoryId)}
                  aria-expanded={isOpen}
                  aria-controls={`owasp-body-${cat.categoryId}`}
                  className="flex-1 flex items-center gap-3 text-left min-w-0"
                >
                  <span className="font-mono text-sm font-bold text-[var(--accent-teal)] w-10 shrink-0">
                    {cat.categoryId}
                  </span>
                  <span className="min-w-0 text-sm font-medium text-[var(--text-primary)] truncate">
                    {cat.name}
                  </span>
                </button>
                <a
                  href={`/?entity=${encodeURIComponent(cat.categoryId)}&tab=owasp-map`}
                  onClick={(e) => e.stopPropagation()}
                  className="text-[10px] font-medium text-[#059669] hover:underline shrink-0"
                  title="Open 360 map view"
                >
                  360 →
                </a>
                <div className="flex items-center gap-2 shrink-0 ml-auto">
                  <Badge label={`${cat.cweCount} CWEs`} variant="neutral" />
                  <Badge label={`${cat.techniqueCount} techniques`} variant="teal" />
                  <span className="hidden sm:inline">
                    <Badge label={`${cat.cveCount.toLocaleString()} CVEs`} variant="pink" />
                  </span>
                  {cat.isDraft && <Badge label="DRAFT" variant="neutral" />}
                  {cat.atlasCount > 0 && <Badge label={`${cat.atlasCount} ATLAS`} variant="purple" />}
                </div>
                <button
                  type="button"
                  onClick={() => setExpanded(isOpen ? null : cat.categoryId)}
                  aria-label={isOpen ? 'Collapse' : 'Expand'}
                  aria-expanded={isOpen}
                  aria-controls={`owasp-body-${cat.categoryId}`}
                  className="shrink-0"
                >
                  <svg
                    aria-hidden="true"
                    className={`w-4 h-4 text-[var(--text-secondary)] transition-transform duration-200 ${isOpen ? 'rotate-90' : ''}`}
                    fill="none" stroke="currentColor" viewBox="0 0 24 24"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                </button>
              </div>

              {/* Expanded detail */}
              {isOpen && (
                <div
                  id={`owasp-body-${cat.categoryId}`}
                  role="region"
                  className="px-4 py-4 bg-[var(--surface-alt)] space-y-4 border-t border-[var(--border-color)]"
                >
                  {detailLoading ? (
                    <DiamondLoader text="Loading..." />
                  ) : detail ? (
                    <>
                      {/* Description */}
                      {detail.description && (
                        <p className="text-sm text-[var(--text-secondary)]">{detail.description}</p>
                      )}

                      {/* CWEs */}
                      <div>
                        <h4 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider mb-2">
                          CWEs ({detail.cwes.length})
                        </h4>
                        <div className="flex flex-wrap gap-1.5">
                          {detail.cwes.map((cwe) => (
                            <a
                              key={cwe}
                              href={`https://cwe.mitre.org/data/definitions/${cwe.replace('CWE-', '')}.html`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-[10px] px-2 py-0.5 rounded bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-secondary)] hover:text-[var(--accent-teal)] hover:border-[var(--teal-dim)] transition-colors"
                            >
                              {cwe}
                            </a>
                          ))}
                        </div>
                        {(detail?.framework === 'ml-2023' || detail?.framework === 'llm-2025') && detail?.cwes && detail.cwes.length > 0 && (
                          <span
                            className="text-[10px] text-[var(--text-secondary)] italic cursor-help"
                            title="CWE mappings are community-contributed, not OWASP-official"
                          >
                            Community-mapped CWEs
                          </span>
                        )}
                      </div>

                      {/* Techniques */}
                      {detail.techniques.length > 0 && (
                        <div>
                          <h4 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider mb-2">
                            ATT&CK Techniques ({detail.techniques.length})
                          </h4>
                          <div className="flex flex-wrap gap-1.5">
                            {[...new Map(detail.techniques.map((t) => [t.attackId, t])).values()].map((t) => (
                              <EntityLink key={t.attackId} type="technique" attackId={t.attackId} name={t.name} useMap />
                            ))}
                          </div>
                        </div>
                      )}

                      {/* ATLAS Techniques */}
                      {detail.atlasTechniques && detail.atlasTechniques.length > 0 && (
                        <div>
                          <h4 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider mb-2">
                            ATLAS Techniques ({detail.atlasTechniques.length})
                          </h4>
                          <div className="flex flex-wrap gap-1.5">
                            {detail.atlasTechniques.map((t) => (
                              <EntityLink key={t.attackId} type="technique" attackId={t.attackId} name={t.name} useMap />
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Top CVEs */}
                      {detail.cves.length > 0 && (
                        <div>
                          <h4 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider mb-2">
                            Top CVEs (by CVSS)
                          </h4>
                          <div className="space-y-1">
                            {detail.cves.slice(0, 10).map((cve) => (
                              <a
                                key={cve.cveId}
                                href={`/cti/cves/${cve.cveId}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="flex items-center gap-2 px-3 py-1.5 rounded bg-[var(--surface-card)] border border-[var(--border-color)] hover:border-[var(--teal-dim)] transition-colors"
                              >
                                <span className="font-mono text-xs text-[var(--accent-teal)]">{cve.cveId}</span>
                                {cve.cvssSeverity && (
                                  <span className={`text-[10px] font-bold ${SEVERITY_COLOR[cve.cvssSeverity] ?? ''}`}>
                                    {cve.cvssSeverity}
                                  </span>
                                )}
                                {cve.cvssScore !== null && (
                                  <span className="text-[10px] text-[var(--text-secondary)]">{cve.cvssScore}</span>
                                )}
                                {cve.isKev && <Badge label="KEV" variant="pink" />}
                                <span className="flex-1 text-[10px] text-[var(--text-secondary)] truncate">
                                  {cve.description?.slice(0, 80)}
                                </span>
                                {cve.publishedAt && (
                                  <span className="text-[10px] text-[var(--text-secondary)] shrink-0">
                                    {formatDate(cve.publishedAt)}
                                  </span>
                                )}
                              </a>
                            ))}
                          </div>
                          <a
                            href={`/cti/cves`}
                            className="inline-block mt-2 text-xs text-[var(--accent-teal)] hover:underline"
                          >
                            View all CVEs →
                          </a>
                        </div>
                      )}

                      {/* Affected Applications */}
                      {detail.applications.length > 0 && (
                        <div>
                          <h4 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider mb-2">
                            Affected Applications ({detail.applications.length})
                          </h4>
                          <div className="flex flex-wrap gap-1.5">
                            {detail.applications.slice(0, 20).map((app) => (
                              <a
                                key={app.normalized}
                                href={`/?entity=${encodeURIComponent(app.normalized)}&tab=application-map`}
                                className="text-[10px] px-2 py-0.5 rounded bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--accent-blue)] hover:border-[var(--accent-blue)] transition-colors"
                              >
                                {app.vendor} {app.product} ({app.cveCount})
                              </a>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Related Categories */}
                      {detail.relatedCategories && detail.relatedCategories.length > 0 && (
                        <div>
                          <h4 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider mb-2">
                            Related Categories
                          </h4>
                          <div className="flex flex-wrap gap-1.5">
                            {detail.relatedCategories.map((rc) => (
                              <button
                                key={`${rc.categoryId}-${rc.framework}`}
                                type="button"
                                onClick={() => { setFramework(null); setExpanded(rc.categoryId); }}
                                className="text-[10px] px-2 py-0.5 rounded bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--accent-orange)] hover:border-[var(--orange-dim)] transition-colors"
                              >
                                {rc.categoryId} {rc.name} ({rc.framework})
                              </button>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* OWASP link */}
                      {detail.url && (
                        <a
                          href={detail.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-block text-xs text-[var(--accent-teal)] hover:underline"
                        >
                          View on OWASP →
                        </a>
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
}

export default OwaspTop10;
