import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { apiFetch } from '../../lib/api';
import { EntityLink } from '../shared/EntityLink';
import { Badge } from '../shared/Badge';
import { DiamondLoader } from '../shared/FoldingDiamond';
import { FrameworkMapCard } from './shared/FrameworkMapCard';

// ── Types ──────────────────────────────────────────────────────────────────────

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
  cves: Array<{
    cveId: string;
    description: string | null;
    cvssScore: number | null;
    cvssSeverity: string | null;
    publishedAt: string | null;
    isKev: boolean;
  }>;
  applications: Array<{
    normalized: string;
    vendor: string;
    product: string;
    cveCount: number;
  }>;
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/** CVSS severity → badge variant */
function severityVariant(severity: string | null): 'orange' | 'yellow' | 'blue' | 'neutral' {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL':
    case 'HIGH':
      return 'orange';
    case 'MEDIUM':
      return 'yellow';
    case 'LOW':
      return 'blue';
    default:
      return 'neutral';
  }
}

/** Whether this framework uses community-mapped CWEs (ML / LLM families) */
function isCommunityMapped(framework: string): boolean {
  return framework === 'ml-2023' || framework === 'llm-2025';
}

/** Human-readable framework label */
function frameworkLabel(framework: string): string {
  switch (framework) {
    case 'web-2021':   return 'OWASP Web Top 10 (2021)';
    case 'ml-2023':    return 'OWASP ML Top 10 (2023)';
    case 'llm-2025':   return 'OWASP LLM Top 10 (2025)';
    default:           return framework;
  }
}

// ── Collapsible card — uses shared FrameworkMapCard with OWASP green ──────────

const OWASP_COLOR = '#059669';

function MapCard(props: { label: string; count?: number; defaultOpen?: boolean; children: React.ReactNode }) {
  return <FrameworkMapCard {...props} labelColor={OWASP_COLOR} />;
}

// ── Main component ─────────────────────────────────────────────────────────────

/**
 * 360 Map View for an OWASP risk category.
 * Shows linked ATT&CK techniques, ATLAS techniques, CVEs, affected applications,
 * CWE mappings, and cross-framework related categories.
 */
export function OwaspMapView({ categoryId }: { categoryId: string }) {
  const [showAllCves, setShowAllCves] = useState(false);
  const { data, isLoading, error } = useQuery<OwaspDetail>({
    queryKey: ['owasp-detail', categoryId],
    queryFn: () => apiFetch<OwaspDetail>(`/frameworks/owasp/${categoryId}`),
    staleTime: 5 * 60 * 1000,
    enabled: Boolean(categoryId),
  });

  if (isLoading) {
    return <DiamondLoader text="Loading OWASP map..." />;
  }

  if (error || !data) {
    return (
      <div className="text-[var(--accent-orange)] text-sm py-8 text-center">
        Failed to load OWASP category data.
      </div>
    );
  }

  const communityMapped = isCommunityMapped(data.framework);

  return (
    <div className="space-y-3">
      {/* ── Header ── */}
      <div className="pb-1">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-mono text-xs text-[#059669] bg-[var(--surface-deep)] border border-[var(--border-color)] px-2 py-0.5 rounded">
            {data.categoryId}
          </span>
          <h2 className="text-lg font-semibold text-[var(--text-primary)]">{data.name}</h2>
        </div>
        <div className="flex flex-wrap items-center gap-2 mt-2">
          <Badge label={frameworkLabel(data.framework)} variant="neutral" />
          {data.isDraft && <Badge label="DRAFT" variant="yellow" />}
        </div>
        {data.description && (
          <p className="mt-3 text-sm text-[var(--text-secondary)] leading-relaxed">
            {data.description}
          </p>
        )}
        {data.url && (
          <a
            href={data.url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 mt-2 text-xs text-[#059669] hover:underline"
          >
            <svg
              className="w-3.5 h-3.5 shrink-0"
              fill="none"
              stroke="currentColor"
              strokeWidth={2}
              viewBox="0 0 24 24"
              aria-hidden="true"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"
              />
            </svg>
            OWASP Reference — {data.categoryId}
          </a>
        )}
      </div>

      {/* ── CWEs ── */}
      {data.cwes.length > 0 && (
        <MapCard label="CWE Mappings" count={data.cwes.length}>
          <div className="flex flex-wrap gap-1.5">
            {data.cwes.map((cwe) => (
              <a
                key={cwe}
                href={`https://cwe.mitre.org/data/definitions/${cwe.replace(/^CWE-/i, '')}.html`}
                target="_blank"
                rel="noopener noreferrer"
                title={communityMapped ? 'Community-mapped CWE' : undefined}
                className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-medium border text-[#059669] bg-[var(--surface-deep)] border-[var(--border-color)] hover:brightness-125 hover:underline transition-all duration-150"
              >
                <span className="font-mono">{cwe}</span>
                {communityMapped && (
                  <span className="opacity-60 text-[10px]" title="Community-mapped">~</span>
                )}
              </a>
            ))}
          </div>
          {communityMapped && (
            <p className="text-xs text-[var(--text-secondary)] opacity-70">
              CWE mappings for {frameworkLabel(data.framework)} are community-contributed and may be approximate.
            </p>
          )}
        </MapCard>
      )}

      {/* ── ATT&CK Techniques ── */}
      <MapCard label="ATT&CK Techniques" count={data.techniques.length} defaultOpen={data.techniques.length > 0}>
        {data.techniques.length > 0 ? (
          <div className="flex flex-wrap gap-1.5">
            {data.techniques.map((t) => (
              <EntityLink
                key={`${t.attackId}-${t.cweId}`}
                type="technique"
                attackId={t.attackId}
                name={t.name}
                useMap
              />
            ))}
          </div>
        ) : (
          <p className="text-xs text-[var(--text-secondary)]">No ATT&CK techniques linked to this category.</p>
        )}
      </MapCard>

      {/* ── ATLAS Techniques (only if present) ── */}
      {data.atlasTechniques.length > 0 && (
        <MapCard label="ATLAS Techniques" count={data.atlasTechniques.length}>
          <div className="flex flex-wrap gap-1.5">
            {data.atlasTechniques.map((t) => (
              <a
                key={t.attackId}
                href={`https://atlas.mitre.org/techniques/${t.attackId}`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-medium border text-[var(--accent-purple)] bg-[var(--purple-faint)] border-[var(--purple-dim)] hover:brightness-125 hover:underline transition-all duration-150"
              >
                <span className="opacity-70 font-mono">{t.attackId}</span>
                <span>{t.name}</span>
              </a>
            ))}
          </div>
        </MapCard>
      )}

      {/* ── Top CVEs ── */}
      <MapCard label="Top CVEs" count={data.cves.length} defaultOpen={data.cves.length > 0}>
        {data.cves.length > 0 ? (
          <div className="space-y-2">
            {(showAllCves ? data.cves : data.cves.slice(0, 10)).map((cve) => (
              <div
                key={cve.cveId}
                className="flex flex-wrap items-start gap-2 py-1 border-b border-[var(--border-color)] last:border-0"
              >
                <a
                  href={`https://nvd.nist.gov/vuln/detail/${cve.cveId}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-mono text-xs text-[#059669] hover:underline shrink-0"
                >
                  {cve.cveId}
                </a>
                {cve.cvssSeverity && (
                  <Badge label={cve.cvssSeverity} variant={severityVariant(cve.cvssSeverity)} />
                )}
                {cve.cvssScore !== null && (
                  <span className="text-xs text-[var(--text-secondary)]">
                    CVSS {Number(cve.cvssScore).toFixed(1)}
                  </span>
                )}
                {cve.isKev && <Badge label="KEV" variant="orange" />}
                {cve.description && (
                  <p className="w-full text-xs text-[var(--text-secondary)] leading-relaxed line-clamp-2">
                    {cve.description}
                  </p>
                )}
              </div>
            ))}
            {data.cves.length > 10 && (
              <button
                type="button"
                onClick={() => setShowAllCves((v) => !v)}
                className="mt-2 text-xs text-[#059669] hover:underline"
              >
                {showAllCves ? 'Show less' : `View all (${data.cves.length}) →`}
              </button>
            )}
          </div>
        ) : (
          <p className="text-xs text-[var(--text-secondary)]">No CVEs linked to this category.</p>
        )}
      </MapCard>

      {/* ── Affected Applications ── */}
      <MapCard label="Affected Applications" count={data.applications.length} defaultOpen={false}>
        {data.applications.length > 0 ? (
          <div className="flex flex-wrap gap-1.5">
            {data.applications.map((app) => (
              <a
                key={app.normalized}
                href={`/?entity=${encodeURIComponent(app.normalized)}&tab=application-map`}
                className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-xs font-medium border text-[var(--accent-blue)] bg-[var(--blue-faint)] border-[var(--blue-dim)] hover:brightness-125 transition-all duration-150"
              >
                <span>{app.vendor} / {app.product}</span>
                <span className="opacity-60">({app.cveCount})</span>
              </a>
            ))}
          </div>
        ) : (
          <p className="text-xs text-[var(--text-secondary)]">No affected applications recorded.</p>
        )}
      </MapCard>

      {/* ── Related Categories ── */}
      {data.relatedCategories.length > 0 && (
        <MapCard label="Related Categories" count={data.relatedCategories.length} defaultOpen={false}>
          <div className="flex flex-wrap gap-1.5">
            {data.relatedCategories.map((cat) => (
              <a
                key={`${cat.framework}-${cat.categoryId}`}
                href={`/?entity=${encodeURIComponent(cat.categoryId)}&tab=owasp-map`}
                className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-xs font-medium border text-[#059669] bg-[var(--surface-deep)] border-[var(--border-color)] hover:brightness-125 hover:underline transition-all duration-150"
              >
                <span className="opacity-70 font-mono">{cat.categoryId}</span>
                <span>{cat.name}</span>
                <Badge label={frameworkLabel(cat.framework)} variant="neutral" />
              </a>
            ))}
          </div>
        </MapCard>
      )}
    </div>
  );
}
