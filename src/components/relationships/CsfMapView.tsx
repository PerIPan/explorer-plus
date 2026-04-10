'use client';

import { useQuery } from '@tanstack/react-query';
import { apiFetch } from '../../lib/api';
import { EntityLink } from '../shared/EntityLink';
import { Badge } from '../shared/Badge';
import { DiamondLoader } from '../shared/FoldingDiamond';
import { FrameworkMapCard } from './shared/FrameworkMapCard';

// ── Types ────────────────────────────────────────────────────────────────────

interface CsfDetail {
  subcategoryId: string;
  function: string;
  functionName: string;
  categoryId: string;
  categoryName: string;
  name: string;
  description: string | null;
  techniques: Array<{ attackId: string; name: string | null; tacticName: string | null }>;
  relatedSubcategories: Array<{ subcategoryId: string; name: string; function: string; sharedCount: number }>;
}

const CSF_COLOR = '#6366f1';

// ── CSF card wrapper uses shared component with indigo label ────────────────
function MapCard(props: { label: string; count?: number; defaultOpen?: boolean; children: React.ReactNode }) {
  return <FrameworkMapCard {...props} labelColor={CSF_COLOR} />;
}

// ── Main component ──────────────────────────────────────────────────────────

/**
 * 360 Map View for a NIST CSF v2 subcategory.
 * Shows the subcategory metadata, linked ATT&CK techniques, and related subcategories.
 */
export function CsfMapView({ subcategoryId }: { subcategoryId: string }) {
  const { data, isLoading, error } = useQuery<CsfDetail>({
    queryKey: ['csf-detail', subcategoryId],
    queryFn: () => apiFetch<CsfDetail>(`/frameworks/csf/${subcategoryId}`),
    staleTime: 5 * 60 * 1000,
    enabled: Boolean(subcategoryId),
  });

  if (isLoading) {
    return <DiamondLoader text="Loading CSF subcategory..." />;
  }

  if (error || !data) {
    return (
      <div className="text-[var(--accent-orange)] text-sm py-8 text-center">
        Failed to load CSF subcategory.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* ── Header ── */}
      <div className="pb-1">
        <div className="flex items-center gap-2 flex-wrap mb-2">
          <span className="font-mono text-xs text-[#6366f1] bg-[var(--surface-deep)] border border-[var(--border-color)] px-2 py-0.5 rounded">
            {data.subcategoryId}
          </span>
          <Badge label={data.functionName} variant="neutral" />
          <span className="text-xs text-[var(--text-secondary)]">{data.categoryName}</span>
        </div>
        <h2 className="text-base font-semibold text-[var(--text-primary)] mb-1">{data.name}</h2>
        {data.description && data.description !== data.name && (
          <p className="text-sm text-[var(--text-secondary)]">{data.description}</p>
        )}
      </div>

      {/* ── Linked ATT&CK techniques ── */}
      <MapCard label="ATT&CK Techniques" count={data.techniques.length} defaultOpen={data.techniques.length > 0}>
        {data.techniques.length === 0 ? (
          <p className="text-xs text-[var(--text-secondary)] italic">
            No direct ATT&CK technique mappings yet. Run the CSF sync cron to populate.
          </p>
        ) : (
          <div className="flex flex-wrap gap-1.5">
            {data.techniques.map((t) => (
              <EntityLink
                key={t.attackId}
                type="technique"
                attackId={t.attackId}
                name={t.name ?? t.attackId}
                useMap
              />
            ))}
          </div>
        )}
      </MapCard>

      {/* ── Related subcategories ── */}
      {data.relatedSubcategories.length > 0 && (
        <MapCard label="Related CSF Subcategories" count={data.relatedSubcategories.length} defaultOpen={false}>
          <div className="flex flex-wrap gap-1.5">
            {data.relatedSubcategories.map((r) => (
              <a
                key={r.subcategoryId}
                href={`/?entity=${encodeURIComponent(r.subcategoryId)}&tab=csf-map`}
                className="text-[10px] px-2 py-0.5 rounded bg-[var(--surface-card)] border border-[var(--border-color)] text-[#6366f1] hover:border-[#6366f1] transition-colors"
                title={`${r.subcategoryId} — ${r.name} (shares ${r.sharedCount} techniques)`}
              >
                <span className="font-mono">{r.subcategoryId}</span>
                <span className="ml-1 text-[var(--text-secondary)]">({r.sharedCount})</span>
              </a>
            ))}
          </div>
        </MapCard>
      )}

      {/* ── Link to full page ── */}
      <a
        href={`/frameworks/csf/${data.subcategoryId}`}
        className="inline-block text-xs text-[#6366f1] hover:underline"
      >
        View full CSF subcategory page →
      </a>
    </div>
  );
}
