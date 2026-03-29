import { useState } from 'react';
import { useMitigation } from '../../hooks/useApi';
import { EntityLink } from '../shared/EntityLink';
import { Badge } from '../shared/Badge';
import { sanitize, sanitizeMarkdown } from '../../lib/sanitize';
import { ExternalLinksButton } from '../shared/ExternalLinksButton';
import { DiamondLoader } from '../shared/FoldingDiamond';
import { getParentId } from '../../lib/getParentId';

// ── Local types ────────────────────────────────────────────────────────────────

interface MitigationWithTechniques {
  techniques?: MitigationTechnique[];
}

interface MitigationTechnique {
  attackId: string;
  name: string;
  description: string | null;
  platforms: string[] | null;
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/** Returns true when attackId is a sub-technique (e.g. T1059.001). */
function isSubTechnique(attackId: string): boolean {
  return /\.\d{3}$/.test(attackId);
}

/** Derives the parent attackId from a sub-technique attackId. */
function parentId(attackId: string): string {
  return getParentId(attackId);
}

/**
 * Splits a flat technique list into parents (with sub-techniques nested).
 * Preserves original order for parents and sub-technique groups.
 */
function buildTechniqueTree(techniques: MitigationTechnique[]): {
  parents: MitigationTechnique[];
  subs: Map<string, MitigationTechnique[]>;
} {
  const parentMap = new Map<string, MitigationTechnique>();
  const subs = new Map<string, MitigationTechnique[]>();

  // First pass: collect parents
  for (const t of techniques) {
    if (!isSubTechnique(t.attackId)) {
      parentMap.set(t.attackId, t);
    }
  }

  // Second pass: bucket sub-techniques; create phantom parent if missing
  for (const t of techniques) {
    if (isSubTechnique(t.attackId)) {
      const pid = parentId(t.attackId);
      if (!parentMap.has(pid)) {
        // phantom parent entry — no standalone data, just a grouping anchor
        parentMap.set(pid, {
          attackId: pid,
          name: pid,
          description: null,
          platforms: null,
        });
      }
      const bucket = subs.get(pid) ?? [];
      bucket.push(t);
      subs.set(pid, bucket);
    }
  }

  // Build ordered parents list: top-level items first (preserving API order),
  // then any phantom parents appended at the end.
  const parents: MitigationTechnique[] = [];
  const seen = new Set<string>();

  for (const t of techniques) {
    if (!isSubTechnique(t.attackId) && !seen.has(t.attackId)) {
      parents.push(t);
      seen.add(t.attackId);
    }
  }

  // Append phantom parents (sub-technique parents not present as top-level)
  for (const [id, entry] of parentMap) {
    if (!seen.has(id)) {
      parents.push(entry);
    }
  }

  return { parents, subs };
}

// ── Icons ──────────────────────────────────────────────────────────────────────

const IconShield = (
  <svg
    fill="none"
    stroke="currentColor"
    strokeWidth={2}
    viewBox="0 0 24 24"
    className="w-4 h-4"
    aria-hidden="true"
  >
    <path
      strokeLinecap="round"
      strokeLinejoin="round"
      d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
    />
  </svg>
);

// ── Collapsible card ───────────────────────────────────────────────────────────

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
          <span className="text-[var(--accent-green)] w-4 h-4 shrink-0">{icon}</span>
          <span className="text-sm font-bold text-[var(--text-secondary)] uppercase tracking-wider">
            {label}
          </span>
          {count !== undefined && (
            <span className="text-xs text-[var(--text-secondary)]">({count})</span>
          )}
        </div>
        <svg
          className={`w-4 h-4 text-[var(--text-secondary)] shrink-0 transition-transform duration-200 ${open ? 'rotate-180' : ''}`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {open && (
        <div className="px-4 py-4 bg-[var(--surface-alt)] space-y-3">{children}</div>
      )}
    </div>
  );
}

/** Labeled row inside a map card. */
function MapRow({ prefix, children }: { prefix: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-3">
      <span className="text-xs text-[var(--text-secondary)] w-32 shrink-0 pt-0.5">{prefix}</span>
      <div className="flex-1 flex flex-wrap gap-1.5">{children}</div>
    </div>
  );
}

// ── Main component ─────────────────────────────────────────────────────────────

interface MitigationMapViewProps {
  attackId: string;
}

/**
 * Structured overview of a MITRE ATT&CK mitigation:
 * identity header, description, techniques it mitigates, and reference link.
 */
export function MitigationMapView({ attackId }: MitigationMapViewProps) {
  const mitigationResult = useMitigation(attackId);

  if (mitigationResult.isLoading) {
    return <DiamondLoader text="Loading mitigation map..." />;
  }

  if (mitigationResult.error || !mitigationResult.data) {
    return (
      <div className="text-[var(--accent-orange)] text-sm py-8 text-center">
        Failed to load mitigation data.
      </div>
    );
  }

  // Intersection cast — detail endpoint returns techniques not in the base Mitigation type
  const data = mitigationResult.data as typeof mitigationResult.data & MitigationWithTechniques;
  const techniques: MitigationTechnique[] = data.techniques ?? [];

  const { parents, subs } = buildTechniqueTree(techniques);

  return (
    <div className="space-y-3">
      {/* Header */}
      <div className="pb-1">
        <div className="flex items-center gap-2">
          <h2 className="text-lg font-semibold text-[var(--text-primary)]">{data.name}</h2>
          <ExternalLinksButton type="mitigation" attackId={data.attackId} name={data.name} />
        </div>
        <div className="flex flex-wrap items-center gap-2 mt-1">
          <span className="font-mono text-xs text-[var(--accent-green)] bg-[var(--green-faint)] border border-[var(--green-dim)] px-2 py-0.5 rounded">
            {data.attackId}
          </span>
          <Badge label="mitigation" variant="green" />
          {data.domain && (
            <Badge label={data.domain.replace('-attack', '')} variant="neutral" />
          )}
          {data.isRevoked && <Badge label="revoked" variant="orange" />}
          {data.isDeprecated && <Badge label="deprecated" variant="neutral" />}
        </div>
      </div>

      {/* Description */}
      {data.description && (
        <div className="bg-[var(--surface-deep)] border border-[var(--border-color)] rounded-lg p-4">
          <p
            className="text-sm text-[var(--text-secondary)] leading-relaxed whitespace-pre-wrap"
            dangerouslySetInnerHTML={{
              __html: sanitize(sanitizeMarkdown(data.description)),
            }}
          />
        </div>
      )}

      {/* Techniques Mitigated */}
      <MapCard
        label="Techniques Mitigated"
        icon={IconShield}
        count={techniques.length}
        defaultOpen
      >
        {techniques.length > 0 ? (
          <div className="space-y-2">
            {parents.map((parent) => {
              const subList = subs.get(parent.attackId) ?? [];
              return (
                <div key={parent.attackId}>
                  {/* Parent technique row */}
                  <div className="flex flex-wrap items-center gap-1.5 py-1">
                    <EntityLink
                      type="technique"
                      attackId={parent.attackId}
                      name={parent.name} useMap />
                    {parent.platforms?.map((platform) => (
                      <Badge key={platform} label={platform} variant="blue" />
                    ))}
                  </div>

                  {/* Sub-techniques nested below */}
                  {subList.length > 0 && (
                    <div className="ml-4 pl-3 border-l border-[var(--border-color)] space-y-1 mt-1">
                      {subList.map((sub) => (
                        <div
                          key={sub.attackId}
                          className="flex flex-wrap items-center gap-1.5 py-0.5"
                        >
                          <EntityLink
                            type="technique"
                            attackId={sub.attackId}
                            name={sub.name} useMap />
                          {sub.platforms?.map((platform) => (
                            <Badge key={platform} label={platform} variant="blue" />
                          ))}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ) : (
          <p className="text-xs text-[var(--text-secondary)]">
            No techniques linked to this mitigation.
          </p>
        )}
      </MapCard>

      {/* Reference */}
      {data.url && (
        <div className="pt-1">
          <p className="text-xs text-[var(--text-secondary)] font-semibold uppercase tracking-wider mb-1.5">
            Reference
          </p>
          <a
            href={data.url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 text-xs text-[var(--accent-green)] hover:underline"
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
            MITRE ATT&amp;CK — {data.attackId}
          </a>
        </div>
      )}
    </div>
  );
}
