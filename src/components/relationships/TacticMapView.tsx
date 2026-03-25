import { useState } from 'react';
import { useTactic } from '../../hooks/useApi';
import { EntityLink } from '../shared/EntityLink';
import { Badge } from '../shared/Badge';
import { sanitize, sanitizeMarkdown } from '../../lib/sanitize';
import { ExternalLinksButton } from '../shared/ExternalLinksButton';

// ── Local technique shape (as returned by useTactic) ──────────────────────────

interface TacticTechnique {
  attackId: string;
  name: string;
  description?: string | null;
  platforms?: string[] | null;
  isSubtechnique?: boolean;
}

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
          <span className="text-[var(--accent-teal)] w-4 h-4 shrink-0">{icon}</span>
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
        <div className="px-4 py-4 bg-[var(--surface-alt)] space-y-3">
          {children}
        </div>
      )}
    </div>
  );
}

/** Labeled row with a fixed-width prefix and flexible children area. */
function MapRow({ prefix, children }: { prefix: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-3">
      <span className="text-xs text-[var(--text-secondary)] w-32 shrink-0 pt-0.5">{prefix}</span>
      <div className="flex-1 flex flex-wrap gap-1.5">{children}</div>
    </div>
  );
}

// ── Icons ─────────────────────────────────────────────────────────────────────

const IconGrid = (
  <svg fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" className="w-4 h-4">
    <path
      strokeLinecap="round"
      strokeLinejoin="round"
      d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"
    />
  </svg>
);

// ── Technique hierarchy helpers ────────────────────────────────────────────────

interface TechniqueGroup {
  parent: TacticTechnique;
  subs: TacticTechnique[];
}

/**
 * Partition techniques into parent/sub groups and build an ordered hierarchy.
 * Sub-techniques are identified by a dot in their attackId (e.g. T1059.001)
 * or by isSubtechnique=true when provided by the API.
 */
function buildHierarchy(techniques: TacticTechnique[]): {
  groups: TechniqueGroup[];
  orphanSubs: TacticTechnique[];
} {
  const isSubtechnique = (t: TacticTechnique) =>
    t.isSubtechnique === true || t.attackId.includes('.');

  const parents = techniques
    .filter((t) => !isSubtechnique(t))
    .sort((a, b) => a.attackId.localeCompare(b.attackId));

  const subs = techniques.filter(isSubtechnique);

  const parentMap = new Map<string, TacticTechnique>(parents.map((p) => [p.attackId, p]));

  const subsByParent = new Map<string, TacticTechnique[]>();
  const orphanSubs: TacticTechnique[] = [];

  for (const sub of subs) {
    const parentId = sub.attackId.split('.')[0];
    if (parentMap.has(parentId)) {
      const list = subsByParent.get(parentId) ?? [];
      list.push(sub);
      subsByParent.set(parentId, list);
    } else {
      orphanSubs.push(sub);
    }
  }

  const groups: TechniqueGroup[] = parents.map((parent) => ({
    parent,
    subs: (subsByParent.get(parent.attackId) ?? []).sort((a, b) =>
      a.attackId.localeCompare(b.attackId)
    ),
  }));

  return { groups, orphanSubs: orphanSubs.sort((a, b) => a.attackId.localeCompare(b.attackId)) };
}

// ── Main component ─────────────────────────────────────────────────────────────

interface TacticMapViewProps {
  attackId: string;
}

/**
 * Structured overview of a MITRE ATT&CK tactic and its technique hierarchy.
 */
export function TacticMapView({ attackId }: TacticMapViewProps) {
  const { data: tactic, isLoading, error } = useTactic(attackId);

  // ── Loading state ──────────────────────────────────────────────────────────
  if (isLoading) {
    return (
      <div className="flex items-center gap-2 text-[var(--text-secondary)] text-sm py-8 justify-center">
        <span className="inline-block w-5 h-5 border-2 border-[var(--teal-dim)] border-t-[var(--accent-teal)] rounded-full animate-spin" />
        Loading tactic map...
      </div>
    );
  }

  // ── Error state ────────────────────────────────────────────────────────────
  if (error || !tactic) {
    return (
      <div className="text-[var(--accent-orange)] text-sm py-8 text-center">
        Failed to load tactic data.
      </div>
    );
  }

  // ── Derived data ───────────────────────────────────────────────────────────
  const techniques: TacticTechnique[] = tactic.techniques ?? [];
  const totalCount = techniques.length;

  const { groups, orphanSubs } = buildHierarchy(techniques);

  const parentCount = groups.length;
  const subCount = techniques.filter(
    (t) => t.isSubtechnique === true || t.attackId.includes('.')
  ).length;

  // ── Render ─────────────────────────────────────────────────────────────────
  return (
    <div className="space-y-3">

      {/* Header */}
      <div className="pb-1">
        <div className="flex items-center gap-2">
          <h2 className="text-lg font-semibold text-[var(--text-primary)]">{tactic.name}</h2>
          <ExternalLinksButton type="tactic" attackId={tactic.attackId} name={tactic.name} />
        </div>
        <div className="flex flex-wrap items-center gap-2 mt-1">
          <span className="font-mono text-xs text-[var(--accent-yellow)] bg-[var(--yellow-faint)] border border-[var(--yellow-dim)] px-2 py-0.5 rounded">
            {tactic.attackId}
          </span>
          <Badge label="tactic" variant="yellow" />
          {tactic.domain && (
            <Badge label={tactic.domain.replace('-attack', '')} variant="neutral" />
          )}
        </div>
      </div>

      {/* Description */}
      {tactic.description && (
        <div className="bg-[var(--surface-deep)] border border-[var(--border-color)] rounded-lg p-4">
          <p
            className="text-sm text-[var(--text-secondary)] leading-relaxed whitespace-pre-wrap"
            dangerouslySetInnerHTML={{
              __html: sanitize(sanitizeMarkdown(tactic.description)),
            }}
          />
        </div>
      )}

      {/* Techniques */}
      <MapCard label="Techniques" icon={IconGrid} count={totalCount} defaultOpen={true}>
        {totalCount === 0 ? (
          <p className="text-xs text-[var(--text-secondary)]">No techniques in this tactic.</p>
        ) : (
          <>
            {/* Summary line */}
            <div className="flex flex-wrap gap-2 pb-1">
              <Badge label={`${parentCount} parent technique${parentCount !== 1 ? 's' : ''}`} variant="teal" />
              {subCount > 0 && (
                <Badge label={`${subCount} sub-technique${subCount !== 1 ? 's' : ''}`} variant="blue" />
              )}
            </div>

            {/* Hierarchy */}
            <div className="space-y-2">
              {groups.map(({ parent, subs }) => (
                <div key={parent.attackId}>
                  {/* Parent technique row */}
                  <div className="flex flex-wrap items-center gap-1.5 py-1">
                    <EntityLink
                      type="technique"
                      attackId={parent.attackId}
                      name={parent.name} useMap />
                    {parent.platforms && parent.platforms.length > 0 &&
                      parent.platforms.map((platform) => (
                        <Badge key={platform} label={platform} variant="blue" />
                      ))
                    }
                  </div>

                  {/* Sub-technique rows */}
                  {subs.length > 0 && (
                    <div className="ml-4 pl-3 border-l border-[var(--border-color)] space-y-1 mt-0.5">
                      {subs.map((sub) => (
                        <div
                          key={sub.attackId}
                          className="flex flex-wrap items-center gap-1.5 py-0.5"
                        >
                          <EntityLink
                            type="technique"
                            attackId={sub.attackId}
                            name={sub.name} useMap />
                          {sub.platforms && sub.platforms.length > 0 &&
                            sub.platforms.map((platform) => (
                              <Badge key={platform} label={platform} variant="blue" />
                            ))
                          }
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}

              {/* Orphan sub-techniques (parent not in tactic list) */}
              {orphanSubs.length > 0 && (
                <div className="pt-1">
                  <MapRow prefix="Other subs">
                    <div className="flex flex-col gap-1 w-full">
                      {orphanSubs.map((sub) => (
                        <div
                          key={sub.attackId}
                          className="flex flex-wrap items-center gap-1.5"
                        >
                          <EntityLink
                            type="technique"
                            attackId={sub.attackId}
                            name={sub.name} useMap />
                          {sub.platforms && sub.platforms.length > 0 &&
                            sub.platforms.map((platform) => (
                              <Badge key={platform} label={platform} variant="blue" />
                            ))
                          }
                        </div>
                      ))}
                    </div>
                  </MapRow>
                </div>
              )}
            </div>
          </>
        )}
      </MapCard>

      {/* Reference */}
      {tactic.url && (
        <div className="px-1 pt-1">
          <p className="text-xs text-[var(--text-secondary)] font-semibold uppercase tracking-wider mb-1">
            Reference
          </p>
          <a
            href={tactic.url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 text-xs text-[var(--accent-teal)] hover:underline"
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
            MITRE ATT&amp;CK — {tactic.name}
          </a>
        </div>
      )}

    </div>
  );
}
