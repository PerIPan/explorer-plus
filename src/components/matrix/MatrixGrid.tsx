import { useMemo } from 'react';
import Link from 'next/link';
import type { MatrixData } from '../../lib/types';
import { MatrixCell } from './MatrixCell';
import type { CellOverlay } from './MatrixCell';
import { MatrixLegend } from './MatrixLegend';
import { getParentId } from '../../lib/getParentId';

export interface ActorOverlay {
  /** CSS color values for each actor slot */
  colors: string[];
  /** parentAttackId → set of actor slot indices (0, 1, 2) */
  lookup: Map<string, Set<number>>;
}

interface MatrixGridProps {
  data: MatrixData;
  /** Live filter text — dims non-matching cells, highlights matches */
  filterText?: string;
  /** Actor comparison overlay */
  actorOverlay?: ActorOverlay;
  /** Set of technique IDs to highlight (dims everything else) */
  highlightIds?: Set<string>;
}

/**
 * Full ATT&CK matrix — tactics as columns, techniques as cells.
 * groupUsageCount uses subTechniques.length as a proxy for cell "richness".
 */
export function MatrixGrid({ data, filterText = '', actorOverlay, highlightIds }: MatrixGridProps) {
  const normalizedFilter = filterText.trim().toLowerCase();
  const hasHighlight = highlightIds && highlightIds.size > 0;

  /** Pre-compute overlay per cell */
  const overlayMap = useMemo(() => {
    if (!actorOverlay) return null;
    const map = new Map<string, CellOverlay>();
    data.forEach((col) =>
      col.techniques.forEach((tech) => {
        const actors = actorOverlay.lookup.get(tech.attackId);
        if (!actors || actors.size === 0) {
          map.set(tech.attackId, { color: null, mode: 'hidden' });
        } else if (actors.size === 1) {
          const slotIdx = actors.values().next().value!;
          map.set(tech.attackId, { color: actorOverlay.colors[slotIdx], mode: 'single' });
        } else {
          map.set(tech.attackId, { color: null, mode: 'shared' });
        }
      })
    );
    return map;
  }, [data, actorOverlay]);

  /** Compute max sub-technique count for color scaling */
  const maxUsage = useMemo(() => {
    let max = 0;
    data.forEach((col) =>
      col.techniques.forEach((t) => {
        if (t.subTechniques.length > max) max = t.subTechniques.length;
      })
    );
    return max || 1;
  }, [data]);

  return (
    <div className="space-y-3">
      <MatrixLegend />

      {/* max-h container enables sticky tactic headers during vertical scroll */}
      <div className="max-h-[70vh] overflow-auto">
        <div className="overflow-x-auto">
          <div
            className="inline-flex gap-1 min-w-max pb-2"
            role="grid"
            aria-label="ATT&CK Matrix"
          >
            {data.map((col) => {
              // Hide entire column when all techniques are filtered out
              if (overlayMap || normalizedFilter || hasHighlight) {
                const hasVisible = col.techniques.some((tech) => {
                  const co = overlayMap?.get(tech.attackId);
                  if (co?.mode === 'hidden') return false;
                  if (hasHighlight) return highlightIds!.has(tech.attackId) || highlightIds!.has(getParentId(tech.attackId));
                  if (normalizedFilter) {
                    return tech.name.toLowerCase().includes(normalizedFilter) || tech.attackId.toLowerCase().includes(normalizedFilter);
                  }
                  return true;
                });
                if (!hasVisible) return null;
              }
              return (
              <div
                key={col.tactic.attackId}
                className="w-[140px] flex-shrink-0"
                role="group"
                aria-label={col.tactic.name}
              >
                {/* Tactic header — sticky within scrollable container */}
                <Link
                  href={`/relationships?entity=${col.tactic.attackId}&tab=tactic-map`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="
                    block bg-[var(--surface-deep)] border border-[var(--border-color)] rounded-t px-2 py-2 mb-1
                    text-center text-[11px] font-semibold text-[var(--accent-yellow)] uppercase tracking-wide
                    sticky top-0 z-10 hover:border-[var(--yellow-dim)] hover:bg-[var(--yellow-faint)] transition-colors
                  "
                >
                  {col.tactic.domain && (
                    <div className={`text-[8px] font-medium mb-0.5 uppercase tracking-widest ${
                      col.tactic.domain === 'enterprise-attack' ? 'text-[var(--text-secondary)]' : 'text-[var(--accent-orange)]'
                    }`}>
                      {col.tactic.domain.replace('-attack', '').replace('enterprise', 'ent')}
                    </div>
                  )}
                  <div>{col.tactic.name}</div>
                  <div className="text-[9px] text-[var(--text-secondary)] font-normal font-mono mt-0.5">
                    {col.tactic.attackId}
                  </div>
                </Link>

                {/* Technique cells */}
                <div className="flex flex-col gap-0.5">
                  {(() => {
                    const visibleCells = col.techniques.filter((tech) => {
                      const co = overlayMap?.get(tech.attackId);
                      if (co?.mode === 'hidden') return false;
                      if (hasHighlight && !highlightIds!.has(tech.attackId) && !highlightIds!.has(getParentId(tech.attackId))) return false;
                      if (normalizedFilter) {
                        const isMatch = tech.name.toLowerCase().includes(normalizedFilter) || tech.attackId.toLowerCase().includes(normalizedFilter);
                        if (!isMatch) return false;
                      }
                      return true;
                    });

                    if (visibleCells.length === 0 && (overlayMap || normalizedFilter || hasHighlight)) {
                      return null;
                    }

                    return visibleCells.map((tech) => {
                      const cellOverlay = overlayMap?.get(tech.attackId);
                      const isMatch = normalizedFilter && (tech.name.toLowerCase().includes(normalizedFilter) || tech.attackId.toLowerCase().includes(normalizedFilter));
                      return (
                        <div
                          key={tech.attackId}
                          className={[
                            'transition-opacity duration-150',
                            isMatch ? 'ring-1 ring-[var(--accent-teal)] rounded' : '',
                          ].join(' ')}
                        >
                          <MatrixCell
                            technique={tech}
                            groupUsageCount={tech.subTechniques.length}
                            maxUsage={maxUsage}
                            overlay={cellOverlay}
                          />
                        </div>
                      );
                    });
                  })()}
                </div>
              </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
