'use client';

import { useMemo } from 'react';
import { useFairCamCoverage } from '../../hooks/useApi';
import { scenarioSummary } from '../../lib/fair-cam-state.mjs';
import { EntityLink } from '../shared/EntityLink';
import { FairCamAttribution, useDomainSources } from './shared';

const SIDES = [
  { key: 'prevention', label: 'Prevention', hint: 'Avoidance, Deterrence or Resistance' },
  { key: 'visibility', label: 'Visibility', hint: 'evidence a detection could use' },
  { key: 'recognition', label: 'Recognition', hint: 'analytics, Sigma, D3FEND detect' },
  { key: 'response', label: 'Response', hint: 'Event Termination, Resilience, Loss Reduction' },
] as const;

const MAX_GAPS = 25;

/**
 * Gaps first, then the totals that put them in context. A "gap" is a side with
 * NO candidate where every source for that side is loaded for the technique's
 * domain; sides our data does not cover are counted separately and never
 * listed as gaps. Order follows the scenario's own ranking (the order the ids
 * arrive in).
 */
export function FairCamCoverageBody({ techniqueIds }: { techniqueIds: string[] }) {
  const { data, isLoading, error } = useFairCamCoverage(true);
  const sources = useDomainSources(data);

  const view = useMemo(() => {
    if (!data) return null;
    const byId = new Map(data.techniques.map((t) => [t.attackId, t]));
    const rows = techniqueIds.map((id) => byId.get(id)).filter((r): r is NonNullable<typeof r> => Boolean(r));
    const names = new Map(rows.map((r) => [r.attackId, r.name]));
    const s = scenarioSummary(rows, sources);
    return { ...s, names, missingFromSet: techniqueIds.length - rows.length };
  }, [data, sources, techniqueIds]);

  if (isLoading) return <p className="text-xs italic text-[var(--text-secondary)]">Loading FAIR-CAM coverage…</p>;
  if (error || !view) return <p className="text-xs text-[var(--accent-orange)]">FAIR-CAM coverage could not be loaded.</p>;

  return (
    <div className="space-y-3">
      <p className="text-[11px] text-[var(--text-secondary)] leading-relaxed">
        Whether public knowledge bases list at least one candidate control per side for these techniques — not
        what you have deployed, and not how well it works. Parent techniques include their sub-techniques.
      </p>

      <div>
        <div className="text-xs font-semibold uppercase tracking-wider text-[var(--text-primary)] mb-1.5">
          Gaps — {view.gaps.length} of {view.techniques} techniques
        </div>
        {view.gaps.length === 0 ? (
          <p className="text-xs text-[var(--text-secondary)]">No technique here lacks a candidate on a side the loaded sources cover.</p>
        ) : (
          <ul className="space-y-1 max-h-64 overflow-y-auto" tabIndex={0} aria-label="Techniques with a missing side">
            {view.gaps.slice(0, MAX_GAPS).map((g) => (
              <li key={g.attackId} className="flex flex-wrap items-center gap-2 text-xs">
                <EntityLink type="technique" attackId={g.attackId as string} name={view.names.get(g.attackId as string) ?? (g.attackId as string)} useMap />
                <span className="text-[var(--accent-orange)]">no {g.missing.join(', no ')} candidate</span>
              </li>
            ))}
            {view.gaps.length > MAX_GAPS && (
              <li className="text-[10px] text-[var(--text-secondary)]">+{view.gaps.length - MAX_GAPS} more, in ranking order</li>
            )}
          </ul>
        )}
      </div>

      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
        {SIDES.map((side) => {
          const c = view.summary[side.key];
          return (
            <div key={side.key} className="rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-3 py-2">
              <div className="text-xs font-semibold text-[var(--text-primary)]">{side.label}</div>
              <div className="text-[10px] text-[var(--text-secondary)] mb-1">{side.hint}</div>
              <div className="text-[11px] tabular-nums text-[var(--text-primary)]">
                {c.found} with candidates · <span className="text-[var(--accent-orange)]">{c['none-found']} none found</span>
                {c['not-covered'] > 0 && <span className="text-[var(--text-secondary)]"> · {c['not-covered']} not covered by loaded sources</span>}
              </div>
            </div>
          );
        })}
      </div>
      <p className="text-[10px] text-[var(--text-secondary)]">
        Monitoring (time between reviews) is always yours to measure; Deterrence and Loss Reduction are barely modelled
        by these sources and are not counted as gaps.{view.missingFromSet > 0 && ` ${view.missingFromSet} technique(s) not in the coverage set (revoked or deprecated).`}
      </p>
      <FairCamAttribution compact />
    </div>
  );
}
