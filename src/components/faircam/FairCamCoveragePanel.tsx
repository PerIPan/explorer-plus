'use client';

import { Suspense, lazy, useState } from 'react';

/**
 * Collapsible FAIR-CAM coverage panel for a scenario — a threat profile's
 * ranked techniques, or a group's techniques. The shell is tiny; the body (and
 * the coverage request) loads only when a visitor opens it.
 */
const Body = lazy(() => import('./FairCamCoverageBody').then((m) => ({ default: m.FairCamCoverageBody })));

export function FairCamCoveragePanel({ techniqueIds, scopeLabel }: { techniqueIds: string[]; scopeLabel: string }) {
  const [open, setOpen] = useState(false);
  if (techniqueIds.length === 0) return null;
  return (
    <section className="rounded-lg border border-[var(--border-color)] overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="w-full flex items-center justify-between gap-3 px-4 py-3 bg-[var(--surface-card)] hover:bg-[var(--surface-base)] transition-colors text-left"
      >
        <span className="min-w-0">
          <span className="text-sm font-semibold text-[var(--text-primary)]">FAIR-CAM coverage</span>
          <span className="ml-2 text-xs text-[var(--text-secondary)]">
            candidate controls for {scopeLabel} ({techniqueIds.length} techniques), by FAIR-CAM function
          </span>
        </span>
        <svg className={`w-4 h-4 shrink-0 text-[var(--text-secondary)] transition-transform ${open ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {open && (
        <div className="px-4 py-3 bg-[var(--surface-alt)]">
          <Suspense fallback={<p className="text-xs italic text-[var(--text-secondary)]">Loading FAIR-CAM coverage…</p>}>
            <Body techniqueIds={techniqueIds} />
          </Suspense>
        </div>
      )}
    </section>
  );
}
