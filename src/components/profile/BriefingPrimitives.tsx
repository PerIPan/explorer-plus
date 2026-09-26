import type { ReactNode } from 'react';

/* ────────────────────────────────────────────────────────────────────────────
 * Shared briefing presentation
 *
 * The four pieces both briefings are built from. They were defined in
 * src/views/ThreatProfile.tsx until src/views/OtProfile.tsx needed exactly the
 * same card, the same notice tones and the same right-aligned labelled metric
 * cell — and a second copy of them would have drifted the first time either
 * page was restyled.
 *
 * Extracted to a module rather than exported from ThreatProfile because that
 * module IMPORTS the OT view (it is the domain router for /profile), so the OT
 * view importing back from it would be a cycle.
 *
 * Deliberately not `src/components/shared/`: these carry the briefing's
 * conventions — an em-dash for absent evidence, uppercase micro-labels that
 * ship with every row so a phone layout never has to drop a table header —
 * rather than being generic site furniture.
 * ──────────────────────────────────────────────────────────────────────────── */

export function Card({ children, className = '' }: { children: ReactNode; className?: string }) {
  return (
    <div
      className={`bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg ${className}`.trim()}
    >
      {children}
    </div>
  );
}

export function Notice({
  tone,
  title,
  children,
}: {
  tone: 'warn' | 'info';
  title: string;
  children: ReactNode;
}) {
  const styles =
    tone === 'warn'
      ? 'border-[var(--orange-dim)] bg-[var(--orange-faint)] text-[var(--accent-orange)]'
      : 'border-[var(--border-color)] bg-[var(--hover-overlay)] text-[var(--text-secondary)]';
  return (
    <div className={`rounded-lg border px-4 py-3 ${styles}`} role="note">
      <p className="text-xs font-semibold uppercase tracking-wider">{title}</p>
      <div className="mt-1 text-sm text-[var(--text-primary)]">{children}</div>
    </div>
  );
}

/**
 * One evidence cell. The label ships with every row rather than living in a
 * header the phone layout would have to drop — six labelled cells wrap
 * cleanly, a headerless six-column table does not.
 */
export function Metric({
  label,
  value,
  emphasis = false,
  title,
}: {
  label: string;
  value: string;
  emphasis?: boolean;
  title?: string;
}) {
  return (
    <div className="flex flex-col items-end min-w-[3.25rem]" title={title}>
      <dt
        className={`text-[9px] font-semibold uppercase tracking-wider ${
          emphasis ? 'text-[var(--accent-teal)]' : 'text-[var(--text-secondary)]'
        }`}
      >
        {label}
      </dt>
      <dd
        className={`text-sm tabular-nums leading-tight ${
          emphasis
            ? 'font-semibold text-[var(--accent-teal)]'
            : value === '—'
              ? 'text-[var(--text-secondary)] opacity-60'
              : 'text-[var(--text-primary)]'
        }`}
      >
        {value}
      </dd>
    </div>
  );
}

export function num(n: number): string {
  return n > 0 ? n.toLocaleString() : '—';
}

/** EPSS is a probability of exploitation in the next 30 days — a percentage
 *  reads more honestly than a raw 0.99999. */
