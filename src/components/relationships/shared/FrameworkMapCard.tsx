'use client';

import { useState, type ReactNode } from 'react';

interface FrameworkMapCardProps {
  label: string;
  count?: number;
  /** CSS color value for the label text (e.g., '#059669' for OWASP, '#6366f1' for CSF) */
  labelColor?: string;
  defaultOpen?: boolean;
  children: ReactNode;
}

/**
 * Collapsible card section used by framework 360 map views (OWASP, CSF, ...).
 * Consistent styling: label + optional count + chevron, collapsible body.
 */
export function FrameworkMapCard({
  label,
  count,
  labelColor,
  defaultOpen = true,
  children,
}: FrameworkMapCardProps) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="border border-[var(--border-color)] rounded-lg overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center gap-3 px-4 py-3 bg-[var(--surface-card)] hover:bg-[var(--hover-subtle)] transition-colors text-left"
      >
        <span
          className="text-sm font-bold uppercase tracking-wider"
          style={labelColor ? { color: labelColor } : undefined}
        >
          {label}
        </span>
        {count !== undefined && (
          <span className="text-xs text-[var(--text-secondary)]">({count})</span>
        )}
        <svg
          className={`w-4 h-4 ml-auto text-[var(--text-secondary)] transition-transform duration-200 ${open ? 'rotate-180' : ''}`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {open && (
        <div className="px-4 py-3 space-y-3 bg-[var(--surface-alt)]">{children}</div>
      )}
    </div>
  );
}
