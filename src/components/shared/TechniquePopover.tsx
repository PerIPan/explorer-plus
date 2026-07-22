'use client';
import { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { useQuery } from '@tanstack/react-query';
import { apiFetch } from '../../lib/api';
import { Badge } from './Badge';
import { EntityLink } from './EntityLink';

/**
 * Clickable technique-count bubble that opens a portal dropdown listing the
 * report's linked ATT&CK techniques. Portal + fixed positioning so it renders
 * correctly anywhere (table cell, landing-page row, …). The button stops
 * propagation AND prevents default so it's safe inside a clickable/link row.
 */
export function TechniquePopover({ reportId, count }: { reportId: string; count: number }) {
  const [open, setOpen] = useState(false);
  const { data, isLoading } = useQuery({
    queryKey: ['report-techniques', reportId],
    queryFn: () => apiFetch<{ data: Array<{ attackId: string; name: string }> }>(`/feed/reports/${reportId}/techniques`),
    enabled: open,
    staleTime: 5 * 60 * 1000,
  });

  const btnRef = useRef<HTMLButtonElement>(null);
  const [, forceReposition] = useState(0);

  // While open: keep the fixed-position panel anchored to the button on
  // scroll/resize (rect is captured at render, so it would otherwise drift),
  // and close on Escape (the overlay's onKeyDown never fires — it isn't focused).
  useEffect(() => {
    if (!open) return;
    const reposition = () => forceReposition((n) => n + 1);
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false); };
    window.addEventListener('scroll', reposition, true); // capture: ancestor scroll too
    window.addEventListener('resize', reposition);
    document.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('scroll', reposition, true);
      window.removeEventListener('resize', reposition);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  const rect = open && btnRef.current ? btnRef.current.getBoundingClientRect() : null;

  return (
    <span>
      <button
        ref={btnRef}
        type="button"
        onClick={(e) => { e.preventDefault(); e.stopPropagation(); setOpen((prev) => !prev); }}
        aria-label={`Show ${count} linked techniques`}
        aria-expanded={open}
        className="cursor-pointer"
      >
        <Badge label={String(count)} variant="teal" />
      </button>
      {open && rect && createPortal(
        <>
          <div
            className="fixed inset-0 z-40"
            onClick={() => setOpen(false)}
            onKeyDown={(e) => { if (e.key === 'Escape') setOpen(false); }}
            role="button"
            aria-label="Close popover"
            tabIndex={-1}
          />
          <div
            className="fixed z-50 bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg shadow-2xl p-3 min-w-[240px] max-h-[300px] overflow-y-auto"
            style={{ top: rect.bottom + 4, left: Math.max(8, rect.right - 240) }}
          >
            <div className="text-[10px] text-[var(--text-secondary)] uppercase tracking-wider mb-2">
              Linked Techniques ({count})
            </div>
            {isLoading && (
              <div className="flex items-center gap-2 text-[var(--text-secondary)] text-xs py-2">
                <span className="inline-block w-3 h-3 border-2 border-[var(--teal-dim)] border-t-[var(--accent-teal)] rounded-full animate-spin" />
                Loading...
              </div>
            )}
            {data?.data && (
              <div className="flex flex-col gap-1">
                {data.data.map((t) => (
                  <EntityLink key={t.attackId} type="technique" attackId={t.attackId} name={t.name} useMap />
                ))}
              </div>
            )}
            {!isLoading && data?.data?.length === 0 && (
              <span className="text-xs text-[var(--text-secondary)]">No techniques found.</span>
            )}
          </div>
        </>,
        document.body,
      )}
    </span>
  );
}
