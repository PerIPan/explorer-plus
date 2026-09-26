'use client';

import { useEffect, useState } from 'react';
import { createPortal } from 'react-dom';
import type { ReactNode, RefObject } from 'react';
import { useDialog } from '../../hooks/useDialog';

let seq = 0;

/**
 * The modal chrome the API documentation surfaces share: scrim, centred panel,
 * a titled header with a close button, and the accessibility contract from
 * `useDialog` (role, aria-modal, focus move, Tab trap, inert background, Escape,
 * focus return).
 *
 * Portalled to `<body>` so the panel is never clipped by an ancestor's
 * `overflow` — the header modal opens from inside a `sticky` bar, and the
 * endpoint modal opens from inside a scrolling page.
 *
 * Not a third modal implementation: `ProfilePanel` keeps its own because its trap
 * is fused to that feature's controller and telemetry, and `RelationshipModel`
 * predates this. Everything new in this area uses this one.
 */
export function Dialog({
  open,
  onClose,
  title,
  subtitle,
  tabs,
  children,
  returnFocusTo,
  maxWidth = '840px',
  mono = false,
}: {
  open: boolean;
  onClose: () => void;
  /** Shown in the header and used as the dialog's accessible name. */
  title: string;
  subtitle?: ReactNode;
  /** Optional tab strip, rendered left of the close button. */
  tabs?: ReactNode;
  children: ReactNode;
  returnFocusTo?: RefObject<HTMLElement | null>;
  maxWidth?: string;
  /** Monospace title — for an endpoint path or a tool name, not a page title. */
  mono?: boolean;
}) {
  const [titleId] = useState(() => `dialog-title-${++seq}`);
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  const { dialogProps } = useDialog({ open, onClose, returnFocusTo, labelledBy: titleId });

  if (!open || !mounted) return null;

  return createPortal(
    <>
      <div
        data-dialog-scrim
        aria-hidden="true"
        onClick={onClose}
        className="fixed inset-0 z-[100] bg-black/70 backdrop-blur-sm"
      />
      <div
        {...dialogProps}
        className="fixed left-1/2 top-1/2 z-[101] flex max-h-[88vh] w-[calc(100%-1.5rem)] -translate-x-1/2 -translate-y-1/2 flex-col rounded-xl border border-[var(--border-color)] bg-[var(--surface-deep)] shadow-2xl focus:outline-none"
        style={{ maxWidth }}
      >
        <div className="flex items-start justify-between gap-3 border-b border-[var(--border-color)] px-4 py-3 md:px-6 md:py-4">
          <div className="min-w-0">
            <h2
              id={titleId}
              className={`truncate text-sm font-semibold text-[var(--text-primary)] ${mono ? 'font-mono' : ''}`}
            >
              {title}
            </h2>
            {subtitle && <div className="mt-1 text-xs text-[var(--text-secondary)]">{subtitle}</div>}
          </div>
          <div className="flex shrink-0 items-center gap-1">
            {tabs}
            <button
              type="button"
              onClick={onClose}
              aria-label="Close"
              className="rounded-md p-2 text-[var(--text-secondary)] transition-colors hover:bg-[var(--hover-overlay)] hover:text-[var(--text-primary)]"
            >
              <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto">{children}</div>
      </div>
    </>,
    document.body,
  );
}

/** The tab buttons the header modal and /open-mcp both use. */
export function DialogTab({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={`rounded-md px-3 py-1.5 text-xs font-semibold transition-colors ${
        active
          ? 'bg-[var(--teal-faint)] text-[var(--accent-teal)]'
          : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
      }`}
    >
      {children}
    </button>
  );
}
