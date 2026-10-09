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
 * is fused to that feature's controller and telemetry. The header's API and
 * Data Model dialogs both use this one, and so does everything new.
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

  /**
   * `open && mounted`, not `open`.
   *
   * The portal cannot render until after the first client commit, so on the
   * render where `open` first becomes true this component returns null and the
   * dialog element does not exist yet. Handing `open` straight to the hook ran
   * its focus and `inert` effects against a null ref, and they never re-ran —
   * `open` had not changed — so a dialog MOUNTED in the open state (the endpoint
   * and tool modals, which are created on click) got no focus move and left the
   * background live, while one whose `open` prop merely flipped (the header
   * modal, always mounted) worked. Caught by driving both in a browser.
   */
  const { dialogProps } = useDialog({ open: open && mounted, onClose, returnFocusTo, labelledBy: titleId });

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
        {/*
          WRAPS, and the tab strip is NOT in the same box as the close button.
          Both matter on a phone.

          This was one row of two children: the text block (`min-w-0`) and a
          `shrink-0` group holding the tabs AND the close button. On a 360px
          screen the panel is ~336px wide and this header's four tabs plus the
          close button need more than the ~304px inside the padding — so a
          `shrink-0` sibling took the width it wanted and `min-w-0` let the text
          block collapse to a few pixels. The title truncated to nothing and the
          subtitle wrapped at one character per line: a column of single letters
          down the left of the dialog.

          `flex-wrap` alone would not fix it (the text block's `flex-1` basis is
          0, so it never forces a break) and would carry the close button down
          to the second row with the tabs. Hence the explicit order: the text
          block and the close button hold row one, and the tab strip is `w-full`
          so it cannot share that row, taking its own below. From `md` up the
          widths and the order revert and the header is the single row it was.
        */}
        <div className="flex flex-wrap items-start gap-3 border-b border-[var(--border-color)] px-4 py-3 md:px-6 md:py-4">
          <div className="order-1 min-w-0 flex-1">
            <h2
              id={titleId}
              className={`truncate text-sm font-semibold text-[var(--text-primary)] ${mono ? 'font-mono' : ''}`}
            >
              {title}
            </h2>
            {subtitle && <div className="mt-1 text-xs text-[var(--text-secondary)]">{subtitle}</div>}
          </div>
          {tabs && (
            <div className="order-3 flex w-full flex-wrap items-center gap-1 md:order-2 md:w-auto md:shrink-0">
              {tabs}
            </div>
          )}
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="order-2 shrink-0 rounded-md p-2 text-[var(--text-secondary)] transition-colors hover:bg-[var(--hover-overlay)] hover:text-[var(--text-primary)] md:order-3"
          >
            <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
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
