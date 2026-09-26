'use client';

import { useCallback, useEffect, useRef } from 'react';
import { usePathname } from 'next/navigation';
import type { KeyboardEvent as ReactKeyboardEvent, RefObject } from 'react';

/**
 * A headless modal dialog: focus moves in, Tab is trapped, the background is
 * marked `inert`, Escape closes, and focus returns to whatever opened it.
 *
 * Extracted rather than reused from `ProfilePanel`. That panel's trap is fused to
 * `useController`, `panelProps`, `data-profile-trigger` hit-testing, `dismiss`
 * telemetry and an anchored flip — none of which a documentation modal wants,
 * and it took three review rounds to get right, so it is not being refactored
 * here. The BEHAVIOUR below is deliberately the same as that panel's, including
 * the two subtleties that are easy to get wrong:
 *
 *  - `inert` is applied to every SIBLING along the dialog's ancestor chain, not
 *    to a single container. That is how you inert "everything except this
 *    subtree": the dialog's own ancestors stay live, so the dialog is
 *    unaffected, while a screen reader's virtual cursor, pointer hit-testing and
 *    browser find all stop at the boundary. Without it `aria-modal="true"` is a
 *    claim rather than a fact.
 *  - the inert effect is declared BEFORE the focus-return effect, because React
 *    runs a component's cleanups in hook-declaration order and the element focus
 *    is handed back to is usually one of the siblings marked here. `inert` has
 *    to come off first or the `focus()` is refused and focus lands on `<body>`.
 *
 * The AppShell help and APIs modals had none of this — no `role`, no trap, no
 * Escape. The APIs one gets it as of this change.
 */

const FOCUSABLE_SELECTOR = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',');

/**
 * Scroll-lock depth, module-level so two dialogs open at once (a tool modal over
 * the header modal) cannot have the inner one's cleanup unlock the page while
 * the outer is still up. Only the transition 0->1 writes the body style, and
 * only 1->0 restores exactly what was there before.
 */
let scrollLocks = 0;
let savedBodyStyle: { overflow: string; paddingRight: string } | null = null;

function hasLayoutBox(el: unknown): el is HTMLElement {
  return el instanceof HTMLElement && el.isConnected && el.getClientRects().length > 0;
}

function focusableWithin(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter(hasLayoutBox);
}

export interface UseDialogOptions {
  /** Mirrors whether the dialog is rendered. Effects no-op while false. */
  open: boolean;
  onClose: () => void;
  /**
   * Where focus goes on close — normally the button that opened the dialog.
   * A ref rather than an element so a re-render cannot stale it.
   */
  returnFocusTo?: RefObject<HTMLElement | null>;
  /** id of the element holding the dialog's accessible name. */
  labelledBy?: string;
}

export interface DialogProps {
  ref: RefObject<HTMLDivElement | null>;
  role: 'dialog';
  'aria-modal': true;
  'aria-labelledby'?: string;
  tabIndex: -1;
  onKeyDown: (event: ReactKeyboardEvent<HTMLDivElement>) => void;
}

export function useDialog({ open, onClose, returnFocusTo, labelledBy }: UseDialogOptions): {
  dialogRef: RefObject<HTMLDivElement | null>;
  dialogProps: DialogProps;
} {
  const dialogRef = useRef<HTMLDivElement | null>(null);
  // Read through a ref so the effects below do not re-run — and re-mark `inert`
  // — every time a parent hands down a fresh closure.
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  /* Focus moves in. */
  useEffect(() => {
    if (!open) return;
    dialogRef.current?.focus();
  }, [open]);

  /* Background inert. Declared before the focus-return effect — see the note above. */
  useEffect(() => {
    if (!open) return undefined;
    const root = dialogRef.current;
    if (!root) return undefined;
    const marked: HTMLElement[] = [];
    let node: HTMLElement | null = root;
    while (node && node !== document.body) {
      const parent: HTMLElement | null = node.parentElement;
      if (!parent) break;
      for (const sibling of Array.from(parent.children)) {
        if (sibling === node || !(sibling instanceof HTMLElement)) continue;
        // The scrim is a sibling of the panel and is what an outside click lands
        // on. Leave it live — it is already aria-hidden.
        if (sibling.hasAttribute('data-dialog-scrim')) continue;
        // Already inert for someone else's reason — not ours to restore.
        if (sibling.hasAttribute('inert')) continue;
        sibling.setAttribute('inert', '');
        marked.push(sibling);
      }
      node = parent;
    }
    return () => {
      for (const el of marked) el.removeAttribute('inert');
    };
  }, [open]);

  /* Focus returns on close, or on unmount while open. */
  useEffect(() => {
    if (!open) return undefined;
    return () => {
      const target = returnFocusTo?.current;
      if (hasLayoutBox(target)) target.focus();
    };
  }, [open, returnFocusTo]);

  /**
   * Escape net for focus OUTSIDE the trap — left on `<body>`, or on the scrim.
   * When focus is inside, the React handler below owns the key instead: this
   * listener shares a node with React's own delegated one (Next's App Router
   * hydrates `document`), so `stopPropagation()` from a nested widget that
   * swallowed Escape would not suppress it. Checking containment is what keeps a
   * nested listbox's Escape from also closing the whole dialog.
   */
  useEffect(() => {
    if (!open) return undefined;
    function onKeyDown(event: KeyboardEvent) {
      if (event.key !== 'Escape' || event.defaultPrevented) return;
      const root = dialogRef.current;
      if (root && root.contains(document.activeElement)) return;
      onCloseRef.current();
    }
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [open]);

  /**
   * Close on client-side navigation.
   *
   * AppShell sits in the root layout, so a dialog it owns keeps its `open` state
   * across a route change — and the API panel inside it links out to /open-apis
   * and /open-mcp. Clicking one navigated the page UNDERNEATH while the dialog
   * stayed on screen with the background still marked `inert`, so the link read
   * as broken. Modals that unmount with their page never had the problem; they
   * get the guarantee anyway.
   *
   * Compares against the path the dialog OPENED on rather than closing on every
   * pathname effect run, so opening a dialog does not immediately close it.
   */
  const pathname = usePathname();
  const openedOn = useRef<string | null>(null);
  useEffect(() => {
    if (!open) {
      openedOn.current = null;
      return;
    }
    if (openedOn.current === null) {
      openedOn.current = pathname;
      return;
    }
    if (openedOn.current !== pathname) onCloseRef.current();
  }, [open, pathname]);

  /* The page behind a modal must not scroll. Compensates for the scrollbar it
     removes, so locking does not shift the layout under the scrim. */
  useEffect(() => {
    if (!open) return undefined;
    if (scrollLocks === 0) {
      const gap = window.innerWidth - document.documentElement.clientWidth;
      savedBodyStyle = {
        overflow: document.body.style.overflow,
        paddingRight: document.body.style.paddingRight,
      };
      document.body.style.overflow = 'hidden';
      if (gap > 0) document.body.style.paddingRight = `${gap}px`;
    }
    scrollLocks += 1;
    return () => {
      scrollLocks -= 1;
      if (scrollLocks === 0 && savedBodyStyle) {
        document.body.style.overflow = savedBodyStyle.overflow;
        document.body.style.paddingRight = savedBodyStyle.paddingRight;
        savedBodyStyle = null;
      }
    };
  }, [open]);

  const handleKeyDown = useCallback(
    (event: ReactKeyboardEvent<HTMLDivElement>) => {
      if (event.key === 'Escape') {
        event.stopPropagation();
        onCloseRef.current();
        return;
      }
      if (event.key !== 'Tab') return;

      const root = dialogRef.current;
      if (!root) return;
      const items = focusableWithin(root);
      if (items.length === 0) {
        event.preventDefault();
        root.focus();
        return;
      }
      const first = items[0];
      const last = items[items.length - 1];
      const active = document.activeElement as HTMLElement | null;
      if (event.shiftKey) {
        if (active === first || active === root || !active || !root.contains(active)) {
          event.preventDefault();
          last.focus();
        }
      } else if (active === last) {
        event.preventDefault();
        first.focus();
      }
    },
    [],
  );

  return {
    dialogRef,
    dialogProps: {
      ref: dialogRef,
      role: 'dialog',
      'aria-modal': true,
      'aria-labelledby': labelledBy,
      tabIndex: -1,
      onKeyDown: handleKeyDown,
    },
  };
}
