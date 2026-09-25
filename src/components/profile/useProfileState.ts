'use client';
import { useCallback, useEffect, useReducer, useState } from 'react';
import { useRouter } from 'next/navigation';
import { peekReducer } from '../../lib/profile-peek.mjs';
import { buildProfileUrl } from '../../lib/profile-url.mjs';
import { useDomain } from '../../contexts/DomainContext';
import { useSector } from '../../contexts/SectorContext';

/**
 * Sourced directly from profile-peek.mjs's own JSDoc `@typedef`s rather than
 * hand-duplicated here — a shape change to the reducer's state/event surfaces
 * as a typecheck failure at this import instead of silently drifting.
 */
export type PeekState = import('../../lib/profile-peek.mjs').PeekState;
export type PeekEvent = import('../../lib/profile-peek.mjs').PeekEvent;

/**
 * What one Apply carries. Sourced from the URL builder's own typedef for the
 * same reason as above — the two cannot drift without a typecheck failure.
 *
 * `sector` and `domain` are named because they are not merely URL payload:
 * each is mirrored into its context's cache and sessionStorage below.
 * Everything else the variant answers goes in `params`, keyed by param name,
 * so the OT variant adding `assets` and `purdue_levels` needs no change here.
 */
export type ApplyProfileInput = import('../../lib/profile-url.mjs').ProfileUrlInput;

/**
 * Dismissal flag. Not 'mx-theme' — a different key entirely, but the same
 * lesson: the old ThemeContext wrote its key on every mount regardless of
 * whether anyone touched anything, so a default silently became a sticky
 * "preference" nobody chose (see src/contexts/ThemeContext.tsx:11-17). This
 * key must only ever be written from `markProfileSeen`, which is called
 * exclusively by `applyProfile` and `dismiss` below — never from a mount
 * effect. Reading it is safe on mount; writing it is not.
 */
const STORAGE_KEY = 'mx-profile';

/** Free-form multi-select answers, keyed by question id (e.g. 'platforms',
 * 'roles', 'frameworks', 'assets', 'purdue_levels'). Sector is intentionally
 * NOT here — it is single-select (SectorContext.tsx:7 is `string | null`) and
 * flows through `applyProfile`'s own `sector` param, not through this bag. */
export type ProfileAnswers = Record<string, string[]>;

const EMPTY_ANSWERS: ProfileAnswers = {};

/**
 * Module scope, deliberately: the unsolicited peek must arm at most once per
 * PAGE LOAD, not once per mount.
 *
 * The provider that owns this hook is mounted only while the homepage shows
 * its diamonds, so selecting an entity unmounts it and clearing the selection
 * mounts it again. Without this flag every landing -> select -> clear round
 * trip re-arms the peek and writes another `auto_close` row — and because
 * `auto_close` deliberately never sets the dismissal flag (see below), there
 * is nothing to stop it repeating. That inflates the one metric this feature
 * is judged on; the mirror case (a provider unmounted mid-peek, whose
 * `auto_close` is never written at all) deflates it. Arming once per load is
 * the only reading of "unsolicited first-visit peek" that both of those agree
 * with.
 *
 * NOT storage: this must reset on a real page load, and adding a storage
 * access here would also have to be guarded for blocked site data. A module
 * variable resets exactly when the JS context does, which is the semantics we
 * want, and it survives client-side navigation within the app — which is
 * correct, since that is not a new page load either.
 */
let peekArmedThisPageLoad = false;

function readDismissed(): boolean {
  try {
    return Boolean(localStorage.getItem(STORAGE_KEY));
  } catch {
    // Private mode / storage disabled — treat as a first-time visitor. The
    // peek/panel must still work with no persistence at all.
    return false;
  }
}

function markProfileSeen(): void {
  try {
    localStorage.setItem(STORAGE_KEY, '1');
  } catch {
    // Storage disabled — nothing persists, but the panel still functions
    // for the rest of this session.
  }
}

export interface UseProfileStateResult {
  /** Draft answers for the non-sector, multi-select questions. */
  answers: ProfileAnswers;
  /** Replace one question's answer. */
  setAnswer: (key: string, value: string[]) => void;
  /**
   * One action, one push: exactly one `router.push`, to `/profile`. Never
   * calls `setSector`
   * and `setDomain` from their contexts, which would each rebuild params
   * from a render-time closure and race (see app/providers.tsx:10-45,
   * `UrlSyncEffect`, and SectorContext.tsx:49-68 / DomainContext.tsx:68-84).
   * The OT path calling this with sector+domain='ics-attack' together is the
   * exact case that race would break.
   *
   * Still calls `syncStoredSector`/`syncStoredDomain` (the state-only, no-router
   * counterparts to those setters) so each context's own cached fallback value
   * — `sector`/`domain` fall back to it whenever the URL has no param — stays
   * coherent with what this just wrote to the URL and sessionStorage. Skipping
   * that call is what previously let a cleared param resurface: the URL and
   * sessionStorage were right, but the context's in-memory cache still held
   * the old value and `useSector()`/`useDomain()` silently read the cache.
   */
  applyProfile: (next: ApplyProfileInput) => void;
  /** True once the visitor has ever applied or explicitly closed the panel
   * (read from `localStorage['mx-profile']` on mount). Gates the unsolicited
   * first-visit peek — it never re-arms for a visitor who has already acted. */
  dismissed: boolean;
  /** Explicit close (the "X" / Escape / outside-click path). Reports 'dismiss'
   * — distinct from an expired peek's 'auto_close' (see peekReducer). */
  dismiss: () => void;
  /** The peek/panel open-state machine. `dispatch` is exposed directly so a
   * consumer can fire 'CLICK_OPEN' (diamond click) and 'INTERACT' (any
   * pointerenter/focusin/keydown/scroll inside the panel) without this hook
   * needing to know about those DOM events. */
  peek: PeekState & { dispatch: (event: PeekEvent) => void };
}

const INITIAL_PEEK: PeekState = { open: false, timer: null, report: null };

/**
 * State layer for the Threat Profile panel: draft answers, the single-push
 * URL sync for sector+domain, the dismissal flag, and the peek timer state
 * machine (see src/lib/profile-peek.mjs for the pure reducer and its tests).
 *
 * This hook owns state and URL sync only — it does not call the telemetry
 * endpoint (app/api/v1/profile/submit) itself. It has no `variant` (the
 * question-set is a UI concern of whoever mounts the panel), and the submit
 * payload needs fields (e.g. `sectors` wrapping the single selected sector)
 * that are assembled by the caller, not owned here.
 */
export function useProfileState(): UseProfileStateResult {
  const router = useRouter();
  const { syncStoredSector } = useSector();
  const { syncStoredDomain } = useDomain();

  const [answers, setAnswers] = useState<ProfileAnswers>(EMPTY_ANSWERS);
  const [dismissed, setDismissed] = useState(false);
  const [peekState, dispatch] = useReducer<PeekState, [PeekEvent]>(peekReducer, INITIAL_PEEK);

  // Mount-only: READ the dismissal flag, never write it here. A first-time
  // visitor (no stored flag) gets the unsolicited peek armed exactly once;
  // a returning visitor who already applied/closed gets neither the peek
  // nor a write on this pass.
  useEffect(() => {
    const seen = readDismissed();
    setDismissed(seen);
    if (!seen && !peekArmedThisPageLoad) {
      peekArmedThisPageLoad = true;
      dispatch({ type: 'PEEK' });
    }
    // Intentionally mount-only — re-running this on every render would risk
    // re-arming the peek, which is the one thing that must never happen.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Mirror peekState.timer with a real timer. INTERACT/CLOSE/APPLY/EXPIRE all
  // set timer back to null; since 'PEEK' is dispatched at most once (the
  // mount effect above), once timer goes null here it can never be re-armed
  // — the cancellation this effect performs on cleanup is therefore
  // permanent, not merely "until the next render".
  useEffect(() => {
    if (peekState.timer == null) return undefined;
    const id = setTimeout(() => dispatch({ type: 'EXPIRE' }), peekState.timer);
    return () => clearTimeout(id);
  }, [peekState.timer]);

  // Persist the dismissal flag on a real interaction only — apply or an
  // explicit close. An auto_close must NOT write it: nobody reacted to the
  // unsolicited peek, so it should still peek again on the next cold visit
  // rather than being silently marked "seen".
  useEffect(() => {
    if (peekState.report === 'apply' || peekState.report === 'dismiss') {
      markProfileSeen();
      setDismissed(true);
    }
  }, [peekState.report]);

  const setAnswer = useCallback((key: string, value: string[]) => {
    setAnswers((prev) => ({ ...prev, [key]: value }));
  }, []);

  const applyProfile = useCallback(
    (next: ApplyProfileInput) => {
      // syncStoredSector/syncStoredDomain do the sessionStorage write (their
      // own try/catch — see SectorContext.tsx/DomainContext.tsx) AND update
      // each context's cached fallback value, with no router call of their
      // own. That's what keeps `useSector().sector`/`useDomain().domain`
      // coherent with the URL this function is about to write, instead of
      // falling through to a stale cache once the URL/sessionStorage are
      // updated but the context's own React state isn't (the bug fixed in
      // this file's fix round 1 — see PR history for the concrete repro).
      //
      // Calling these instead of `setSector`/`setDomain` themselves is what
      // keeps this a single push: each setter also calls its own
      // router.push from a render-time closure, which is exactly the race
      // app/providers.tsx:13-19 documents.
      syncStoredSector(next.sector);
      syncStoredDomain(next.domain);

      // `push`, not `replace`, and to `/profile` rather than the current
      // pathname: landing on a briefing is a real navigation, and Back must
      // return the visitor to the homepage they came from. This is still one
      // action, one push — the ruling that phrase comes from exists to stop
      // two context setters racing two navigations out of stale closures, and
      // it is satisfied by there being exactly ONE router call here.
      //
      // The query is built fresh rather than from the current `searchParams`:
      // `/profile` reads only sector/platforms/sort/domain, so carrying the
      // homepage's `entity`/`tab` across would be noise on a different route.
      router.push(buildProfileUrl(next));

      dispatch({ type: 'APPLY' });
    },
    [router, syncStoredSector, syncStoredDomain],
  );

  const dismiss = useCallback(() => {
    dispatch({ type: 'CLOSE' });
  }, []);

  return {
    answers,
    setAnswer,
    applyProfile,
    dismissed,
    dismiss,
    peek: { ...peekState, dispatch },
  };
}
