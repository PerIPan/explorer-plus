'use client';

import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { useCallback, useEffect, useRef, useState } from 'react';
import { isOwnEcho, nextSearchQuery } from '../lib/search-params.mjs';

/** Long enough to cover ordinary typing, short enough that the results do not
 *  feel detached from the box. Matches what the hand-rolled copies used. */
export const SEARCH_DEBOUNCE_MS = 300;

export interface DebouncedSearchParam {
  /** Bind straight to the input's `value` — it updates on every keystroke. */
  value: string;
  /** Bind to `onChange`; the URL follows once typing stops. */
  onChange: (next: string) => void;
  /** Commit immediately — for Enter, or a blur that should not wait. */
  flush: () => void;
}

/**
 * A search box whose value lives in the URL, without the URL fighting the box.
 *
 * Five list views each hand-rolled this with a `debounceRef` and a
 * `useEffect(() => setInput(urlValue), [urlValue])`, and that effect is a race:
 * it echoes our own navigation back into the input, so any character typed
 * while the navigation was in flight got overwritten. Five more views had no
 * debounce at all and navigated on every keystroke.
 *
 * Two things fix it, and both matter:
 *
 *   1. Adopt the URL value only when it changed from OUTSIDE. A value equal to
 *      what we just wrote is our own echo and is ignored, so in-flight typing
 *      survives.
 *   2. `router.replace`, not `push`. `useUpdateParams` pushes, which is right
 *      for a deliberate filter change but wrong here: debounced typing would
 *      pile up one history entry per pause, and Back would walk the visitor
 *      backwards through their own search a few characters at a time.
 *
 * The URL stays the source of truth, so deep links, sharing and Back still
 * work — only the WRITE is deferred.
 */
export function useDebouncedSearchParam(
  key: string,
  delay: number = SEARCH_DEBOUNCE_MS,
): DebouncedSearchParam {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const urlValue = searchParams.get(key) ?? '';

  const [value, setValue] = useState(urlValue);
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);
  /** The last value this hook wrote, awaiting its echo. */
  const pending = useRef<string | null>(null);
  /** Latest query string, so a timer that fires after an unrelated param
   *  changed still builds on the current URL rather than a stale closure. */
  const queryRef = useRef(searchParams.toString());
  queryRef.current = searchParams.toString();

  useEffect(() => {
    if (isOwnEcho(pending.current, urlValue)) {
      pending.current = null;
      return;
    }
    pending.current = null;
    setValue(urlValue);
  }, [urlValue]);

  useEffect(() => () => clearTimeout(timer.current), []);

  const commit = useCallback(
    (next: string) => {
      const trimmed = next.trim();
      if (trimmed === (new URLSearchParams(queryRef.current).get(key) ?? '')) return;
      pending.current = trimmed;
      const qs = nextSearchQuery(queryRef.current, key, next);
      router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
    },
    [key, pathname, router],
  );

  const onChange = useCallback(
    (next: string) => {
      setValue(next);
      clearTimeout(timer.current);
      timer.current = setTimeout(() => commit(next), delay);
    },
    [commit, delay],
  );

  const flush = useCallback(() => {
    clearTimeout(timer.current);
    commit(value);
  }, [commit, value]);

  return { value, onChange, flush };
}
