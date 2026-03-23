import { useMemo, useRef } from 'react';
import Fuse from 'fuse.js';

/**
 * Client-side fuzzy search filter using Fuse.js.
 * Wraps an array of items and returns filtered results based on query.
 * Stabilizes the items reference to prevent unnecessary Fuse index rebuilds.
 */
export function useFuseFilter<T>(
  items: T[],
  keys: string[],
  query: string,
  options?: { threshold?: number; limit?: number },
): T[] {
  // Stabilize items reference — avoid rebuilding Fuse on every render
  // when callers pass `data?.data ?? []` (new [] each render during loading)
  const itemsRef = useRef(items);
  if (items.length !== itemsRef.current.length || items !== itemsRef.current) {
    itemsRef.current = items;
  }
  const stableItems = itemsRef.current;

  const fuse = useMemo(() => {
    if (!stableItems.length) return null;
    return new Fuse(stableItems, {
      keys,
      threshold: options?.threshold ?? 0.35,
      distance: 120,
      minMatchCharLength: 2,
    });
  }, [stableItems, keys, options?.threshold]);

  return useMemo(() => {
    const trimmed = query.trim();
    if (!trimmed || trimmed.length < 2 || !fuse) return stableItems;
    const results = fuse.search(trimmed, { limit: options?.limit ?? 500 });
    return results.map((r) => r.item);
  }, [fuse, query, stableItems, options?.limit]);
}
