// Pure URL-parameter maths for the debounced search inputs. Kept out of the
// hook so the part that is easy to get wrong can be tested without a renderer —
// this repo has no jsdom and no testing-library.

/**
 * Apply one search value to an existing query string.
 *
 * An empty value DELETES the key rather than writing `key=`: a blank param is
 * indistinguishable from "searched for nothing" when the URL is shared, and it
 * survives Back as a filter the visitor never set.
 *
 * Paging resets to 1, because holding page 7 while narrowing the result set to
 * three rows shows an empty table that looks like "no matches".
 *
 * @param {string} current  the current query string, with or without '?'
 * @param {string} key      the param the search box owns
 * @param {string} value    the raw input value
 * @returns {string}        the new query string, without '?'
 */
export function nextSearchQuery(current, key, value) {
  const params = new URLSearchParams(current.startsWith('?') ? current.slice(1) : current);
  const trimmed = value.trim();
  if (trimmed) params.set(key, trimmed);
  else params.delete(key);
  if (params.has('page')) params.set('page', '1');
  return params.toString();
}

/**
 * True when an incoming URL value is this hook's OWN write coming back, rather
 * than a genuine outside change (Back/Forward, a link, a reset elsewhere).
 *
 * This is the whole bug. The old per-view code synced the URL into the input on
 * every change, so a character typed while a navigation was in flight was
 * overwritten by the value that navigation carried — type "123", pause, type
 * "4", and the input snapped back to "123".
 *
 * @param {string|null} pending  the last value written by this hook, or null
 * @param {string} incoming      the value now in the URL
 */
export function isOwnEcho(pending, incoming) {
  return pending !== null && pending === incoming;
}
