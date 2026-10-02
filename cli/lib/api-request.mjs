/**
 * Composing a real request URL from an endpoint template and the values a
 * reader typed — the INPUT half of /open-apis' endpoint modal.
 *
 * Pure and `.mjs` for the same reason as the other modules in here: `npm test`
 * runs `node --test "scripts/**\/*.test.mjs"` and node cannot import a `.ts`
 * module, so anything worth testing without a browser lives outside the
 * component. The component is then only inputs and layout.
 */

/** `{id}` is one segment; `{...slug}` swallows the rest of the path. */
const PLACEHOLDER = /^\{(\.\.\.)?([^}]+)\}$/;

/**
 * The dynamic segments of a template path, in order.
 * @param {string} template e.g. `/applications/{...slug}`
 * @returns {Array<{ name: string, catchAll: boolean, index: number }>}
 */
export function pathVariables(template) {
  const out = [];
  template.split('/').forEach((seg, index) => {
    const m = PLACEHOLDER.exec(seg);
    if (m) out.push({ name: m[2], catchAll: Boolean(m[1]), index });
  });
  return out;
}

/**
 * Seed the form from the catalogue's worked example, so the modal opens on a
 * request that already returns 200 and the reader edits rather than composes.
 *
 * Positional: the example is the same template with real values substituted, so
 * segment i of one lines up with segment i of the other. A catch-all takes every
 * remaining segment, which is what made `/applications/microsoft/windows_10`
 * seed `{...slug}` rather than only `microsoft`.
 *
 * @param {string} template
 * @param {string} [example] the relative example path, query string included
 * @returns {{ path: Record<string,string>, query: Record<string,string> }}
 */
export function seedValues(template, example) {
  const path = {};
  const query = {};
  if (!example) return { path, query };

  const [rawPath, rawQuery = ''] = example.split('?');
  const exampleSegs = rawPath.split('/');
  for (const v of pathVariables(template)) {
    path[v.name] = v.catchAll
      ? exampleSegs.slice(v.index).join('/')
      : (exampleSegs[v.index] ?? '');
  }
  for (const [k, v] of new URLSearchParams(rawQuery)) query[k] = v;
  return { path, query };
}

/**
 * Build the relative path to call.
 *
 * Empty query values are DROPPED rather than sent as `?x=`: an empty string is
 * a value a route can reject, and "I left the box alone" should not become a
 * filter. A blank PATH variable is kept as an empty segment on purpose — the
 * resulting 404 is a true answer about the URL the reader built.
 *
 * @param {string} template
 * @param {Record<string,string>} pathValues
 * @param {Array<[string, string]>} queryPairs ordered, so the URL reads the way
 *   the form does rather than in object-key order
 * @returns {string}
 */
export function composePath(template, pathValues, queryPairs = []) {
  const path = template
    .split('/')
    .map((seg) => {
      const m = PLACEHOLDER.exec(seg);
      if (!m) return seg;
      const raw = pathValues[m[2]] ?? '';
      // A catch-all's slashes are structure, not content, so they survive;
      // everything else is encoded whole.
      return m[1]
        ? raw.split('/').map(encodeURIComponent).join('/')
        : encodeURIComponent(raw);
    })
    .join('/');

  const search = queryPairs
    .filter(([, v]) => v !== undefined && v !== null && String(v).trim() !== '')
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&');

  return search ? `${path}?${search}` : path;
}
