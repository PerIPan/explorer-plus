/**
 * The one copy of the REST-path → CLI-command rule.
 *
 * `scripts/gen-cli.mjs` uses it to generate the command table that ships in the
 * package, and `src/views/Cli.tsx` uses it to render the same commands on the
 * /cli page. Two derivations of this rule would drift, and the drift would be
 * invisible: the page would document commands the CLI does not have. One copy,
 * imported by both, and `npm run check:cli` fails if the generated table stops
 * matching the catalogue.
 *
 * `.mjs` in src/lib for the same reason as src/lib/app-slug.mjs — it has to be
 * importable from both a TypeScript web bundle and a plain Node script.
 *
 * A path segment is either a literal word, which becomes a subcommand, or a
 * `{placeholder}`, which becomes a positional argument. `{...rest}` marks a
 * catch-all. Nothing else is special; that is what makes `mitrex <words…>` a
 * faithful mirror of the URL and keeps the command list unguessable only in the
 * ways the API itself is.
 */

const PLACEHOLDER = /^\{(\.\.\.)?([^}]+)\}$/;

/**
 * @param {{ path: string }} entry
 * @returns {{ words: string[], positionals: Array<{ name: string, catchAll: boolean, index: number }> }}
 */
export function commandFor(entry) {
  const segs = entry.path.split('/').filter(Boolean);
  const words = [];
  const positionals = [];
  segs.forEach((seg, i) => {
    const m = PLACEHOLDER.exec(seg);
    if (m) positionals.push({ name: m[2], catchAll: Boolean(m[1]), index: i + 1 });
    else words.push(seg);
  });
  return { words, positionals };
}

/**
 * The invocation as a reader would type it: `<name> groups attackId`.
 *
 * The binary name is a PARAMETER, not a literal — it is not settled, and
 * callers pass CLI_COMMAND_NAME from src/lib/site.ts so a rename is one edit.
 * Positionals are shown by their NAME rather than in angle brackets, because
 * brackets read as shell redirection in a line someone is meant to copy.
 *
 * @param {{ path: string }} entry
 * @param {string} name
 */
export function invocationFor(entry, name) {
  const { words, positionals } = commandFor(entry);
  return [name, ...words, ...positionals.map((p) => p.name)].join(' ');
}
