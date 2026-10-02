/**
 * The property that makes `mitrex <words…>` a safe mirror of the REST paths.
 *
 * Pure and separate from the generator so it can be tested without running the
 * generator's file writes.
 */

/**
 * Parents that have BOTH a static and a dynamic child.
 *
 * The subcommand mirror is only unambiguous while this is empty. If
 * `/frameworks/scf` and `/frameworks/{id}` ever coexisted, `mitrex frameworks
 * scf` would have two readings and dispatch would silently pick one of them.
 * Empty for the catalogue as it stands; `gen-cli.mjs` refuses to generate if it
 * ever stops being.
 *
 * @param {Array<{ path: string }>} entries
 * @returns {string[]} one human-readable line per offending parent
 */
export function collisions(entries) {
  const children = {};
  for (const e of entries) {
    const segs = e.path.split('/').filter(Boolean);
    for (let i = 0; i < segs.length; i += 1) {
      const parent = `/${segs.slice(0, i).join('/')}`;
      (children[parent] ??= new Set()).add(segs[i]);
    }
  }
  const bad = [];
  for (const [parent, set] of Object.entries(children)) {
    const segs = [...set];
    const dynamic = segs.filter((x) => x.startsWith('{'));
    const statics = segs.filter((x) => !x.startsWith('{'));
    if (dynamic.length && statics.length) {
      bad.push(
        `${parent} has both dynamic (${dynamic.join(' ')}) and static (${statics.join(' ')}) children`,
      );
    }
  }
  return bad;
}
