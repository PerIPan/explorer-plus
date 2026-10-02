/**
 * The facts `scripts/gen-cli.mjs` has to know about the CLI's runtime.
 *
 * Its own module, with no imports, because the generator validates the CLI and
 * also WRITES two of the CLI's files — importing dispatch.mjs to read these
 * lists made the generator depend on a file it had not produced yet.
 */

/**
 * Positional transforms dispatch.mjs implements, by the name the generated
 * table may reference.
 *
 * The table carries a transform NAME and dispatch resolves it from a map at
 * call time, so a name nothing implements used to pass every check and every
 * test, then throw `TRANSFORMS[cmd.transform] is not a function` the first time
 * anyone ran that command. `scripts/lib/cli-contract.test.mjs` asserts this
 * list and dispatch's map stay in agreement.
 */
export const TRANSFORM_NAMES = ['appSlug'];

/**
 * Flags the CLI itself owns.
 *
 * A catalogue parameter sharing one of these names would silently capture it:
 * a param called `expand` would be both a renderer flag and a query param, and
 * one called `help` would make `--help` demand a value. None collide today, and
 * the generator refuses to build if one ever does.
 */
export const RESERVED_FLAGS = ['json', 'expand', 'timeout', 'base', 'no-color', 'help', 'query', 'table', 'url'];
