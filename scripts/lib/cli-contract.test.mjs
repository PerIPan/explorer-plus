/**
 * The two lists `scripts/gen-cli.mjs` validates the CLI against.
 *
 * They live in cli/lib/contract.mjs — a module with no imports — because the
 * generator both validates the CLI and WRITES two of its files, so importing
 * dispatch.mjs to read them made the generator depend on output it had not
 * produced yet.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TRANSFORM_NAMES, RESERVED_FLAGS } from '../../cli/lib/contract.mjs';
import { TRANSFORMS, optionsFor, resolve } from '../../cli/lib/dispatch.mjs';

test('every declared transform name is implemented, and vice versa', () => {
  /* The generated table carries a transform NAME and dispatch resolves it from
     a map at call time. An unknown name passed every check and every test, then
     threw `TRANSFORMS[cmd.transform] is not a function` the first time anyone
     ran that one command. */
  assert.deepEqual([...TRANSFORM_NAMES].sort(), Object.keys(TRANSFORMS).sort());
  for (const name of TRANSFORM_NAMES) assert.equal(typeof TRANSFORMS[name], 'function');
});

test('RESERVED_FLAGS is exactly what the CLI declares for itself', () => {
  // A catalogue param sharing one of these names would silently capture it.
  const own = optionsFor(resolve(['techniques']).cmd);
  for (const flag of RESERVED_FLAGS) {
    if (flag === 'query') continue; // only present on full-text commands
    assert.ok(own[flag], `${flag} is reserved but not declared`);
  }
  const fulltext = optionsFor(resolve(['groups']).cmd);
  assert.ok(fulltext.query, 'query is reserved but not declared on a full-text command');
});
