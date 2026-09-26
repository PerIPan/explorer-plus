// scripts/lib/search-params.test.mjs — run with `npm test`, no DB required.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { nextSearchQuery, isOwnEcho } from '../../src/lib/search-params.mjs';

test('search: a value is written and other params are preserved', () => {
  assert.equal(nextSearchQuery('domain=ics-attack', 'q', 'plc'), 'domain=ics-attack&q=plc');
});

test('search: an empty value DELETES the key, never writes a blank one', () => {
  // A blank `q=` survives Back and sharing as a filter nobody set.
  assert.equal(nextSearchQuery('q=plc&domain=x', 'q', ''), 'domain=x');
  assert.equal(nextSearchQuery('q=plc', 'q', '   '), '');
});

test('search: the value is trimmed', () => {
  assert.equal(nextSearchQuery('', 'q', '  plc  '), 'q=plc');
});

test('search: paging resets to 1 when it was set, and is not invented when it was not', () => {
  // Holding page 7 while narrowing to three rows shows an empty table that
  // reads as "no matches".
  assert.equal(nextSearchQuery('page=7', 'q', 'plc'), 'page=1&q=plc');
  assert.equal(nextSearchQuery('', 'q', 'plc'), 'q=plc');
});

test('search: echo detection ignores our own write, adopts an outside change', () => {
  assert.equal(isOwnEcho('123', '123'), true, "our own write must not be pushed back into the input");
  assert.equal(isOwnEcho('123', '1234'), false, 'a different value is an outside change');
  assert.equal(isOwnEcho(null, '123'), false, 'with nothing pending, any value is external (Back/link)');
  assert.equal(isOwnEcho(null, ''), false);
});

test('search: an empty pending write is still our own echo', () => {
  // Clearing the box writes '', and the echo of that must not re-trigger a sync.
  assert.equal(isOwnEcho('', ''), true);
});
