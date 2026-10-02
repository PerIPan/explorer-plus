import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  resolveSector,
  shouldInjectStoredSector,
  ALL_SECTORS_PARAM,
  PROFILE_PATH,
} from '../../src/lib/sector-scope.mjs';

// resolveSector — which sector a page filters by.

test('sector scope: the URL wins over the cache', () => {
  assert.equal(resolveSector({ urlSector: 'energy', storedSector: 'financial' }), 'energy');
});

test('sector scope: the cache is used when the URL is silent', () => {
  assert.equal(resolveSector({ storedSector: 'financial' }), 'financial');
});

test('sector scope: nothing anywhere means all sectors', () => {
  assert.equal(resolveSector({}), null);
});

test('sector scope: an empty URL value falls back to the cache, as the DOM does', () => {
  // `searchParams.get('sector') || null` — an empty param reads as absent here,
  // which is exactly why `?sector=` cannot express "no sector scope".
  assert.equal(resolveSector({ urlSector: '', storedSector: 'financial' }), 'financial');
});

test('sector scope: allSectors beats the cache — the evidence-count regression', () => {
  // The bug: /profile?sector=financial stores 'financial', then every evidence
  // count links to /cti/cves, which inherited it and applied an unrelated
  // relation, so "29 CVEs" landed on a list of 17.
  assert.equal(resolveSector({ storedSector: 'financial', allSectors: true }), null);
});

test('sector scope: allSectors beats an explicit URL sector too', () => {
  assert.equal(
    resolveSector({ urlSector: 'energy', storedSector: 'financial', allSectors: true }),
    null,
  );
});

// shouldInjectStoredSector — whether the cache is written into the URL.

test('sector injection: a remembered sector is carried onto an ordinary page', () => {
  assert.equal(
    shouldInjectStoredSector({ storedSector: 'financial', pathname: '/cti/cves' }),
    true,
  );
});

test('sector injection: never onto the briefing itself', () => {
  assert.equal(
    shouldInjectStoredSector({ storedSector: 'financial', pathname: PROFILE_PATH }),
    false,
  );
});

test('sector injection: never when the link declares no sector scope', () => {
  assert.equal(
    shouldInjectStoredSector({
      storedSector: 'financial', pathname: '/cti/cves', allSectors: true,
    }),
    false,
  );
});

test('sector injection: never over a sector the URL already carries', () => {
  assert.equal(
    shouldInjectStoredSector({
      storedSector: 'financial', hasSectorParam: true, pathname: '/cti/cves',
    }),
    false,
  );
});

test('sector injection: nothing to inject when nothing is stored', () => {
  assert.equal(shouldInjectStoredSector({ pathname: '/cti/cves' }), false);
});

test('sector scope: the two halves agree on an allSectors link', () => {
  // The invariant the split broke: if the URL is not given a sector, the page
  // must not filter by one either.
  const link = { storedSector: 'financial', pathname: '/cti/cves', allSectors: true };
  assert.equal(shouldInjectStoredSector(link), false);
  assert.equal(resolveSector(link), null);
});

test('sector scope: the parameter name is the one the link builds', () => {
  assert.equal(ALL_SECTORS_PARAM, 'allSectors');
});
