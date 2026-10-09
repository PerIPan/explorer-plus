// scripts/lib/feeds.test.mjs — run with `npm test` (Node strips the .ts types)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FEED_SOURCES, MANUAL_SOURCES, FEED_MAX_AGE_HOURS, isFeedLate } from '../../src/lib/feeds.ts';

test('every scheduled feed has a lateness window; manual ones do not', () => {
  for (const s of FEED_SOURCES) {
    if (MANUAL_SOURCES.has(s)) assert.equal(FEED_MAX_AGE_HOURS[s], undefined, s);
    else assert.ok(FEED_MAX_AGE_HOURS[s] > 0, `${s} has no window`);
  }
});

test('isFeedLate: only a success row older than its window', () => {
  const now = Date.parse('2026-10-09T18:00:00Z');
  const hoursAgo = (h) => new Date(now - h * 3_600_000).toISOString();
  assert.equal(isFeedLate('otx', 'success', hoursAgo(17), now), false);
  assert.equal(isFeedLate('otx', 'success', hoursAgo(19), now), true);
  assert.equal(isFeedLate('otx', 'error', hoursAgo(500), now), false);     // error speaks for itself
  assert.equal(isFeedLate('attack_update', 'success', hoursAgo(5000), now), false); // manual
  assert.equal(isFeedLate('scf', 'success', 'not a date', now), false);
  // The SCF failure mode: last success 2026-09-21, nothing since — late by mid-October.
  assert.equal(isFeedLate('scf', 'success', '2026-09-21T07:39:37Z', Date.parse('2026-10-27T00:00:00Z')), true);
});
