import { test } from 'node:test';
import assert from 'node:assert/strict';
import { diffSnapshots, summarizeDiff } from './attack-diff.mjs';

/** Minimal snapshot with just the coverage field the class-D rule reads. */
function snap(linkedGroups, liveGroups) {
  return {
    counts: {}, ids: {}, relationCounts: { group_sectors: 396 },
    orphanSubtechniques: 0,
    sectorCoverage: { linkedGroups, liveGroups, ratio: linkedGroups / liveGroups },
  };
}

const failuresOf = (pre, post) =>
  diffSnapshots(pre, post).failures.filter((f) => f.kind === 'sector_coverage_dropped');

test('coverage rule fires on new groups arriving WITHOUT sector links', () => {
  // The spec's named failure mode: 15 new groups, none linked. group_sectors
  // stays at 396 rows, so no row-count rule can see it.
  const pre = snap(149, 180);
  const post = snap(149, 195);
  assert.equal(post.relationCounts.group_sectors, pre.relationCounts.group_sectors);
  const { passed, failures } = diffSnapshots(pre, post);
  assert.equal(passed, false, 'a 6.4-point coverage drop must fail the ingest');
  const f = failures.find((x) => x.kind === 'sector_coverage_dropped');
  assert.ok(f, 'expected a sector_coverage_dropped failure');
  assert.equal(f.postLive, 195);
  assert.match(f.remedy, /extract_sectors/);
});

test('a row-count-only diff passes the same snapshots — coverage is the only rule that catches it', () => {
  const pre = { counts: {}, ids: {}, relationCounts: { group_sectors: 396 }, orphanSubtechniques: 0 };
  const post = { counts: {}, ids: {}, relationCounts: { group_sectors: 396 }, orphanSubtechniques: 0 };
  assert.equal(diffSnapshots(pre, post).passed, true);
});

test('a routine release adding 3 unlinked groups is not flagged', () => {
  // 149/183 = 81.4%, a 1.4-point drop. Under the 3-point tolerance on purpose:
  // the rule must not cry wolf on every ATT&CK version bump.
  assert.equal(failuresOf(snap(149, 180), snap(149, 183)).length, 0);
});

test('coverage IMPROVING is never a failure', () => {
  assert.equal(failuresOf(snap(149, 180), snap(170, 180)).length, 0);
});

test('revoking groups does not read as decay — both sides are live-scoped', () => {
  // 10 groups revoked, 8 of them previously linked: 141/170 = 82.9%, flat.
  assert.equal(failuresOf(snap(149, 180), snap(141, 170)).length, 0);
});

test('a pre snapshot predating sectorCoverage is skipped, not read as a drop to zero', () => {
  const pre = { counts: {}, ids: {}, relationCounts: {}, orphanSubtechniques: 0 };
  assert.equal(failuresOf(pre, snap(149, 180)).length, 0);
});

test('summarizeDiff carries the coverage pair for forensics', () => {
  const s = summarizeDiff(snap(149, 180), snap(149, 195));
  assert.equal(s.sectorCoverage.pre.liveGroups, 180);
  assert.equal(s.sectorCoverage.post.liveGroups, 195);
});
