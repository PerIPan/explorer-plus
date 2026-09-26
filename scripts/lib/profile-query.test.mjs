// scripts/lib/profile-query.test.mjs — run with `npm test`, no DB required.
//
// The read side of the briefing's URL contract. The first test is the one
// that matters: an absent `?domain=` silently produced a cross-domain pool
// (205 enterprise + 12 ICS + 2 mobile for `energy`) under a heading naming
// one sector, and nothing in the codebase would have noticed. It notices now.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  resolveProfileDomain,
  parsePlatforms,
  parseCsvParam,
  buildProfileApiQuery,
  ALL_DOMAINS,
} from '../../src/lib/profile-query.mjs';

const ENTERPRISE = 'enterprise-attack';

test('profile query: an absent domain resolves to the default, never to no filter', () => {
  for (const absent of [null, undefined, '', '   ']) {
    const r = resolveProfileDomain(absent, ENTERPRISE);
    assert.equal(r.domain, ENTERPRISE, `${JSON.stringify(absent)} must not mean "every domain"`);
    assert.equal(r.allDomains, false);
  }
});

test('profile query: an explicit domain is passed through untouched', () => {
  for (const d of ['ics-attack', 'mobile-attack', 'atlas-attack', ENTERPRISE]) {
    assert.deepEqual(resolveProfileDomain(d, ENTERPRISE), { domain: d, allDomains: false });
  }
});

test('profile query: "all" is the ONLY way to get no domain filter, and it is flagged', () => {
  // The site-wide dropdown can write it; the API would 400 on it; coercing it
  // to the default would overrule a choice the visitor actually made.
  assert.deepEqual(resolveProfileDomain(ALL_DOMAINS, ENTERPRISE), {
    domain: null,
    allDomains: true,
  });
  assert.equal(resolveProfileDomain('  all  ', ENTERPRISE).allDomains, true, 'trimmed');
});

test('profile query: platforms split on commas, blanks dropped', () => {
  assert.deepEqual(parsePlatforms('Windows,Linux'), ['Windows', 'Linux']);
  assert.deepEqual(parsePlatforms(' Windows , Linux '), ['Windows', 'Linux']);
  assert.deepEqual(parsePlatforms('Field Controller/RTU/PLC/IED'), [
    'Field Controller/RTU/PLC/IED',
  ]);
  for (const empty of ['', ',,', '  ', null, undefined]) {
    assert.deepEqual(parsePlatforms(empty), [], `${JSON.stringify(empty)} is no constraint`);
  }
});

test('profile query: the API query always carries a domain unless all-domains', () => {
  const { domain } = resolveProfileDomain(null, ENTERPRISE);
  const q = new URLSearchParams(
    buildProfileApiQuery({ sector: 'energy', platforms: [], sort: 'lift', domain }),
  );
  assert.equal(q.get('domain'), ENTERPRISE, 'a bare /profile must still be domain-filtered');
  assert.equal(q.get('sector'), 'energy');
  assert.equal(q.get('sort'), 'lift');
  assert.equal(q.has('platforms'), false, 'no platforms means no param, not a blank one');

  const all = resolveProfileDomain(ALL_DOMAINS, ENTERPRISE);
  const r = new URLSearchParams(
    buildProfileApiQuery({ sector: 'energy', sort: 'kev', domain: all.domain }),
  );
  // An explicit all-domains request is now SENT as `domain=all`, not omitted.
  // The assembler defaults an absent domain to enterprise-attack, so omitting it
  // would silently convert "every domain" into "enterprise only" while the page
  // went on disclosing a mixed pool. `all` is a value the API accepts, and it
  // answers with meta.mixedDomain set.
  assert.equal(r.get('domain'), ALL_DOMAINS, 'all-domains must be stated, not implied');
});

test('profile query: an unresolved (undefined) domain is still omitted', () => {
  // Only the `null` that resolveProfileDomain returns for an explicit "all"
  // becomes `domain=all`. A caller that never resolved a domain omits the
  // parameter and picks up the assembler's enterprise-attack default.
  const q = new URLSearchParams(buildProfileApiQuery({ sector: 'energy', sort: 'kev' }));
  assert.equal(q.has('domain'), false);
});

test('profile query: carries nothing the assembler does not read', () => {
  const q = new URLSearchParams(
    buildProfileApiQuery({
      sector: 'financial',
      platforms: ['Windows', 'Linux'],
      sort: 'cv',
      domain: ENTERPRISE,
    }),
  );
  assert.deepEqual([...q.keys()].sort(), ['domain', 'platforms', 'sector', 'sort']);
  assert.equal(q.get('platforms'), 'Windows,Linux');
});

test('profile query: a null sector is omitted, not sent blank', () => {
  // A blank `sector=` would be indistinguishable from an answered-with-nothing
  // sector; the assembler's no-sector branch keys off the parameter's absence.
  const q = new URLSearchParams(
    buildProfileApiQuery({ sector: null, sort: 'kev', domain: ENTERPRISE }),
  );
  assert.equal(q.has('sector'), false);
  assert.equal(q.get('domain'), ENTERPRISE, 'still domain-filtered with no sector');
});

/* ────────────────────────────────────────────────────────────────────────────
 * The OT path's parameters
 * ──────────────────────────────────────────────────────────────────────────── */

test('profile query: the OT call carries assets and levels and no sort', () => {
  // The OT engine ranks Band A on exposure by definition — `exposure` is
  // deliberately not in `sortKeySchema`. Sending a sort key it cannot act on
  // would put a parameter in the URL that cannot affect the answer.
  const q = new URLSearchParams(
    buildProfileApiQuery({
      assets: ['A0003', 'A0010'],
      levels: ['l1', 'l2'],
      domain: 'ics-attack',
    }),
  );
  assert.deepEqual([...q.keys()].sort(), ['assets', 'domain', 'levels']);
  assert.equal(q.get('assets'), 'A0003,A0010');
  assert.equal(q.get('levels'), 'l1,l2');
  assert.equal(q.has('sort'), false);
});

test('profile query: an empty OT selection writes no blank params', () => {
  // `no-assets` (nothing chosen) and `empty-selection` (chose only l5) are
  // distinct visitor-facing states on the OT path, and the assembler tells them
  // apart by whether the parameters are PRESENT. A blank `levels=` would
  // collapse the two.
  const q = new URLSearchParams(
    buildProfileApiQuery({ assets: [], levels: [], domain: 'ics-attack' }),
  );
  assert.deepEqual([...q.keys()], ['domain']);

  const l5 = new URLSearchParams(
    buildProfileApiQuery({ assets: [], levels: ['l5'], domain: 'ics-attack' }),
  );
  assert.equal(l5.get('levels'), 'l5', 'an l5-only pick is a real selection, not an absence');
});

test('profile query: parseCsvParam normalises assets and levels like platforms', () => {
  assert.deepEqual(parseCsvParam('A0001,A0014'), ['A0001', 'A0014']);
  assert.deepEqual(parseCsvParam(' l3 , l3_5 '), ['l3', 'l3_5']);
  for (const empty of ['', ',,', '  ', null, undefined]) {
    assert.deepEqual(parseCsvParam(empty), [], `${JSON.stringify(empty)} is no constraint`);
  }
});
