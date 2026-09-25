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
  assert.equal(r.has('domain'), false, 'only an explicit "all" omits it');
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
