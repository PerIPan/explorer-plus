// scripts/lib/profile-url.test.mjs — run with `npm test`, no DB required.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildProfileUrl, PROFILE_PATH, MAX_LIST_VALUES } from '../../src/lib/profile-url.mjs';

/** Parse a built URL back into [pathname, URLSearchParams]. */
function parse(url) {
  const [path, qs = ''] = url.split('?');
  return [path, new URLSearchParams(qs)];
}

test('profile url: domain is always written, including the default', () => {
  // The assembler reads `AND ($2::text IS NULL OR t.domain = $2)`, so an
  // absent domain is NO filter — enterprise + mobile + ICS + ATLAS ranked
  // together. It must survive being equal to the default.
  const [, p] = parse(buildProfileUrl({ sector: 'energy', domain: 'enterprise-attack' }));
  assert.equal(p.get('domain'), 'enterprise-attack');

  const [, q] = parse(buildProfileUrl({ sector: null, domain: 'enterprise-attack' }));
  assert.equal(q.get('domain'), 'enterprise-attack', 'written even with no other answer');

  const [, r] = parse(buildProfileUrl({ sector: 'energy', domain: 'ics-attack' }));
  assert.equal(r.get('domain'), 'ics-attack');
});

test('profile url: targets the briefing page, never the current one', () => {
  const [path] = parse(buildProfileUrl({ sector: 'financial', domain: 'enterprise-attack' }));
  assert.equal(path, PROFILE_PATH);
});

test('profile url: an unanswered sector is omitted, never blank', () => {
  // `/profile` reports `no-sector` explicitly; `?sector=` would read as an
  // answer of "nothing" and is not the same thing.
  const [, p] = parse(buildProfileUrl({ sector: null, domain: 'enterprise-attack' }));
  assert.equal(p.has('sector'), false);
  assert.equal(p.get('domain'), 'enterprise-attack');
});

test('profile url: list params become comma-separated, empties omitted', () => {
  const [, p] = parse(
    buildProfileUrl({
      sector: 'energy',
      domain: 'ics-attack',
      params: { platforms: ['Windows', 'Control Server'], assets: [], purdue_levels: null },
    }),
  );
  assert.equal(p.get('platforms'), 'Windows,Control Server');
  assert.equal(p.has('assets'), false, 'an empty answer is not a blank param');
  assert.equal(p.has('purdue_levels'), false);
});

test('profile url: values survive the round trip and lists are capped', () => {
  const messy = ['Field Controller/RTU/PLC/IED', ' Office Suite ', ''];
  const [, p] = parse(
    buildProfileUrl({ sector: 'manufacturing', domain: 'ics-attack', params: { platforms: messy } }),
  );
  // Slashes, spaces and the separator itself must come back intact.
  assert.deepEqual(p.get('platforms').split(','), [
    'Field Controller/RTU/PLC/IED',
    'Office Suite',
  ]);

  const many = Array.from({ length: MAX_LIST_VALUES + 5 }, (_, i) => `v${i}`);
  const [, q] = parse(
    buildProfileUrl({ sector: 'energy', domain: 'enterprise-attack', params: { assets: many } }),
  );
  assert.equal(q.get('assets').split(',').length, MAX_LIST_VALUES, 'over the cap the API 400s');
});

test('profile url: params cannot hijack sector or domain', () => {
  const [, p] = parse(
    buildProfileUrl({
      sector: 'retail',
      domain: 'enterprise-attack',
      params: { sector: 'defense', domain: 'ics-attack', sort: 'lift' },
    }),
  );
  assert.equal(p.get('sector'), 'retail');
  assert.equal(p.get('domain'), 'enterprise-attack');
  assert.equal(p.get('sort'), 'lift', 'a scalar extra still passes through');
});
