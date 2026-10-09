// scripts/lib/canonical-redirects.test.mjs — run with `npm test`
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canonicalRedirect, RENAMED_FRAMEWORK_KEYS } from '../../src/lib/canonical-redirects.mjs';

test('D3FEND ids: any lowercase -> uppercase; canonical and non-D3FEND paths untouched', () => {
  assert.equal(canonicalRedirect('/frameworks/d3fend/d3-am'), '/frameworks/d3fend/D3-AM');
  assert.equal(canonicalRedirect('/frameworks/d3fend/D3-psep'), '/frameworks/d3fend/D3-PSEP');
  assert.equal(canonicalRedirect('/frameworks/d3fend/D3-AM'), null);
  assert.equal(canonicalRedirect('/frameworks/d3fend'), null);
  assert.equal(canonicalRedirect('/frameworks/d3fend/not-an-id'), null);
  assert.equal(canonicalRedirect('/frameworks/d3fend/d3-am/extra'), null);
});

test('retired compliance keys -> successor; live keys untouched; no chains, no self-loops', () => {
  assert.equal(canonicalRedirect('/compliance/deu-c5-2020'), '/compliance/deu-c5-2026');
  assert.equal(canonicalRedirect('/compliance/eu-cyber-resilience-act-2022'), '/compliance/eu-cra');
  assert.equal(canonicalRedirect('/compliance/eu-cra'), null);
  assert.equal(canonicalRedirect('/compliance/hasOwnProperty'), null);
  assert.equal(canonicalRedirect('/compliance/constructor'), null);
  for (const [from, to] of Object.entries(RENAMED_FRAMEWORK_KEYS)) {
    assert.notEqual(from, to);
    assert.equal(Object.hasOwn(RENAMED_FRAMEWORK_KEYS, to), false, `${from} -> ${to} would chain`);
  }
});
