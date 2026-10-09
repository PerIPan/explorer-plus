import test from 'node:test';
import assert from 'node:assert/strict';
import { domainSources, techniqueState, scenarioSummary } from '../../src/lib/fair-cam-state.mjs';

const kindOf = (id) => (id.startsWith('D3-') ? 'd3fend' : 'mitigation');
const row = (domain, functions = {}, counts = {}, unmapped = []) => ({
  domain, functions, unmapped,
  counts: { dataComponents: 0, detectionStrategies: 0, sigmaRules: 0, ...counts },
});

// A small world shaped like the 2026-10-09 measurement: Enterprise has every
// source; ICS has D3FEND and data components but no detection strategies or
// Sigma; Mobile has data components only; ATLAS has unclassified mitigations.
const WORLD = [
  row('enterprise-attack', { resistance: ['M1032', 'D3-MFA'], recognition: ['D3-PSA'], eventTermination: ['D3-PT'] }, { dataComponents: 3, detectionStrategies: 1, sigmaRules: 2 }),
  row('enterprise-attack', {}, {}),
  row('ics-attack', { resistance: ['M0930'], recognition: ['D3-OPM'] }, { dataComponents: 2 }),
  row('ics-attack', { resistance: ['D3-MFA'] }, { dataComponents: 2 }),
  row('mobile-attack', {}, { dataComponents: 1 }),
  row('atlas-attack', {}, {}, ['AML.M0001']),
];

test('sources are read from the data, per domain', () => {
  const s = domainSources(WORLD, kindOf);
  assert.deepEqual(s['enterprise-attack'], { mitigations: true, d3fend: true, dataComponents: true, detectionStrategies: true, sigmaRules: true });
  assert.equal(s['ics-attack'].detectionStrategies, false);
  assert.equal(s['mobile-attack'].d3fend, false);
});

test('Enterprise with nothing: a real "none-found" on every side', () => {
  const s = domainSources(WORLD, kindOf);
  assert.deepEqual(techniqueState(WORLD[1], s['enterprise-attack']),
    { prevention: 'none-found', visibility: 'none-found', recognition: 'none-found', response: 'none-found' });
});

test('ICS without D3FEND detect: recognition is NOT a gap — strategies and Sigma are not loaded for ICS', () => {
  const s = domainSources(WORLD, kindOf);
  assert.equal(techniqueState(WORLD[3], s['ics-attack']).recognition, 'not-covered');
  assert.equal(techniqueState(WORLD[2], s['ics-attack']).recognition, 'found');
});

test('Mobile and ATLAS: missing sources and unclassified mitigations read as not-covered', () => {
  const s = domainSources(WORLD, kindOf);
  assert.equal(techniqueState(WORLD[4], s['mobile-attack']).prevention, 'not-covered');
  assert.equal(techniqueState(WORLD[4], s['mobile-attack']).visibility, 'found');
  assert.equal(techniqueState(WORLD[5], s['atlas-attack']).prevention, 'not-covered');
});

test('scenario summary counts techniques per state and lists only real gaps', () => {
  const s = domainSources(WORLD, kindOf);
  const out = scenarioSummary(WORLD.slice(0, 4), s);
  assert.equal(out.techniques, 4);
  assert.deepEqual(out.summary.recognition, { found: 2, 'none-found': 1, 'not-covered': 1 });
  // Enterprise-empty misses everything; both ICS rows genuinely lack a response
  // candidate (D3FEND, which supplies Evict/Restore, IS loaded for ICS).
  assert.equal(out.gaps.length, 3);
  assert.deepEqual(out.gaps[0].missing, ['prevention', 'visibility', 'recognition', 'response']);
  assert.deepEqual(out.gaps[1].missing, ['response']);
});

import { detectionState, missingSources } from '../../src/lib/fair-cam-state.mjs';

test('detection is found only when BOTH halves are found (FAIR-CAM §3.2 AND)', () => {
  assert.equal(detectionState({ visibility: 'found', recognition: 'found' }), 'found');
  assert.equal(detectionState({ visibility: 'found', recognition: 'not-covered' }), 'not-covered'); // ICS/Mobile
  assert.equal(detectionState({ visibility: 'found', recognition: 'none-found' }), 'none-found');
  assert.equal(detectionState({ visibility: 'not-covered', recognition: 'not-covered' }), 'not-covered');
});

test('missingSources names what is not loaded, per side', () => {
  const s = domainSources(WORLD, kindOf);
  assert.deepEqual(missingSources('recognition', s['ics-attack'], false), ['ATT&CK detection strategies', 'Sigma rules']);
  assert.deepEqual(missingSources('prevention', s['atlas-attack'], true), ['ATT&CK mitigations', 'D3FEND', 'classification of this technique’s mitigations']);
  assert.deepEqual(missingSources('visibility', s['enterprise-attack'], false), []);
});
