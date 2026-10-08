import test from 'node:test';
import assert from 'node:assert/strict';

import {
  SP800_53_CONTROLS,
  CSF_11_SUBCATEGORIES,
  RISK_RESPONSES,
  SCENARIOS,
  MAINTENANCE_GROUP_EXAMPLES,
  RECOMMENDATIONS,
  PROCUREMENT_QUESTIONS,
} from '../../src/lib/nist-800-40.mjs';

/* Counts are the publication's (SP 800-40r4, April 2022): the appendix names 8
 * SP 800-53 controls and 13 CSF 1.1 subcategories; §2.1 has 4 risk responses,
 * §3.3 4 scenarios, §3.4 6 example groups, §3 7 recommendations, §3.7 8
 * procurement questions. A lost or duplicated row fails here. */

test('the eight SP 800-53 controls from the appendix, in order', () => {
  assert.deepEqual(SP800_53_CONTROLS.map((c) => c.id), ['CM-2', 'CM-3', 'CM-8', 'RA-7', 'SI-2', 'SR-2', 'SR-3', 'SR-5']);
});

test('siteId is the zero-padded form the nist_controls table uses', () => {
  // The route regex accepts `CM-2` and would return zero rows for it — a
  // silent zero, indistinguishable from the three controls that really have
  // none. So the padded id must be exactly the published id, padded.
  for (const c of SP800_53_CONTROLS) {
    assert.match(c.siteId, /^[A-Z]{2}-\d{2,3}$/, c.id);
    const [fam, num] = c.id.split('-');
    assert.equal(c.siteId, `${fam}-${num.padStart(2, '0')}`);
  }
});

test('CSF entries are CSF 1.1 identifiers, as published', () => {
  assert.equal(CSF_11_SUBCATEGORIES.length, 13);
  for (const s of CSF_11_SUBCATEGORIES) assert.match(s.id, /^(ID|PR)\.[A-Z]{2}-\d{1,2}$/, s.id);
  assert.equal(new Set(CSF_11_SUBCATEGORIES.map((s) => s.id)).size, 13);
});

test('section list sizes match the publication', () => {
  assert.equal(RISK_RESPONSES.length, 4);
  assert.deepEqual(SCENARIOS.map((s) => s.n), [1, 2, 3, 4]);
  assert.equal(MAINTENANCE_GROUP_EXAMPLES.length, 6);
  assert.deepEqual(RECOMMENDATIONS.map((r) => r.section), ['3.1', '3.2', '3.3', '3.4', '3.5', '3.6', '3.7']);
  assert.equal(PROCUREMENT_QUESTIONS.length, 8);
});
