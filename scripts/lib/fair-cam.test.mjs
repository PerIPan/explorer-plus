import test from 'node:test';
import assert from 'node:assert/strict';

import {
  FAIR_CAM_SOURCE,
  FAIR_CAM_ATTRIBUTION,
  FAIR_CAM_DOMAINS,
  FAIR_CAM_FUNCTIONS,
  FAIR_CAM_GROUP_RELATIONS,
  FAIR_CAM_EFFECTIVENESS,
  fairCamFunction,
} from '../../src/lib/fair-cam.mjs';

/* The ontology is quoted from a CC BY-NC-ND work, so the tests guard
 * completeness and shape — the text itself is the Standard's and is checked
 * against the PDF by a human, never generated. */

test('26 functions: 9 Loss Event, 6 Variance Management, 11 Decision Support', () => {
  const by = (d) => FAIR_CAM_FUNCTIONS.filter((f) => f.domain === d).length;
  assert.deepEqual([by('LEC'), by('VMC'), by('DSC')], [9, 6, 11]);
});

test('ids unique; every function has a quoted name, definition, unit, relation and section', () => {
  const ids = FAIR_CAM_FUNCTIONS.map((f) => f.id);
  assert.equal(new Set(ids).size, ids.length);
  for (const f of FAIR_CAM_FUNCTIONS) {
    for (const k of ['name', 'definition', 'unit', 'relation', 'group']) assert.ok(f[k] && f[k].length > 3, `${f.id}.${k}`);
    assert.match(f.section, /^\d(\.\d)+$|^\d\.\d$/, f.id);
    assert.ok(FAIR_CAM_DOMAINS.some((d) => d.id === f.domain), f.id);
  }
});

test('Loss Event logic is the Standard’s: prevention OR, detection AND, response weak AND', () => {
  for (const id of ['avoidance', 'deterrence', 'resistance']) assert.match(fairCamFunction(id).relation, /Boolean OR/);
  for (const id of ['visibility', 'monitoring', 'recognition']) assert.match(fairCamFunction(id).relation, /Boolean AND/);
  for (const id of ['eventTermination', 'resilience', 'lossReduction']) assert.match(fairCamFunction(id).relation, /“weak” Boolean AND/);
  assert.match(FAIR_CAM_GROUP_RELATIONS.find((r) => r.domain === 'LEC').text, /Detection and Loss Event Response have a Boolean AND/);
});

test('Monitoring is measured in time — the one detection function this site can never supply', () => {
  assert.equal(fairCamFunction('monitoring').unit, 'Elapsed time between reviews');
});

test('source carries the licence, the reference URL the Standard requires, and an attribution line', () => {
  assert.equal(FAIR_CAM_SOURCE.licenceShort, 'CC BY-NC-ND 4.0');
  assert.match(FAIR_CAM_SOURCE.licenceUrl, /by-nc-nd\/4\.0/);
  assert.equal(FAIR_CAM_SOURCE.referenceUrl, 'http://www.fairinstitute.org/FAIR-CAM/');
  assert.match(FAIR_CAM_ATTRIBUTION, /FAIR Institute/);
  assert.match(FAIR_CAM_ATTRIBUTION, /CC BY-NC-ND 4\.0/);
  assert.equal(FAIR_CAM_EFFECTIVENESS.attributes.length, 3);
});

/* Verbatim integrity — LOCAL ONLY. The PDF text extracts live in docs/research/
 * (git-ignored: docs/ is local), so CI skips this; on the machine that has them
 * it proves every quoted field is a substring of the Standard (or the Overview),
 * after undoing line wraps and the PDF's "fi" ligature. Formulas are maths set in
 * italic Unicode in the PDF and are not compared. */
import { existsSync, readFileSync } from 'node:fs';
const STANDARD = new URL('../../docs/research/fair-cam-standard-v1.0.txt', import.meta.url);
const OVERVIEW = new URL('../../docs/research/fair-cam-overview.txt', import.meta.url);
// Undo the PDF's page furniture (footer "©2025 FAIR Institute . All Rights
// Reserved. N" and the running header), which the extract splices mid-sentence.
const norm = (s) => s
  .replace(/ﬁ/g, 'fi').replace(/ﬂ/g, 'fl')
  .replace(/#####[^\n]*\n/g, ' ')
  .replace(/\s+/g, ' ')
  .replace(/ ?©2025 FAIR Institute ?\. All Rights Reserved\. ?\d* ?/g, ' ')
  .replace(/ ?FAIR Controls Analytics Model \| Standard Artifact \| V1\.0 January 2025 ?/g, ' ')
  .replace(/ ?www\.FAIRInstitute\.org ?/g, ' ')
  .replace(/\s+/g, ' ');

test('every quoted field is verbatim in the Standard / Overview text', { skip: !existsSync(STANDARD) && 'PDF extract not present (local-only check)' }, () => {
  const std = norm(readFileSync(STANDARD, 'utf8'));
  const ovw = existsSync(OVERVIEW) ? norm(readFileSync(OVERVIEW, 'utf8')) : '';
  const missing = [];
  const check = (label, text, corpus = std) => { if (!corpus.includes(norm(text))) missing.push(`${label}: ${text.slice(0, 70)}…`); };
  for (const f of FAIR_CAM_FUNCTIONS) {
    for (const k of ['name', 'definition', 'unit', 'relation', 'group']) check(`${f.id}.${k}`, f[k]);
  }
  for (const d of FAIR_CAM_DOMAINS) { check(`${d.id}.effect`, d.effect); check(`${d.id}.plural`, d.plural); check(`${d.id}.name`, d.name); }
  for (const r of FAIR_CAM_GROUP_RELATIONS) check(`group ${r.domain}`, r.text);
  check('effectiveness.intro', FAIR_CAM_EFFECTIVENESS.intro);
  for (const a of FAIR_CAM_EFFECTIVENESS.attributes) check(`effectiveness.${a.name}`, a.text);
  if (ovw) { check('overview.formulaNote', FAIR_CAM_EFFECTIVENESS.formulaNote, ovw); check('overview.example', FAIR_CAM_EFFECTIVENESS.example, ovw); }
  assert.deepEqual(missing, []);
});
