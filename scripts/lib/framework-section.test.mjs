// scripts/lib/framework-section.test.mjs — run with `npm test`
// Every case is a real ref_id shape from the SCF 2026.3 workbook.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { extractSection } from '../../src/lib/framework-section.mjs';

const cases = [
  // framework-specific
  ['§ 164.306(a)(1)', 'hipaa-security-rule', '§ 164.306'],
  ['03.01.01.a', 'nist-800-171-r3', '03.01'],
  ['Part I(2)(e)', 'eu-cra', 'Annex I'],          // pre-glue rows
  ['Annex I, Part I(2)(e)', 'eu-cra', 'Annex I'],
  ['Annex II', 'eu-cra', 'Annex II'],
  ['Article 13(13)', 'eu-cra', 'Article 13'],
  // container paths, glued and bare
  ['Title 2, Chapter II, Art. 29(5)', 'bel-act-30-2018', 'Title 2'],
  ['Appendix A, 1.1', 'isr-cmo-2-0', 'Appendix A'],
  ['Schedule 1 - 1(1)(a)', 'hkg-pdo-2022', 'Schedule 1'],
  ['Annex 1.1.7', 'ind-rbi-pa-2025', 'Annex 1'],
  ['Appendix C', 'isr-cmo-2-0', 'Appendix C'],
  ['Title II - Chapter IV', 'eu-dora-rts', 'Title II'],
  // generic rules
  ['Article 21(2)(d)', 'eu-nis2', 'Article 21'],
  ['164.308(a)(1)', 'x', '164.308'],
  ['CCC-01', 'csa-ccm-4-1', 'CCC'],
  ['12.10.1', 'pci-dss-4', '12'],
  // roman chapters
  ['III.9.a', 'ind-rbi-pa-2025', 'III.9'],
  ['IV.1.49', 'srb-act-9-2018', 'IV.1'],
  ['II.A.3.a', 'ffiec-iteh-2016', 'II.A'],
  ['II.4(1)', 'bhs-dpa-2003', 'II.4'],
  ['IV.B.a-48', 'che-finma-circ-23-1', 'IV.B'],
  ['VII.', 'tsa-sd-pipeline-2021-02f', 'VII.'],
  // letter sections are not roman chapters
  ['C.11.4', 'grc-pirppd-1997', 'C.11.4'],
  ['L.1', 'sig-2025', 'L.1'],
  // a word that starts like a container keyword
  ['Participation 3', 'x', 'Participation'],
  ['', 'x', '(unspecified)'],
];

test('extractSection groups real SCF ref shapes as intended', () => {
  for (const [ref, key, want] of cases) assert.equal(extractSection(ref, key), want, `${key}: ${JSON.stringify(ref)}`);
});
