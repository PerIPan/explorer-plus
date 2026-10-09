import test from 'node:test';
import assert from 'node:assert/strict';

import { FAIR_CAM_FUNCTIONS } from '../../src/lib/fair-cam.mjs';
import {
  D3FEND_TO_FAIR_CAM,
  MITIGATION_TO_FAIR_CAM,
  D3FEND_TACTIC_DEFAULT,
  classifyCoverageRow,
} from '../../src/lib/fair-cam-mappings.mjs';

/* Snapshot of the identifiers the curation must cover, read from the live
 * site on 2026-10-09 (D3FEND 156; ATT&CK mitigations Enterprise 44 + ICS 52).
 * A new upstream id does not fail here — it surfaces as "unclassified" in the
 * UI — but an id dropped from or added to the curation without updating this
 * list does. */
const D3FEND_IDS = ["D3-AA", "D3-ABPI", "D3-ACH", "D3-AEM", "D3-AL", "D3-AM", "D3-ANAA", "D3-ANCI", "D3-APCA", "D3-AVE", "D3-BA", "D3-CA", "D3-CAA", "D3-CBAN", "D3-CCSA", "D3-CDP", "D3-CERO", "D3-CF", "D3-CH", "D3-CI", "D3-CIA", "D3-CM", "D3-CP", "D3-CQ", "D3-CR", "D3-CRO", "D3-CS", "D3-CSPP", "D3-CTS", "D3-DA", "D3-DAM", "D3-DE", "D3-DENCR", "D3-DF", "D3-DI", "D3-DKE", "D3-DKF", "D3-DKP", "D3-DLV", "D3-DNL", "D3-DNR", "D3-DNSAL", "D3-DNSDL", "D3-DNSTA", "D3-DQSA", "D3-DRA", "D3-DTP", "D3-DUC", "D3-EAL", "D3-EDL", "D3-EF", "D3-EFA", "D3-EHB", "D3-ER", "D3-FA", "D3-FBA", "D3-FC", "D3-FCA", "D3-FE", "D3-FEMC", "D3-FEV", "D3-FFV", "D3-FIM", "D3-FRDDL", "D3-FV", "D3-HBPI", "D3-HBWP", "D3-HCI", "D3-HD", "D3-HR", "D3-HS", "D3-IAA", "D3-IDA", "D3-IOPR", "D3-IPCTA", "D3-ISVA", "D3-ITF", "D3-KBPI", "D3-LAM", "D3-LFP", "D3-LLM", "D3-MAN", "D3-MBT", "D3-MENCR", "D3-MFA", "D3-NNI", "D3-NRAM", "D3-NTCD", "D3-NTF", "D3-NTPM", "D3-NTSA", "D3-OMM", "D3-OPM", "D3-OPR", "D3-OTF", "D3-OTP", "D3-OVAR", "D3-PCSV", "D3-PHDURA", "D3-PLA", "D3-PLM", "D3-PMAD", "D3-PR", "D3-PS", "D3-PSA", "D3-PSEP", "D3-PSMD", "D3-PT", "D3-PWA", "D3-RC", "D3-RD", "D3-RE", "D3-RF", "D3-RFAM", "D3-RFUM", "D3-RH", "D3-RIC", "D3-RKD", "D3-RNA", "D3-RPA", "D3-RRID", "D3-RS", "D3-RTA", "D3-RTSD", "D3-RUAA", "D3-SAOR", "D3-SBV", "D3-SCA", "D3-SCF", "D3-SCP", "D3-SDM", "D3-SFA", "D3-SFCV", "D3-SFV", "D3-SICA", "D3-SJA", "D3-SMRA", "D3-SPP", "D3-SRA", "D3-SSC", "D3-ST", "D3-SU", "D3-SWI", "D3-SYSVA", "D3-TB", "D3-TBA", "D3-TL", "D3-UA", "D3-UAP", "D3-UGLPA", "D3-ULA", "D3-URA", "D3-USICA", "D3-VI", "D3-VS", "D3-WSAM"];
const MITIGATION_IDS = ["M0800", "M0801", "M0802", "M0803", "M0804", "M0805", "M0806", "M0807", "M0808", "M0809", "M0810", "M0811", "M0812", "M0813", "M0814", "M0815", "M0816", "M0817", "M0818", "M0913", "M0915", "M0916", "M0917", "M0918", "M0919", "M0920", "M0921", "M0922", "M0924", "M0926", "M0927", "M0928", "M0930", "M0931", "M0932", "M0934", "M0935", "M0936", "M0937", "M0938", "M0941", "M0942", "M0944", "M0945", "M0946", "M0947", "M0948", "M0949", "M0950", "M0951", "M0953", "M0954", "M1013", "M1015", "M1016", "M1017", "M1018", "M1019", "M1020", "M1021", "M1022", "M1024", "M1025", "M1026", "M1027", "M1028", "M1029", "M1030", "M1031", "M1032", "M1033", "M1034", "M1035", "M1036", "M1037", "M1038", "M1039", "M1040", "M1041", "M1042", "M1043", "M1044", "M1045", "M1046", "M1047", "M1048", "M1049", "M1050", "M1051", "M1052", "M1053", "M1054", "M1055", "M1056", "M1057", "M1060"];

const FUNCTION_IDS = new Set(FAIR_CAM_FUNCTIONS.map((f) => f.id));

test('curation covers exactly the 2026-10-09 snapshot', () => {
  assert.deepEqual(Object.keys(D3FEND_TO_FAIR_CAM).sort(), D3FEND_IDS);
  assert.deepEqual(Object.keys(MITIGATION_TO_FAIR_CAM).sort(), MITIGATION_IDS);
  assert.equal(D3FEND_IDS.length, 156);
  assert.equal(MITIGATION_IDS.length, 96);
});

test('every row names real FAIR-CAM functions and gives a reason', () => {
  for (const [id, row] of [...Object.entries(D3FEND_TO_FAIR_CAM), ...Object.entries(MITIGATION_TO_FAIR_CAM)]) {
    assert.ok(row, id);
    assert.ok(row.rationale && row.rationale.length >= 15, `${id}: rationale`);
    if (row.notAControl) { assert.equal(row.functions.length, 0, id); continue; }
    assert.ok(row.functions.length > 0, `${id}: no function`);
    for (const fn of row.functions) assert.ok(FUNCTION_IDS.has(fn), `${id}: unknown function ${fn}`);
    assert.ok(!row.functions.includes('monitoring'), `${id}: Monitoring is time between reviews — never a control-catalogue property`);
  }
});

test('ICS mitigations that mirror Enterprise ones get the identical classification', () => {
  assert.deepEqual(MITIGATION_TO_FAIR_CAM.M0930, MITIGATION_TO_FAIR_CAM.M1030);
  assert.deepEqual(MITIGATION_TO_FAIR_CAM.M0951, MITIGATION_TO_FAIR_CAM.M1051);
});

test('ICS mitigations mirror Enterprise ones by NAME, not just by number (pinned 2026-10-09)', () => {
  // The M09NN <-> M10NN pairing is an assumption about ATT&CK numbering; these
  // name pairs were read from the live site and make the assumption checkable.
  const pairs = {
    M0913: 'Application Developer Guidance', M0930: 'Network Segmentation', M0931: 'Network Intrusion Prevention',
    M0932: 'Multi-factor Authentication', M0937: 'Filter Network Traffic', M0947: 'Audit', M0949: 'Antivirus/Antimalware',
    M0951: 'Update Software', M0953: 'Data Backup', M0954: 'Software Configuration',
  };
  for (const id of Object.keys(pairs)) assert.deepEqual(MITIGATION_TO_FAIR_CAM[id], MITIGATION_TO_FAIR_CAM[`M10${id.slice(3)}`], id);
});

test('classifyCoverageRow groups ids by function and keeps source counts separate', () => {
  const r = classifyCoverageRow({
    mitigations: ['M1032', 'M1053', 'M1055', 'AML.M0000'],
    d3fend: ['D3-MFA|Harden', 'D3-PT|Evict', 'D3-PSA|Detect'],
    dataComponents: 4, detectionStrategies: 2, sigmaRules: 0,
  });
  assert.deepEqual(r.functions.resistance, ['D3-MFA', 'M1032']);
  assert.deepEqual(r.functions.resilience, ['M1053']);
  assert.deepEqual(r.functions.eventTermination, ['D3-PT']);
  assert.deepEqual(r.functions.recognition, ['D3-PSA']);
  assert.deepEqual(r.counts, { dataComponents: 4, detectionStrategies: 2, sigmaRules: 0 });
  assert.deepEqual(r.unmapped, ['AML.M0000']);           // ATLAS: not classified yet
  assert.ok(!Object.values(r.functions).flat().includes('M1055')); // "Do Not Mitigate" is not a control
});

test('a new upstream D3FEND id falls back to its tactic default and is flagged', () => {
  const r = classifyCoverageRow({ d3fend: ['D3-NEWX|Harden', 'D3-ODD|Weird', 'not-an-id|Harden'] });
  assert.deepEqual(r.functions.resistance, ['D3-NEWX']);
  assert.deepEqual(r.defaultRule, ['D3-NEWX']);
  assert.deepEqual(r.unmapped, ['D3-ODD']);               // unknown tactic: unmapped, not guessed
  assert.ok(!JSON.stringify(r).includes('not-an-id'));    // a label stored as an id is ignored
  for (const fn of Object.values(D3FEND_TACTIC_DEFAULT)) assert.ok(FUNCTION_IDS.has(fn), fn);
});
