// src/lib/fair-cam-mappings.mjs — pure data + logic, no React. Tested by
// scripts/lib/fair-cam-mappings.test.mjs.
//
// THIS SITE'S CURATION, NOT THE FAIR INSTITUTE'S
// Which FAIR-CAM function each D3FEND countermeasure and ATT&CK mitigation can
// serve. FAIR-CAM itself (src/lib/fair-cam.mjs) defines the functions; it maps
// no D3FEND or ATT&CK identifier, and no open mapping exists anywhere (checked
// 2026-10-09: the FAIR Institute's CIS/CSF mappings are members-only, its
// ATT&CK mapping unpublished, D3FEND unmapped). Every row below is therefore a
// judgement, carries its reason, and every surface that shows it says so.
//
// WHAT A MAPPING MEANS HERE
// "Control X can serve function F" — the CANDIDATE function, read from what the
// control does. It says nothing about efficacy, coverage, reliability or
// whether anyone has deployed it: FAIR-CAM measures those per organisation, in
// units this site has no data for. The classifier below therefore reports
// availability (which functions have at least one candidate control), never a
// strength.
//
// RULES (applied consistently; a row departs from its tactic default only with
// a rationale saying why):
//   D3FEND Harden  -> resistance          (Standard §3.1.3 examples: authentication,
//                                           privilege restrictions, encryption)
//   D3FEND Detect  -> recognition         (§3.2.3 examples: signatures, baselines,
//                                           checksums); evidence producers also -> visibility
//   D3FEND Isolate -> resistance, or avoidance where it keeps the threat from
//                     reaching the asset at all (§3.1.1 examples: network firewalls,
//                     IP filtering at a boundary; Overview: outer layers act as
//                     Avoidance for inner ones)
//   D3FEND Deceive -> recognition         (decoys reveal activity)
//   D3FEND Evict   -> eventTermination    (§3.3.1)
//   D3FEND Restore -> resilience          (§3.3.2)
//   D3FEND Model   -> Decision Support (Provide Asset/Controls Data) or Variance
//                     Management (Control Monitoring) — not a Loss Event function
//   ATT&CK data components -> visibility; Sigma rules, detection strategies -> recognition
//   Patching / update controls -> implementation (VMC; §4.3.2 names patching) AND
//                     resistance (the patched system is what resists, §3.1.3 "Software
//                     or systems without exploitable weaknesses")
//
// Snapshot: D3FEND 156 countermeasures (Model 12, Harden 32, Detect 56, Isolate 29,
// Deceive 4, Evict 14, Restore 9); ATT&CK mitigations Enterprise 44 + ICS 52,
// read from the live site 2026-10-09. Mobile (12) and ATLAS (35) mitigations are
// not classified yet and surface as "unclassified".

/**
 * @typedef {Object} Mapping
 * @property {string[]} functions  FAIR-CAM function ids (src/lib/fair-cam.mjs).
 * @property {string} rationale
 * @property {boolean} [notAControl]  ATT&CK entries that say "no mitigation".
 */

const m = (functions, rationale) => Object.freeze({ functions: Object.freeze(functions), rationale });

const R = {
  harden: 'Hardens the asset so a threat action is less likely to succeed (Resistance; §3.1.3 lists authentication, privilege restrictions and encryption).',
  detect: 'Analyses activity or artefacts to tell malicious from normal (Recognition; §3.2.3 lists signatures, baselines and checksums).',
  isolateResist: 'Constrains what an action can do once attempted — the attempt is made but fails (Resistance).',
  isolateAvoid: 'Keeps the threat from reaching the asset at all, like the boundary filtering the Standard gives for Avoidance (§3.1.1).',
  deceive: 'Decoys produce a signal only an intruder triggers (Recognition).',
  evict: 'Removes the adversary’s foothold or access, ending the activity (Event Termination, §3.3.1).',
  restore: 'Returns systems, data or access to normal operation (Resilience, §3.3.2).',
  inventory: 'An inventory or map — it informs decisions about controls rather than stopping or detecting an event (Decision Support: Provide Asset Data).',
  vulnFind: 'Finds variant conditions such as vulnerable software or weak configuration (Variance Management: Control Monitoring).',
  patch: 'Patching is the Standard’s own example for Implementation (§4.3.2); the patched system is what then resists (§3.1.3).',
  rotate: 'Limits how long a stolen secret remains usable — the attempt with it fails (Resistance).',
};

/** @type {Readonly<Record<string, Mapping>>} */
export const D3FEND_TO_FAIR_CAM = Object.freeze({
  // ── Model (12) ──────────────────────────────────────────────────────────
  'D3-AM': m(['provideControlsData'], 'Models who can access what — data about the state of access controls (Decision Support: Provide Controls Data).'),
  'D3-AVE': m(['controlMonitoring'], R.vulnFind),
  'D3-CI': m(['provideAssetData', 'controlMonitoring'], 'Records configurations — asset data, and the baseline against which configuration drift (variance) is found.'),
  'D3-CIA': m(['controlMonitoring'], 'Inspects container images for vulnerable or misconfigured contents before they run (Control Monitoring).'),
  'D3-DI': m(['provideAssetData'], R.inventory),
  'D3-HCI': m(['provideAssetData'], R.inventory),
  'D3-LLM': m(['provideAssetData'], R.inventory),
  'D3-NNI': m(['provideAssetData'], R.inventory),
  'D3-NTPM': m(['provideControlsData'], 'Maps network traffic policy — data about the filtering controls in place (Provide Controls Data).'),
  'D3-PLM': m(['provideAssetData'], R.inventory),
  'D3-SWI': m(['provideAssetData'], R.inventory),
  'D3-SYSVA': m(['controlMonitoring'], R.vulnFind),

  // ── Harden (32) ─────────────────────────────────────────────────────────
  'D3-AA': m(['resistance'], R.harden),
  'D3-ACH': m(['resistance'], R.harden),
  'D3-BA': m(['resistance'], R.harden),
  'D3-CBAN': m(['resistance'], R.harden),
  'D3-CDP': m(['resistance'], R.harden),
  'D3-CERO': m(['resistance'], R.rotate),
  'D3-CH': m(['resistance'], R.harden),
  'D3-CP': m(['resistance'], R.harden),
  'D3-CRO': m(['resistance'], R.rotate),
  'D3-CS': m(['resistance'], 'Removes credentials an intruder could harvest, so the attempt finds nothing to use (Resistance).'),
  'D3-DENCR': m(['resistance'], R.harden),
  'D3-DLV': m(['resistance'], R.harden),
  'D3-DRA': m(['avoidance'], 'Removes the remote path entirely, so the threat never makes contact through it (Avoidance, §3.1.1).'),
  'D3-FE': m(['resistance'], R.harden),
  'D3-HBWP': m(['resistance'], R.harden),
  'D3-MAN': m(['resistance'], R.harden),
  'D3-MENCR': m(['resistance'], R.harden),
  'D3-MFA': m(['resistance'], R.harden),
  'D3-OTP': m(['resistance'], R.harden),
  'D3-PR': m(['resistance'], R.rotate),
  'D3-PSEP': m(['resistance'], R.harden),
  'D3-PWA': m(['resistance'], R.harden),
  'D3-RH': m(['resistance'], 'Physical hardening of electronics against radiation-induced faults (Resistance).'),
  'D3-SAOR': m(['resistance'], R.harden),
  'D3-SCP': m(['resistance'], R.harden),
  'D3-SFCV': m(['resistance'], R.harden),
  'D3-SPP': m(['resistance'], R.harden),
  'D3-SU': m(['implementation', 'resistance'], R.patch),
  'D3-TB': m(['resistance'], R.harden),
  'D3-TBA': m(['resistance'], R.harden),
  'D3-TL': m(['resistance'], R.harden),
  'D3-VI': m(['resistance'], R.harden),

  // ── Detect (56) ─────────────────────────────────────────────────────────
  'D3-AEM': m(['recognition'], R.detect),
  'D3-ANAA': m(['recognition'], R.detect),
  'D3-APCA': m(['recognition'], R.detect),
  'D3-CA': m(['recognition'], R.detect),
  'D3-CAA': m(['recognition'], R.detect),
  'D3-CCSA': m(['recognition', 'eventTermination'], 'Scopes what a compromised credential reached — recognises the extent of the event and directs its termination.'),
  'D3-CSPP': m(['recognition'], R.detect),
  'D3-DA': m(['recognition'], R.detect),
  'D3-DAM': m(['recognition'], R.detect),
  'D3-DNSTA': m(['recognition'], R.detect),
  'D3-DQSA': m(['recognition'], R.detect),
  'D3-EFA': m(['recognition'], R.detect),
  'D3-EHB': m(['visibility'], 'Endpoints report their state — it produces the evidence that recognition then reviews (Visibility, §3.2.1).'),
  'D3-FA': m(['recognition'], R.detect),
  'D3-FBA': m(['recognition'], R.detect),
  'D3-FC': m(['visibility', 'recognition'], 'Extracts files from traffic or storage — produces evidence and enables its analysis.'),
  'D3-FCA': m(['recognition'], R.detect),
  'D3-FEMC': m(['visibility', 'recognition'], 'Monitoring code inside firmware — captures activity no host agent sees, and flags deviations.'),
  'D3-FIM': m(['recognition'], R.detect),
  'D3-FV': m(['recognition'], R.detect),
  'D3-HD': m(['recognition'], R.detect),
  'D3-IAA': m(['recognition'], R.detect),
  'D3-IDA': m(['recognition'], R.detect),
  'D3-IPCTA': m(['recognition'], R.detect),
  'D3-ISVA': m(['recognition'], R.detect),
  'D3-LAM': m(['recognition'], R.detect),
  'D3-MBT': m(['recognition'], R.detect),
  'D3-NTCD': m(['recognition'], R.detect),
  'D3-NTSA': m(['recognition'], R.detect),
  'D3-OMM': m(['recognition'], R.detect),
  'D3-OPM': m(['recognition'], R.detect),
  'D3-PCSV': m(['recognition'], R.detect),
  'D3-PHDURA': m(['recognition'], R.detect),
  'D3-PLA': m(['recognition'], R.detect),
  'D3-PMAD': m(['recognition'], R.detect),
  'D3-PSA': m(['recognition'], R.detect),
  'D3-PSMD': m(['recognition'], R.detect),
  'D3-RFUM': m(['recognition'], R.detect),
  'D3-RPA': m(['recognition'], R.detect),
  'D3-RTA': m(['recognition'], R.detect),
  'D3-RTSD': m(['recognition'], R.detect),
  'D3-SBV': m(['recognition'], R.detect),
  'D3-SCA': m(['recognition'], R.detect),
  'D3-SDM': m(['recognition'], R.detect),
  'D3-SFA': m(['recognition'], R.detect),
  'D3-SFV': m(['recognition'], R.detect),
  'D3-SICA': m(['recognition'], R.detect),
  'D3-SJA': m(['recognition'], R.detect),
  'D3-SMRA': m(['recognition'], R.detect),
  'D3-SRA': m(['recognition'], R.detect),
  'D3-SSC': m(['recognition'], R.detect),
  'D3-UA': m(['recognition'], R.detect),
  'D3-UGLPA': m(['recognition'], R.detect),
  'D3-URA': m(['recognition'], R.detect),
  'D3-USICA': m(['recognition'], R.detect),
  'D3-VS': m(['visibility'], 'Cameras — the Standard’s own Visibility example (CCTV, §3.2.1).'),

  // ── Isolate (29) ────────────────────────────────────────────────────────
  'D3-ABPI': m(['resistance'], R.isolateResist),
  'D3-CF': m(['avoidance'], R.isolateAvoid),
  'D3-CM': m(['resistance'], 'Rewrites risky content (e.g. disarming active elements) so it is delivered but cannot act (Resistance).'),
  'D3-CQ': m(['avoidance'], R.isolateAvoid),
  'D3-CTS': m(['resistance'], R.isolateResist),
  'D3-DNL': m(['avoidance'], 'One-way link (data diode) — traffic from the outside physically cannot reach the protected side (Avoidance).'),
  'D3-DNSAL': m(['avoidance'], R.isolateAvoid),
  'D3-DNSDL': m(['avoidance'], R.isolateAvoid),
  'D3-DTP': m(['resistance'], R.isolateResist),
  'D3-EAL': m(['resistance'], R.isolateResist),
  'D3-EDL': m(['resistance'], R.isolateResist),
  'D3-EF': m(['avoidance'], R.isolateAvoid),
  'D3-FFV': m(['resistance'], R.isolateResist),
  'D3-FRDDL': m(['avoidance'], R.isolateAvoid),
  'D3-HBPI': m(['resistance'], R.isolateResist),
  'D3-IOPR': m(['resistance'], R.isolateResist),
  'D3-ITF': m(['avoidance'], R.isolateAvoid),
  'D3-KBPI': m(['resistance'], R.isolateResist),
  'D3-LFP': m(['resistance'], R.isolateResist),
  'D3-NRAM': m(['resistance'], R.isolateResist),
  'D3-NTF': m(['avoidance'], R.isolateAvoid),
  'D3-OPR': m(['resistance'], R.isolateResist),
  'D3-OTF': m(['resistance'], 'Blocks outbound connections such as command-and-control or exfiltration — the action is attempted and fails (Resistance).'),
  'D3-OVAR': m(['resistance'], R.isolateResist),
  'D3-RFAM': m(['resistance'], R.isolateResist),
  'D3-RRID': m(['avoidance'], R.isolateAvoid),
  'D3-SCF': m(['resistance'], R.isolateResist),
  'D3-UAP': m(['resistance'], R.isolateResist),
  'D3-WSAM': m(['resistance'], R.isolateResist),

  // ── Deceive (4) ─────────────────────────────────────────────────────────
  'D3-DE': m(['recognition', 'avoidance'], 'A decoy environment both reveals the intruder and draws contact away from real assets.'),
  'D3-DF': m(['recognition'], R.deceive),
  'D3-DNR': m(['recognition'], R.deceive),
  'D3-DUC': m(['recognition'], R.deceive),

  // ── Evict (14) ──────────────────────────────────────────────────────────
  'D3-AL': m(['eventTermination'], R.evict),
  'D3-ANCI': m(['eventTermination'], R.evict),
  'D3-CR': m(['eventTermination'], R.evict),
  'D3-DKE': m(['eventTermination'], R.evict),
  'D3-DKF': m(['eventTermination'], R.evict),
  'D3-DKP': m(['eventTermination'], R.evict),
  'D3-ER': m(['eventTermination'], R.evict),
  'D3-FEV': m(['eventTermination'], R.evict),
  'D3-HR': m(['eventTermination'], R.evict),
  'D3-HS': m(['eventTermination'], R.evict),
  'D3-PS': m(['eventTermination'], R.evict),
  'D3-PT': m(['eventTermination'], R.evict),
  'D3-RKD': m(['eventTermination'], R.evict),
  'D3-ST': m(['eventTermination'], R.evict),

  // ── Restore (9) ─────────────────────────────────────────────────────────
  'D3-RC': m(['resilience'], R.restore),
  'D3-RD': m(['resilience'], R.restore),
  'D3-RE': m(['resilience'], R.restore),
  'D3-RF': m(['resilience'], R.restore),
  'D3-RIC': m(['resilience'], R.restore),
  'D3-RNA': m(['resilience'], R.restore),
  'D3-RS': m(['resilience'], R.restore),
  'D3-RUAA': m(['resilience'], R.restore),
  'D3-ULA': m(['resilience'], R.restore),
});

const NOT_A_CONTROL = Object.freeze({ functions: Object.freeze([]), rationale: 'ATT&CK’s own marker that no mitigation applies — not a control, so no function.', notAControl: true });

/**
 * Enterprise mitigations. The ICS set mirrors most of them one-for-one under
 * M09NN (M0930 Network Segmentation = M1030), so those reuse the Enterprise row
 * below rather than being argued twice; ICS-only mitigations follow.
 * @type {Readonly<Record<string, Mapping>>}
 */
const ENTERPRISE = {
  M1013: m(['reduceVarianceProbability'], 'Guidance to developers lowers the chance that a change introduces a weakness (Variance Management: Reduce Variance Probability).'),
  M1015: m(['resistance'], R.harden),
  M1016: m(['controlMonitoring'], R.vulnFind),
  M1017: m(['ensureCapability', 'resistance'], 'Training gives people the skills to act as intended (Decision Support: Ensure Capability); a trained user is the Standard’s example of a human Resistance control (§3.1.3).'),
  M1018: m(['resistance'], R.harden),
  M1019: m(['threatIntelligence', 'provideThreatData'], 'Tracks changes in the threat landscape (Variance Management: Threat Intelligence, §4.2.1) and supplies threat data to decisions (§5.1.3.1.2).'),
  M1020: m(['visibility'], 'Decrypts traffic for inspection — evidence that would otherwise be unreadable (Visibility).'),
  M1021: m(['avoidance'], R.isolateAvoid),
  M1022: m(['resistance'], R.isolateResist),
  M1024: m(['resistance'], R.isolateResist),
  M1025: m(['resistance'], R.harden),
  M1026: m(['resistance'], R.harden),
  M1027: m(['resistance'], R.harden),
  M1028: m(['resistance'], R.harden),
  M1029: m(['resilience', 'visibility'], 'Data and logs kept off-host survive deletion on the host — evidence remains (Visibility) and data can be restored (Resilience).'),
  M1030: m(['avoidance'], 'Segmentation keeps threats in outer zones from reaching inner assets — the Overview’s architectural defence-in-depth, which it names as Avoidance.'),
  M1031: m(['resistance', 'recognition'], 'Intrusion prevention recognises malicious traffic and blocks it (Recognition, Resistance).'),
  M1032: m(['resistance'], R.harden),
  M1033: m(['resistance'], R.isolateResist),
  M1034: m(['resistance'], R.isolateResist),
  M1035: m(['avoidance'], R.isolateAvoid),
  M1036: m(['resistance'], R.harden),
  M1037: m(['avoidance'], R.isolateAvoid),
  M1038: m(['resistance'], R.isolateResist),
  M1039: m(['resistance'], R.isolateResist),
  M1040: m(['resistance', 'recognition'], 'Recognises malicious behaviour on the endpoint and blocks it (Recognition, Resistance).'),
  M1041: m(['resistance'], R.harden),
  M1042: m(['avoidance'], 'Removing the feature removes the path — the threat has nothing to make contact with (Avoidance).'),
  M1043: m(['resistance'], R.harden),
  M1044: m(['resistance'], R.isolateResist),
  M1045: m(['resistance'], R.harden),
  M1046: m(['resistance'], R.harden),
  M1047: m(['controlMonitoring'], 'Audits find controls that have drifted from their intended state (Variance Management: Control Monitoring, §4.2.2).'),
  M1048: m(['resistance'], R.isolateResist),
  M1049: m(['resistance', 'visibility', 'recognition'], 'The Standard lists anti-malware under Visibility and its signatures under Recognition; it also blocks (Resistance).'),
  M1050: m(['resistance'], R.harden),
  M1051: m(['implementation', 'resistance'], R.patch),
  M1052: m(['resistance'], R.harden),
  M1053: m(['resilience'], 'Backups restore data after an event — the Standard’s Resilience example (§3.3.2).'),
  M1054: m(['resistance'], R.harden),
  M1055: NOT_A_CONTROL,
  M1056: Object.freeze({ functions: Object.freeze([]), rationale: 'ATT&CK marks the technique as occurring before compromise, outside the enterprise’s control — not a control, so no function.', notAControl: true }),
  M1057: m(['resistance', 'recognition'], 'Recognises sensitive data leaving and blocks it (Recognition, Resistance).'),
  M1060: m(['resilience'], 'Keeps operations communicating when primary channels are compromised (Resilience).'),
};

const ICS_ONLY = {
  M0800: m(['resistance'], R.harden),
  M0801: m(['resistance'], R.harden),
  M0802: m(['resistance'], R.harden),
  M0803: m(['resistance', 'recognition'], 'Recognises sensitive data leaving and blocks it (Recognition, Resistance).'),
  M0804: m(['resistance'], R.harden),
  M0805: m(['lossReduction'], 'Mechanical safety layers limit the physical damage when control is lost (Loss Reduction).'),
  M0806: m(['avoidance'], 'Less wireless reach means fewer places a threat can make contact from (Avoidance).'),
  M0807: m(['avoidance'], R.isolateAvoid),
  M0808: m(['resistance'], R.harden),
  M0809: m(['deterrence', 'resistance'], 'Withholding operational detail obscures what an asset is worth and how to attack it — the Standard lists "Obfuscation of asset value" under Deterrence (§3.1.2).'),
  M0810: m(['resilience'], 'Keeps operations communicating when primary channels are compromised (Resilience).'),
  M0811: m(['resilience'], 'Redundant services keep the process running through a failure (Resilience).'),
  M0812: m(['lossReduction'], 'Safety instrumented systems drive the process to a safe state, limiting the harm an event causes (Loss Reduction).'),
  M0813: m(['resistance'], R.harden),
  M0814: m(['resistance'], R.harden),
  M0815: m(['resilience'], 'Watchdogs restart hung components to restore normal operation (Resilience).'),
  M0816: NOT_A_CONTROL,
  M0817: m(['reduceVarianceProbability'], 'Vetting suppliers lowers the chance that new components arrive weakened or compromised (Reduce Variance Probability).'),
  M0818: m(['resistance'], R.harden),
};

/** ICS M09NN mirrors Enterprise M10NN by name; these are the mirrored ids present in ICS. */
const ICS_MIRRORED = ['M0913', 'M0915', 'M0916', 'M0917', 'M0918', 'M0919', 'M0920', 'M0921', 'M0922', 'M0924',
  'M0926', 'M0927', 'M0928', 'M0930', 'M0931', 'M0932', 'M0934', 'M0935', 'M0936', 'M0937', 'M0938', 'M0941',
  'M0942', 'M0944', 'M0945', 'M0946', 'M0947', 'M0948', 'M0949', 'M0950', 'M0951', 'M0953', 'M0954'];

/** @type {Readonly<Record<string, Mapping>>} */
export const MITIGATION_TO_FAIR_CAM = Object.freeze({
  ...ENTERPRISE,
  ...ICS_ONLY,
  ...Object.fromEntries(ICS_MIRRORED.map((id) => [id, ENTERPRISE[`M10${id.slice(3)}`]])),
});

/**
 * Default function per D3FEND tactic — used ONLY for a countermeasure id that
 * is not in D3FEND_TO_FAIR_CAM yet (a new upstream id from the weekly D3FEND
 * sync). Such ids are classified by this rule and flagged `defaultRule`, so the
 * UI can say "default rule, not reviewed" and scripts/check-fair-cam-coverage.mjs
 * lists them for someone to classify properly.
 */
export const D3FEND_TACTIC_DEFAULT = Object.freeze({
  Model: 'provideAssetData',
  Harden: 'resistance',
  Detect: 'recognition',
  Isolate: 'resistance',
  Deceive: 'recognition',
  Evict: 'eventTermination',
  Restore: 'resilience',
});

/**
 * @typedef {Object} CoverageInput   one technique as the coverage SQL returns it
 * @property {string[]} mitigations          ATT&CK mitigation ids (sub-techniques rolled up)
 * @property {string[]} d3fend               "D3-XXX|Tactic" pairs
 * @property {number} dataComponents
 * @property {number} detectionStrategies
 * @property {number} sigmaRules
 *
 * @typedef {Object} CoverageRow
 * @property {Record<string, string[]>} functions   FAIR-CAM function id -> D3FEND / mitigation ids
 * @property {{ dataComponents: number, detectionStrategies: number, sigmaRules: number }} counts
 * @property {string[]} defaultRule   D3FEND ids classified by the tactic default (not reviewed)
 * @property {string[]} unmapped      ids with no classification (Mobile/ATLAS mitigations, unknown tactics)
 */

/**
 * Classify one technique's candidate controls into FAIR-CAM functions.
 * Server-side only (the API route); the tables never ship to the browser.
 * Data components, detection strategies and Sigma rules are counts, kept
 * separate from the id lists: they are whole sources, not controls.
 *
 * @param {CoverageInput} input
 * @returns {CoverageRow}
 */
export function classifyCoverageRow({ mitigations = [], d3fend = [], dataComponents = 0, detectionStrategies = 0, sigmaRules = 0 }) {
  /** @type {Record<string, Set<string>>} */
  const fns = {};
  const add = (fn, id) => { (fns[fn] ??= new Set()).add(id); };
  /** @type {string[]} */ const defaultRule = [];
  /** @type {string[]} */ const unmapped = [];

  for (const id of mitigations) {
    const row = MITIGATION_TO_FAIR_CAM[id];
    if (!row) { unmapped.push(id); continue; }
    for (const fn of row.functions) add(fn, id);
  }
  for (const pair of d3fend) {
    const [id, tactic = ''] = pair.split('|');
    if (!/^D3-/.test(id)) continue;
    const row = D3FEND_TO_FAIR_CAM[id];
    if (row) { for (const fn of row.functions) add(fn, id); continue; }
    const fallback = D3FEND_TACTIC_DEFAULT[tactic];
    if (fallback) { add(fallback, id); defaultRule.push(id); } else unmapped.push(id);
  }
  return {
    functions: Object.fromEntries(Object.entries(fns).map(([k, v]) => [k, [...v].sort()])),
    counts: { dataComponents, detectionStrategies, sigmaRules },
    defaultRule: [...new Set(defaultRule)].sort(),
    unmapped: [...new Set(unmapped)].sort(),
  };
}
