// src/lib/fair-cam.mjs — pure data, no React. Tested by scripts/lib/fair-cam.test.mjs.
//
// The FAIR Controls Analytics Model (FAIR-CAM™) v1.0 ontology, VERBATIM.
//
// LICENCE AND WHY THIS FILE IS QUOTE-ONLY
// FAIR-CAM is published by the FAIR Institute under Creative Commons
// Attribution-NonCommercial-NoDerivatives 4.0 (Standard §1.2): it may be copied
// and redistributed "as a framework" for non-commercial use with credit and a
// link to the licence, users must be pointed to http://www.fairinstitute.org/FAIR-CAM/,
// and modified versions may not be distributed. So every string in this file
// marked as a quote — names, definitions, units, relationship statements — is
// copied character-for-character from the Standard Artifact v1.0 (15 January
// 2025) or the "An Overview of FAIR-CAM" white paper, with its section number,
// and must never be paraphrased, shortened or "improved" here. Anything this
// site says ABOUT FAIR-CAM belongs in the views, in our own words, visibly
// separate. Which D3FEND / ATT&CK controls serve which function is this site's
// curation and lives in src/lib/fair-cam-mappings.mjs, never here.
//
// Read from the PDFs on 2026-10-09 (text extraction, line-wrapping undone).
// scripts/lib/fair-cam.test.mjs checks every quoted field against that extract
// (docs/research/, local only) when it is present.

export const FAIR_CAM_SOURCE = Object.freeze({
  name: 'FAIR Controls Analytics Model (FAIR-CAM™)',
  version: '1.0',
  published: '15 January 2025',
  publisher: 'FAIR Institute',
  copyright: '©2025 FAIR Institute',
  licence: 'Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International (CC BY-NC-ND 4.0)',
  licenceShort: 'CC BY-NC-ND 4.0',
  licenceUrl: 'https://creativecommons.org/licenses/by-nc-nd/4.0/legalcode',
  /** The Standard asks users to refer here "to ensure that users are employing the most up-to-date guidance". */
  referenceUrl: 'http://www.fairinstitute.org/FAIR-CAM/',
  standardPdf: 'https://www.fairinstitute.org/hubfs/Standards%20Artifacts/FAIR%20Controls%20Analytics%20Model%20(FAIR-CAM)%20Standard%20V1.0%20(January%202025).pdf',
  overviewPdf: 'https://www.fairinstitute.org/hubfs/An%20Overview%20of%20FAIR-CAM.pdf',
});

/** One sentence every surface showing FAIR-CAM terms renders. */
export const FAIR_CAM_ATTRIBUTION =
  'FAIR Controls Analytics Model (FAIR-CAM™) Standard Artifact v1.0, ©2025 FAIR Institute — ' +
  'licensed CC BY-NC-ND 4.0. FAIR-CAM names, definitions, units and relationships are quoted unmodified.';

/**
 * @typedef {'LEC' | 'VMC' | 'DSC'} DomainId
 * @typedef {Object} FairCamDomain
 * @property {DomainId} id
 * @property {string} name     Quoted (the §3/§4/§5 headings).
 * @property {string} plural   Quoted (§1.3.3).
 * @property {string} effect   §2.2, quoted.
 *
 * @typedef {Object} FairCamFunction
 * @property {string} id         Stable key (ours).
 * @property {DomainId} domain
 * @property {string} group      The Standard's grouping heading, quoted.
 * @property {string} section    Standard section number.
 * @property {string} name       Quoted.
 * @property {string} definition Quoted function description.
 * @property {string} unit       Quoted unit of measurement.
 * @property {string} relation   Quoted relationships-and-dependencies statement.
 */

/** @type {readonly FairCamDomain[]} */
export const FAIR_CAM_DOMAINS = Object.freeze([
  { id: 'LEC', name: 'Loss Event Control', plural: 'Loss Event Controls', effect: 'By directly affecting the frequency or magnitude of loss (Loss Event Control functions)' },
  { id: 'VMC', name: 'Variance Management Control', plural: 'Variance Management Controls', effect: 'By affecting the reliability of controls (Variance Management Control functions)' },
  { id: 'DSC', name: 'Decision Support Control', plural: 'Decision Support Controls', effect: 'By affecting decisions (Decision Support Control functions)' },
]);


/** @type {readonly FairCamFunction[]} */
export const FAIR_CAM_FUNCTIONS = Object.freeze([
  // ── Loss Event Control (§3) ─────────────────────────────────────────────
  { id: 'avoidance', domain: 'LEC', group: 'Loss Event Prevention', section: '3.1.1', name: 'Avoidance',
    definition: 'Reduce the frequency of contact between threat agents and the assets they could adversely affect.',
    unit: '% reduction in contact frequency with threat agents',
    relation: 'The Avoidance function has a Boolean OR relationship with the Deterrence and Resistance functions. In other words, if controls serving any of these functions are in place and operating as intended, the probability of a loss event occurring is reduced accordingly. If multiple controls serving any of these functions are in place and operating as intended, then the effect of these controls is cumulative.' },
  { id: 'deterrence', domain: 'LEC', group: 'Loss Event Prevention', section: '3.1.2', name: 'Deterrence',
    definition: 'Reduce the probability of potentially harmful actions after a threat agent has come into contact with an asset.',
    unit: '% reduction in the probability that threat actors would choose to act in a way that could result in harm',
    relation: 'The Deterrence function has a Boolean OR relationship with the Avoidance and Resistance functions. In other words, if controls serving any one of these functions are in place and operating as intended, the probability of a loss event occurring is reduced accordingly. If multiple controls serving any of these functions are in place and operating as intended, then the effect of these controls is cumulative.' },
  { id: 'resistance', domain: 'LEC', group: 'Loss Event Prevention', section: '3.1.3', name: 'Resistance',
    definition: 'Reduce the likelihood that a threat agent’s action(s) will result in a loss event.',
    unit: '% probability of resisting potentially harmful actions by threat actors',
    relation: 'The Resistance function has a Boolean OR relationship with the Avoidance and Deterrence functions. In other words, if controls serving any one of these functions are in place and operating as intended, the probability of a loss event occurring is reduced accordingly. If multiple controls serving any of these functions are in place and operating as intended, then the effect of these controls is cumulative.' },
  { id: 'visibility', domain: 'LEC', group: 'Loss Event Detection', section: '3.2.1', name: 'Visibility',
    definition: 'Provide evidence of activity that may be anomalous or illicit.',
    unit: '% probability that the control provides access to the necessary information',
    relation: 'The Visibility function has a Boolean AND relationship with the Monitoring and Recognition functions. In other words, if controls serving any of these functions are sufficiently deficient, detection won’t occur, and the organization cannot mount a timely response.' },
  { id: 'monitoring', domain: 'LEC', group: 'Loss Event Detection', section: '3.2.2', name: 'Monitoring',
    definition: 'Review data provided by Visibility controls.',
    unit: 'Elapsed time between reviews',
    relation: 'The Monitoring function has a Boolean AND relationship with the Visibility and Recognition functions. In other words, if controls serving any of these functions are sufficiently deficient, detection won’t occur, and the organization cannot mount a timely response.' },
  { id: 'recognition', domain: 'LEC', group: 'Loss Event Detection', section: '3.2.3', name: 'Recognition',
    definition: 'Enable differentiation of normal activity/conditions from abnormal activity/conditions that may indicate a loss event has occurred or is in progress.',
    unit: '% probability that a loss event will be successfully differentiated from normal activities or conditions.',
    relation: 'The Recognition function has a Boolean AND relationship with the Visibility and Monitoring functions. In other words, if controls serving any of these functions are sufficiently deficient, detection won’t occur, and the organization cannot mount a timely response.' },
  { id: 'eventTermination', domain: 'LEC', group: 'Loss Event Response', section: '3.3.1', name: 'Event Termination',
    definition: 'Enable termination of threat agent activities that could continue to be harmful.',
    unit: 'The amount of time that expires between recognition that a loss event has occurred and the point at which control over the event has been achieved.',
    relation: 'Event Termination has a “weak” Boolean AND relationship with Resilience and Loss Reduction. In other words, deficiencies in one of these sub-functions will diminish overall Response efficacy but won’t necessarily inhibit it entirely.' },
  { id: 'resilience', domain: 'LEC', group: 'Loss Event Response', section: '3.3.2', name: 'Resilience',
    definition: 'Maintain or restore normal operations.',
    unit: 'The amount of time operating in a degraded mode.',
    relation: 'Resilience has a “weak” Boolean AND relationship with Event Termination and Loss Reduction. In other words, deficiencies in one of these sub-functions will diminish overall Response efficacy but won’t necessarily inhibit it entirely.' },
  { id: 'lossReduction', domain: 'LEC', group: 'Loss Event Response', section: '3.3.3', name: 'Loss Reduction',
    definition: 'Reduce the amount of realized losses from an event.',
    unit: 'Reduction of lost economic value (e.g., dollars, Euros, etc.).',
    relation: 'Loss Reduction has a “weak” Boolean AND relationship with Event Termination and Resilience. In other words, deficiencies in one of these sub-functions will diminish overall Response efficacy but won’t necessarily inhibit it entirely.' },

  // ── Variance Management Control (§4) ────────────────────────────────────
  { id: 'reduceChangeFrequency', domain: 'VMC', group: 'Variance Prevention', section: '4.1.1', name: 'Reduce Change Frequency',
    definition: 'Reduce the frequency of changes.',
    unit: 'Forecast or measured % reduction in the frequency of changes that could introduce variance',
    relation: 'Reducing Change Frequency has a Boolean OR relationship with Reducing Variance Probability based on the fact that reducing either will reduce the frequency of variance.' },
  { id: 'reduceVarianceProbability', domain: 'VMC', group: 'Variance Prevention', section: '4.1.2', name: 'Reduce Variance Probability',
    definition: 'Reduce the probability that changes will result in control degradation or failure.',
    unit: 'Forecast or measured % reduction in variance',
    relation: 'Reduce Variance Probability has a Boolean OR relationship with Reduce Change Frequency because variance can be independently reduced with either one.' },
  { id: 'threatIntelligence', domain: 'VMC', group: 'Variance Identification', section: '4.2.1', name: 'Threat Intelligence',
    definition: 'Identify changes in the threat landscape that diminish the efficacy of controls.',
    unit: 'Elapsed time between changes in the threat landscape and awareness of those changes.',
    relation: 'Threat Intelligence has a Boolean AND relationship with Variance Correction, given that you can’t account for changes in the threat landscape that you aren’t aware of.' },
  { id: 'controlMonitoring', domain: 'VMC', group: 'Variance Identification', section: '4.2.2', name: 'Control Monitoring',
    definition: 'Identify variance in control conditions.',
    unit: 'Elapsed time between changes in control conditions and the recognition of those changes.',
    relation: 'Controls Monitoring has a Boolean AND relationship with Variance Correction, given that you can’t correct variant conditions that you aren’t aware of. Consequently, if either one is deficient, the duration of variant conditions will persist.' },
  { id: 'treatmentSelection', domain: 'VMC', group: 'Variance Correction', section: '4.3.1', name: 'Treatment Selection and Prioritization',
    definition: 'Select and prioritize control variance corrections.',
    unit: 'Elapsed time from the identification of a variant condition until corrective actions begin.',
    relation: 'Boolean AND with Implementation' },
  { id: 'implementation', domain: 'VMC', group: 'Variance Correction', section: '4.3.2', name: 'Implementation',
    definition: 'Correct variant conditions.',
    unit: 'Elapsed time from initiation of corrective actions until their completion.',
    relation: 'Boolean AND with Treatment Selection and Prioritization' },

  // ── Decision Support Control (§5) ───────────────────────────────────────
  { id: 'definedExpectations', domain: 'DSC', group: 'Preventing Misaligned Decisions', section: '5.1.1', name: 'Defined Expectations',
    definition: 'Clearly define expectations and/or objectives.',
    unit: 'The probability that clear expectations and objectives have been defined.',
    relation: 'This has a Boolean AND relationship with the other DSC/Prevention control functions — i.e., even if the other functions are operating well, deficiencies in this function will increase the probability of misaligned decisions.' },
  { id: 'communicationOfExpectations', domain: 'DSC', group: 'Preventing Misaligned Decisions', section: '5.1.2', name: 'Communication of Expectations',
    definition: 'Communicate expectations to responsible personnel.',
    unit: 'The probability that expectations and objectives have been clearly communicated to decision-makers.',
    relation: 'This has a Boolean AND relationship with the other DSC/Prevention control functions — i.e., even if the other functions are operating well, deficiencies in this function will increase the probability of misaligned decisions.' },
  { id: 'provideAssetData', domain: 'DSC', group: 'Preventing Misaligned Decisions', section: '5.1.3.1.1', name: 'Provide Asset Data',
    definition: 'Provide data regarding the assets that are relevant to or affected by decisions.',
    unit: 'Probability that asset data used to support a decision is accurate.',
    relation: 'This has a Boolean AND relationship with the other DSC/Prevention control functions — i.e., even if the other functions are operating well, deficiencies in this function will increase the probability of misaligned decisions.' },
  { id: 'provideThreatData', domain: 'DSC', group: 'Preventing Misaligned Decisions', section: '5.1.3.1.2', name: 'Provide Threat Data',
    definition: 'Provide data regarding relevant threats.',
    unit: 'Probability that threat data used to support a decision is accurate.',
    relation: 'This has a Boolean AND relationship with the other DSC/Prevention control functions — i.e., even if the other functions are operating well, deficiencies in this function will increase the probability of misaligned decisions.' },
  { id: 'provideControlsData', domain: 'DSC', group: 'Preventing Misaligned Decisions', section: '5.1.3.1.3', name: 'Provide Controls Data',
    definition: 'Provide data regarding the condition of controls that are relevant to decisions.',
    unit: 'Probability that controls-related data used to support a decision is accurate.',
    relation: 'This has a Boolean AND relationship with the other DSC/Prevention control functions — i.e., even if the other functions are operating well, deficiencies in this function will increase the probability of misaligned decisions.' },
  { id: 'analysis', domain: 'DSC', group: 'Preventing Misaligned Decisions', section: '5.1.3.2', name: 'Analysis',
    definition: 'Synthesize asset, threat, and controls data and generate accurate results.',
    unit: 'Probability that an analysis model will generate accurate results provided that it has accurate data.',
    relation: 'This has a Boolean AND relationship with the other DSC/Prevention control functions — i.e., even if the other functions are operating well, deficiencies in this function will increase the probability of misaligned decisions.' },
  { id: 'reporting', domain: 'DSC', group: 'Preventing Misaligned Decisions', section: '5.1.3.3', name: 'Reporting',
    definition: 'Provide decision-makers with analysis results.',
    unit: 'Probability that useful analysis results are provided to decision-makers in time to support their decisions.',
    relation: 'This has a Boolean AND relationship with the other DSC/Prevention control functions — i.e., even if the other functions are operating well, deficiencies in this function will increase the probability of misaligned decisions.' },
  { id: 'ensureCapability', domain: 'DSC', group: 'Preventing Misaligned Decisions', section: '5.1.4', name: 'Ensure Capability',
    definition: 'Ensure that the decision-maker has the necessary skills, authority, and resources to make decisions that are aligned with the organization’s expectations and objectives.',
    unit: 'The probability that responsible persons will have the skills and resources necessary to act in a manner that is aligned with expectations.',
    relation: 'This has a Boolean AND relationship with the other DSC/Prevention control functions — i.e., even if the other functions are operating well, deficiencies in this function will increase the probability of misaligned decisions.' },
  { id: 'incentives', domain: 'DSC', group: 'Preventing Misaligned Decisions', section: '5.1.5', name: 'Incentives',
    definition: 'Motivate personnel to make decisions that are aligned with the organization’s expectations and objectives.',
    unit: 'The probability that appropriate incentives are in place to encourage well-aligned decisions.',
    relation: 'This has a Boolean AND relationship with the other DSC/Prevention control functions — i.e., even if the other functions are operating well, deficiencies in this function will increase the probability of misaligned decisions.' },
  { id: 'identifyingMisalignedDecisions', domain: 'DSC', group: 'Identifying Misaligned Decisions', section: '5.2', name: 'Identifying Misaligned Decisions',
    definition: 'Enable the identification of decisions that were not aligned with the expectations and objectives of the organization.',
    unit: 'The amount of elapsed time from when a misaligned decision was made and its identification.',
    relation: 'This has a Boolean AND relationship with the Defined Expectations function, which provides the baseline for comparing a current state versus a desired state.' },
  { id: 'correctingMisalignedDecisions', domain: 'DSC', group: 'Correcting Misaligned Decisions', section: '5.3', name: 'Correcting Misaligned Decisions',
    definition: 'Correct the causes and outcomes of misaligned decisions.',
    unit: 'The amount of elapsed time between when a misaligned decision was recognized and corrected.',
    relation: 'Because this function is fulfilled by controls within other functions, it is wholly dependent upon those other functions.' },
]);

/** Group-level relationship statements, quoted (§3, §4, §5 introductions). */
export const FAIR_CAM_GROUP_RELATIONS = Object.freeze([
  { domain: 'LEC', section: '3', text: 'Loss Event Detection and Loss Event Response have a Boolean AND relationship to one another — i.e., both must exist in order to mitigate the effects of a loss event.' },
  { domain: 'VMC', section: '4', text: 'Variance Identification and Variance Correction have a Boolean AND relationship to one another — i.e., both must exist in order to mitigate the effects of a loss event.' },
  { domain: 'DSC', section: '5', text: 'Misaligned Decision Identification and Misaligned Decision Correction have a Boolean AND relationship to one another — i.e., both must exist in order to mitigate the risk of poor decisions.' },
]);

/** Operational effectiveness attributes (§2.4), quoted. */
export const FAIR_CAM_EFFECTIVENESS = Object.freeze({
  intro: 'Capability, Coverage, and Reliability are the critical attributes for evaluating the Operational Effectiveness of controls (i.e., Control Maturity), particularly in the context of the FAIR Controls Analytics Model (FAIR-CAM).',
  attributes: [
    { name: 'Capability', text: 'A control’s inherent ability to perform its intended function in addressing specific aspects of risk.' },
    { name: 'Coverage', text: 'Measures the extent to which a control or set of controls applies to the assets, threats, or risk scenarios within the organization.' },
    { name: 'Reliability', text: 'Refers to the likelihood that a control will perform its intended function consistently and without failure when needed.' },
  ],
  /** From "An Overview of FAIR-CAM" — its own "Licensing and Use" section grants the same CC BY-NC-ND 4.0 licence. Quoted. */
  reliabilityFormula: 'Reliability = (1 − (VF/365))^VD',
  binaryOpEffFormula: 'OpEff = IntEff * Reliability',
  formulaNote: 'The formula below provides the percentage of time a control is in its intended state given VF and VD values (i.e., its “reliability”)',
  example: 'A binary control with a VF of once per year, and a VD of 36 days has an operational efficacy of roughly 91%.',
});

/** @param {string} id */
export function fairCamFunction(id) {
  return FAIR_CAM_FUNCTIONS.find((f) => f.id === id);
}
