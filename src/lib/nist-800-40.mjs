// src/lib/nist-800-40.mjs — pure data, no React. Tested by
// scripts/lib/nist-800-40.test.mjs (control-id format, list sizes).
//
// NIST SP 800-40 Rev. 4, as a reference page under /frameworks.
//
// WHERE THE TECHNIQUE LINK COMES FROM
// The publication cites no ATT&CK technique. It does, in its own "Mappings to
// NIST Guidance and Frameworks" appendix, name the eight SP 800-53 Rev. 5
// controls "most important for enterprise patch management planning". This
// site already carries CTID's SP 800-53 -> ATT&CK mappings (/frameworks/nist),
// so 800-40 reaches techniques in two sourced hops — NIST's list, then CTID's
// mapping — with no judgement of ours in between. That is the only bridge the
// page draws. A per-technique "patching" panel was considered and rejected:
// CM-2 alone maps to ~290 techniques, so it would sit on almost every technique
// page and say nothing about any of them.
//
// The CSF subcategories in the same appendix are CSF 1.1 identifiers (ID.AM-1,
// PR.IP-12, …). They are listed as published; this file does not translate them
// to CSF 2.0, because NIST's own 1.1 -> 2.0 mapping is many-to-many and the
// translation would be ours.
//
// RIGHTS
// A NIST publication: a work of the US Government, not subject to copyright in
// the United States. Section summaries below are paraphrased; the control and
// subcategory titles are quoted.

export const NIST_800_40_SOURCE = {
  id: 'SP 800-40 Rev. 4',
  title: 'Guide to Enterprise Patch Management Planning: Preventive Maintenance for Technology',
  authors: 'Murugiah Souppaya, Karen Scarfone',
  published: 'April 2022',
  doi: 'https://doi.org/10.6028/NIST.SP.800-40r4',
  csrc: 'https://csrc.nist.gov/pubs/sp/800/40/r4/final',
  companion: { id: 'SP 1800-31', title: 'Improving Enterprise Patching for General IT Systems', url: 'https://csrc.nist.gov/pubs/sp/1800/31/final' },
};

/** @typedef {{ key: 'accept' | 'mitigate' | 'transfer' | 'avoid', label: string, summary: string }} RiskResponse */

/** §2.1 — the four risk responses. Patching is one form of "mitigate". */
/** @type {readonly RiskResponse[]} */
export const RISK_RESPONSES = [
  { key: 'accept', label: 'Accept', summary: 'Rely on existing controls, or judge the impact low enough that nothing more is needed. The default for any software until a response is chosen.' },
  { key: 'mitigate', label: 'Mitigate', summary: 'Remove the vulnerability (patch, update, upgrade, disable the feature) and/or add controls that make exploitation harder, such as segmentation.' },
  { key: 'transfer', label: 'Transfer', summary: 'Share the consequences with another party: cyber insurance, or moving to SaaS where the provider patches.' },
  { key: 'avoid', label: 'Avoid', summary: 'Remove the attack surface: uninstall the software, decommission the asset, or disable the capability.' },
];

/** §2.2 — the software vulnerability management life cycle. Step 3 has four phases. */
export const LIFE_CYCLE = [
  { step: 1, label: 'Know', summary: 'Know when new vulnerabilities affect your assets — which requires knowing the assets, their software and versions down to packages, and following vulnerability feeds.' },
  { step: 2, label: 'Plan', summary: 'Assess the risk, choose the response (or combination), and decide how to carry it out.' },
  { step: 3, label: 'Execute', summary: 'Prepare (acquire, validate, test, schedule) → implement (deploy, install, reconfigure) → verify it took effect → continuously monitor that it stays in place.' },
];

/**
 * @typedef {Object} Scenario
 * @property {1 | 2 | 3 | 4} n
 * @property {'routine' | 'emergency-patch' | 'emergency-mitigation' | 'unpatchable'} key
 * @property {string} label
 * @property {string} when
 * @property {string} plan
 */

/**
 * §3.3 risk-response scenarios, each with the §3.5 maintenance-plan guidance.
 * Scenarios 2 and 3 are where the KEV catalogue comes in: the publication names
 * it (§3.5) and BOD 22-01's two-week federal remediation window.
 */
/** @type {readonly Scenario[]} */
export const SCENARIOS = [
  { n: 1, key: 'routine', label: 'Routine patching', when: 'Patches on a regular release cycle, not elevated to emergency. Most patching; most often postponed.', plan: 'Phased deployment: canary assets first, then expand. Flexible install window with forced installation after a grace period.' },
  { n: 2, key: 'emergency-patch', label: 'Emergency patching', when: 'A severe vulnerability, or one being actively exploited. May be part of incident response.', plan: 'The routine approach on an accelerated schedule: minutes-to-hours of canary checks, then deployment within hours or days.' },
  { n: 3, key: 'emergency-mitigation', label: 'Emergency mitigation', when: 'The same crisis, but no usable patch yet — or the patch is flawed, disruptive or compromised.', plan: 'Pre-planned, automatable mitigations (disable functionality, isolate the asset), each with a schedule for replacing it by the permanent fix and removing it.' },
  { n: 4, key: 'unpatchable', label: 'Unpatchable assets', when: 'End-of-life software, assets that cannot take updates, or assets that must run uninterrupted.', plan: 'Pre-approved long-term mitigations per maintenance group (micro-segmentation, software-defined perimeters per SP 800-207), plus targeted mitigations for specific vulnerabilities; reassess risk and cost-benefit periodically.' },
];

/**
 * @typedef {Object} MaintenanceGroupExample
 * @property {string} label
 * @property {string} software
 * @property {string} outage
 * @property {string} mitigations
 * @property {'Moderate' | 'High'} impact
 */

/**
 * §3.4 — NIST's six simplified example maintenance groups. Quoted closely:
 * these are the publication's own illustrations, and the point of showing them
 * is that "legacy OT" is a GROUP with a plan, not an exception.
 */
/** @type {readonly MaintenanceGroupExample[]} */
export const MAINTENANCE_GROUP_EXAMPLES = [
  { label: 'Mobile workforce laptops for standard end users', software: 'Firmware, operating systems, client applications', outage: 'Tolerant to downtime', mitigations: 'Endpoint security controls on the laptops', impact: 'Moderate' },
  { label: 'On-premises datacenter (servers, network equipment, storage)', software: 'Firmware, operating systems, server applications', outage: 'Scheduled outage windows for all non-emergency situations', mitigations: 'Network-based access restriction plus on-asset controls', impact: 'High' },
  { label: 'Legacy OT assets', software: 'None — no longer supported, cannot be patched', outage: 'Scheduled outage windows for all non-emergency situations', mitigations: 'Network isolation, physical security controls', impact: 'High' },
  { label: 'Smartphones for the mobile workforce', software: 'Operating systems and mobile apps', outage: 'Tolerant to downtime', mitigations: 'Mobile device security controls', impact: 'Moderate' },
  { label: 'On-premises servers for automated software testing', software: 'Firmware, server OSs, virtualization, guest OSs, server and client applications', outage: 'Usually tolerant to downtime', mitigations: 'Network-based access restriction plus on-asset controls', impact: 'Moderate' },
  { label: 'Containers with customer-facing applications in the public cloud', software: 'Container operating systems, application modules', outage: 'Highly tolerant to downtime', mitigations: 'Controls on the container operating system', impact: 'High' },
];

/** §3 — the four principles the recommendations support. */
export const PRINCIPLES = [
  { label: 'Problems are inevitable; be prepared for them', summary: 'Plan to handle the occasional bad patch instead of delaying every patch for fear of one.' },
  { label: 'Simplify decision making', summary: 'Decide responses in advance per group and scenario; per-vulnerability risk assessment does not scale.' },
  { label: 'Rely on automation', summary: 'The volume of assets, software and patches — and emergencies — cannot be handled by hand.' },
  { label: 'Start improvements now', summary: 'Some changes take years; others can start today.' },
];

/** §3 — the seven recommendations, in the publication's order. */
export const RECOMMENDATIONS = [
  { section: '3.1', label: 'Reduce patching-related disruptions' },
  { section: '3.2', label: 'Inventory your software and assets' },
  { section: '3.3', label: 'Define risk response scenarios' },
  { section: '3.4', label: 'Assign each asset to a maintenance group' },
  { section: '3.5', label: 'Define maintenance plans for each maintenance group' },
  { section: '3.6', label: 'Choose actionable enterprise-level patching metrics' },
  { section: '3.7', label: 'Consider software maintenance in procurement' },
];

/**
 * §3.6 — the shape of NIST's notional metrics matrix (Table 1). The numbers in
 * the publication are illustrative, so only the axes and the three measures are
 * reproduced; SP 800-55 is the measurement guidance it points toward.
 */
export const METRICS_MATRIX = {
  rows: 'Vulnerability importance (low · medium · high · critical)',
  columns: 'Asset importance (low · moderate · high)',
  measures: ['% patched by the maintenance plan’s deadline', 'mean time to patch', 'median time to patch'],
  caution: 'Single-number metrics such as "90% of assets patched" are not actionable: they say nothing about which assets and which vulnerabilities make up the other 10%.',
  measurementGuide: { id: 'SP 800-55 Vol. 1 & 2', url: 'https://csrc.nist.gov/pubs/sp/800/55/v1/final' },
};

/**
 * @typedef {Object} ControlRef
 * @property {string} id      As published (CM-2).
 * @property {string} siteId  The zero-padded form this site's 800-53 tables use
 *   (CM-02). The API route accepts the unpadded form too and then finds no rows,
 *   which would read as a real zero — three of these eight controls really are
 *   zero — so the padded id is stored, and tested, rather than derived.
 * @property {string} title
 */

/** Appendix — the eight SP 800-53 Rev. 5 controls NIST names for patch management planning. */
/** @type {readonly ControlRef[]} */
export const SP800_53_CONTROLS = [
  { id: 'CM-2', siteId: 'CM-02', title: 'Baseline Configuration' },
  { id: 'CM-3', siteId: 'CM-03', title: 'Configuration Change Control' },
  { id: 'CM-8', siteId: 'CM-08', title: 'System Component Inventory' },
  { id: 'RA-7', siteId: 'RA-07', title: 'Risk Response' },
  { id: 'SI-2', siteId: 'SI-02', title: 'Flaw Remediation' },
  { id: 'SR-2', siteId: 'SR-02', title: 'Supply Chain Risk Management Plan' },
  { id: 'SR-3', siteId: 'SR-03', title: 'Supply Chain Controls and Processes' },
  { id: 'SR-5', siteId: 'SR-05', title: 'Acquisition Strategies, Tools, and Methods' },
];

/** Appendix — CSF 1.1 subcategories, as published (not translated to CSF 2.0). */
export const CSF_11_SUBCATEGORIES = [
  { id: 'ID.AM-1', title: 'Physical devices and systems within the organization are inventoried' },
  { id: 'ID.AM-2', title: 'Software platforms and applications within the organization are inventoried' },
  { id: 'ID.AM-4', title: 'External information systems are catalogued' },
  { id: 'ID.AM-5', title: 'Resources are prioritized based on their classification, criticality, and business value' },
  { id: 'ID.BE-3', title: 'Priorities for organizational mission, objectives, and activities are established and communicated' },
  { id: 'ID.BE-5', title: 'Resilience requirements to support delivery of critical services are established for all operating states' },
  { id: 'ID.GV-3', title: 'Legal and regulatory requirements regarding cybersecurity are understood and managed' },
  { id: 'ID.RA-5', title: 'Threats, vulnerabilities, likelihoods, and impacts are used to determine risk' },
  { id: 'ID.RA-6', title: 'Risk responses are identified and prioritized' },
  { id: 'ID.SC-1', title: 'Cyber supply chain risk management processes are identified, established, assessed, managed, and agreed to by organizational stakeholders' },
  { id: 'PR.IP-1', title: 'A baseline configuration of information technology/industrial control systems is created and maintained' },
  { id: 'PR.IP-3', title: 'Configuration change control processes are in place' },
  { id: 'PR.IP-12', title: 'A vulnerability management plan is developed and implemented' },
];

/** §3.7 — NIST's sample procurement questionnaire, condensed to its eight questions. */
export const PROCUREMENT_QUESTIONS = [
  'Will you release updates for this software to address vulnerabilities?',
  'How many patches, updates and upgrades per year, how quickly per vulnerability, bundled or separate, how many emergencies?',
  'For how many years will you correct vulnerabilities in it?',
  'Regular schedule, as needed, or both — and what schedule?',
  'Do you have a vulnerability disclosure and incident response programme, and how transparent are you?',
  'When a vulnerability is public but unpatched, how should customers protect themselves — will you ship an emergency mitigation?',
  'How disruptive is patching: restart the software, reboot the asset?',
  'How do you test patches, how often do they cause significant issues, and can they be rolled back?',
];
