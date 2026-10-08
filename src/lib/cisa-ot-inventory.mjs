// src/lib/cisa-ot-inventory.mjs — pure data + helpers, no React, no DOM.
// Tested by scripts/lib/cisa-ot-inventory.test.mjs.
//
// CISA's multinational OT asset-inventory guidance, and a crosswalk from its
// example sector taxonomies to the 18 ATT&CK for ICS assets (A0001-A0018).
//
// WHAT IS SOURCE AND WHAT IS OURS
// The steps, the 32 inventory fields with their priorities, and the sector
// taxonomy rows (criticality -> category -> item) are CISA's. The item texts
// are reproduced verbatim; they are short noun phrases from a TLP:CLEAR joint
// guide. The `assets`, `match` and `rationale` on each item are this project's
// curation. The guide carries no ATT&CK identifier anywhere, so any link from a
// CISA item to a technique is a judgement, and every page that shows one says so.
//
// THE MATCH RULE, applied the same way in all three sectors
//   direct  — the item names the same kind of device ATT&CK models as an asset
//             (CISA "RTUs" -> A0004; CISA "Protection relays" -> A0005, which
//             ATT&CK lists as an IED related asset).
//   partial — the item is a function or system that ATT&CK models only part of,
//             or that lives inside an asset class (fault isolation runs in
//             relays/IEDs; "OT communications infrastructure" is switches,
//             routers and gateways).
//   none    — physical process, power or facility equipment. ATT&CK for ICS
//             models no transformers, pumps, wellheads or HVAC plant, and
//             saying so is the answer. These rows are SHOWN, never dropped: a
//             crosswalk that hid its gaps would overstate its coverage.
// A process system ("Chemical dosing systems") is `none` even though a PLC
// probably runs it: CISA lists the controllers in their own rows (Control
// Systems), and mapping every process to "PLC" would double count and invent an
// architecture the guide does not describe.
//
// SCOPE
// Only the criticality taxonomies (oil & gas Tables 3-5, electricity Tables
// 7-9, water and wastewater Tables 11-13). The notional per-process-area lists
// (Tables 2, 6, 10) are the raw material CISA refined into those tables and
// are left out to avoid listing the same asset twice.
//
// Source: "Foundations for OT Cybersecurity: Asset Inventory Guidance for
// Owners and Operators", August 2025. Read from the 508c PDF on 2026-10-08.

import { buildProfileUrl } from './profile-url.mjs';

/**
 * @typedef {'oil-gas' | 'electricity' | 'water'} SectorKey
 * @typedef {'high' | 'medium' | 'low'} Criticality
 * @typedef {'direct' | 'partial' | 'none'} MatchKind
 *
 * @typedef {Object} TaxonomyItem
 * @property {string} key        Stable id, `<sector>:<slug>`.
 * @property {SectorKey} sector
 * @property {Criticality} criticality
 * @property {string} category   CISA's column heading, verbatim.
 * @property {string} item       CISA's cell text, verbatim.
 * @property {string[]} assets   ATT&CK ICS asset ids; empty when `match` is none.
 * @property {MatchKind} match
 * @property {string} rationale  Why this mapping (or why none).
 */

export const CISA_OT_SOURCE = Object.freeze({
  title: 'Foundations for OT Cybersecurity: Asset Inventory Guidance for Owners and Operators',
  publisher: 'CISA',
  coAuthors: ['EPA', 'NSA', 'FBI', "ASD's ACSC", 'Cyber Centre', 'BSI', 'NCSC-NL', 'NCSC-NZ'],
  published: 'August 2025',
  marking: 'TLP:CLEAR',
  page: 'https://www.cisa.gov/resources-tools/resources/foundations-ot-cybersecurity-asset-inventory-guidance-owners-and-operators',
  pdf: 'https://www.cisa.gov/sites/default/files/2025-08/joint-guide-foundations-for-OT-cybersecurity-asset-inventory-guidance_508c.pdf',
});

/** CISA's five steps (Figure 1), with a one-line summary of each. */
export const INVENTORY_STEPS = Object.freeze([
  { n: 1, title: 'Define scope and objectives', summary: 'Governance over asset management, roles for collecting and validating data, and the boundary of the programme: zones, facilities, systems, and what counts as an asset.' },
  { n: 2, title: 'Identify assets and collect attributes', summary: 'Physical inspection plus a logical survey, then the attributes for each asset, high-priority fields first.' },
  { n: 3, title: 'Create a taxonomy to categorize assets', summary: 'Classify by criticality and function, group functions into zones, organise communication pathways, then validate and visualise.' },
  { n: 4, title: 'Manage and collect data', summary: 'Keep the inventory current as assets and their attributes change.' },
  { n: 5, title: 'Implement life cycle management', summary: 'Track each asset from procurement to decommissioning, including support status and obsolescence.' },
]);

/**
 * Appendix A, Table 1 — the recommended inventory fields. `benefit` is a short
 * paraphrase of CISA's benefit column, not a quotation.
 *
 * `inApp` points at the page on this site that can use the field. Only four do,
 * and only where the link is literal: make/model/OS/firmware are what CVE
 * matching runs on, role/type is what the crosswalk below runs on, and logging
 * and network monitoring decide which ATT&CK data sources you can see.
 *
 * @type {ReadonlyArray<{ field: string, priority: Criticality, benefit: string,
 *                        inApp?: { label: string, href: string } }>}
 */
export const INVENTORY_FIELDS = Object.freeze([
  { field: 'Active/supported communication protocols', priority: 'high', benefit: 'Network-traffic analysis; start with assets that talk across the IT/OT perimeter or to SCADA over a WAN.' },
  { field: 'Asset criticality', priority: 'high', benefit: 'Manage assets by operational role, safety impact and exposure.' },
  { field: 'Asset number', priority: 'high', benefit: 'Unique organisational identifier.' },
  { field: 'Asset role/type', priority: 'high', benefit: 'Context and function on the network (engineering workstation, PLC, historian, switch/router, hypervisor host).', inApp: { label: 'crosswalk below', href: '#taxonomies' } },
  { field: 'Hostname', priority: 'high', benefit: 'Context, if naming conventions encode function.' },
  { field: 'IP address', priority: 'high', benefit: 'Network-traffic analysis.' },
  { field: 'Logging', priority: 'high', benefit: 'How the asset’s logs are collected, for detection and investigation.', inApp: { label: 'data sources', href: '/data-sources' } },
  { field: 'MAC address', priority: 'high', benefit: 'Manufacturer when not otherwise known (may only identify the network card).' },
  { field: 'Manufacturer', priority: 'high', benefit: 'Known vulnerabilities.', inApp: { label: 'applications / CVEs', href: '/applications' } },
  { field: 'Model', priority: 'high', benefit: 'Known vulnerabilities.', inApp: { label: 'applications / CVEs', href: '/applications' } },
  { field: 'Operating system', priority: 'high', benefit: 'Known vulnerabilities, where applicable.' },
  { field: 'Physical location/address', priority: 'high', benefit: 'Where to find the asset.' },
  { field: 'Ports/services', priority: 'high', benefit: 'Verify role and attack surface; costly to maintain, so start at the perimeter.' },
  { field: 'User accounts', priority: 'high', benefit: 'Which accounts are expected to use the asset.' },
  { field: 'Backup frequency/type', priority: 'medium', benefit: 'How often and how (full, incremental, differential).' },
  { field: 'Baseline image', priority: 'medium', benefit: 'Known-good image for post-incident recovery.' },
  { field: 'Department/owner', priority: 'medium', benefit: 'Who is responsible for the asset.' },
  { field: 'Distributor', priority: 'medium', benefit: 'Where the asset came from, if not the manufacturer.' },
  { field: 'Firmware/software version', priority: 'medium', benefit: 'Known vulnerabilities, where applicable.' },
  { field: 'OS version', priority: 'medium', benefit: 'Known vulnerabilities, where applicable.' },
  { field: 'Physical or virtual', priority: 'medium', benefit: 'Whether the asset is a physical device or a VM.' },
  { field: 'VLAN', priority: 'medium', benefit: 'The asset’s place in the network structure.' },
  { field: 'Antivirus/endpoint protection', priority: 'low', benefit: 'The asset’s ability to protect itself.' },
  { field: 'Date of manufacture', priority: 'low', benefit: 'Obsolescence.' },
  { field: 'Hypervisor', priority: 'low', benefit: 'Which hypervisor runs the VM, if applicable.' },
  { field: 'Local time zone', priority: 'low', benefit: 'Timelines in behaviour analysis.' },
  { field: 'Location within hypervisor', priority: 'low', benefit: 'Where the VM resides, if applicable.' },
  { field: 'Network monitoring', priority: 'low', benefit: 'How well communications to the asset are monitored.', inApp: { label: 'data sources', href: '/data-sources' } },
  { field: 'Notes/description', priority: 'low', benefit: 'Free-text context and history.' },
  { field: 'Primary communication method', priority: 'low', benefit: 'Wired, wireless, cellular, RF, satellite — scope of an incident and of the attack surface.' },
  { field: 'Serial number', priority: 'low', benefit: 'Unique identifier; some vendors require it for patches and support.' },
  { field: 'Time source', priority: 'low', benefit: 'NTP, GPS, atomic or local clock — losing it causes drift with real impact.' },
]);

/**
 * The 18 ATT&CK for ICS assets. Names are informational — everything joins on
 * the id, exactly as src/lib/purdue-registry.ts does.
 */
/** @type {Readonly<Record<string, string>>} */
export const ICS_ASSET_NAMES = Object.freeze({
  A0001: 'Workstation',
  A0002: 'Human-Machine Interface (HMI)',
  A0003: 'Programmable Logic Controller (PLC)',
  A0004: 'Remote Terminal Unit (RTU)',
  A0005: 'Intelligent Electronic Device (IED)',
  A0006: 'Data Historian',
  A0007: 'Control Server',
  A0008: 'Application Server',
  A0009: 'Data Gateway',
  A0010: 'Safety Controller',
  A0011: 'Virtual Private Network (VPN) Server',
  A0012: 'Jump Host',
  A0013: 'Field I/O',
  A0014: 'Routers',
  A0015: 'Switch',
  A0016: 'Firewall',
  A0017: 'Distributed Control System (DCS) Controller',
  A0018: 'Programmable Automation Controller (PAC)',
});

/** @type {ReadonlyArray<{ key: SectorKey, label: string, tables: string }>} */
export const SECTORS = Object.freeze([
  { key: 'oil-gas', label: 'Oil and natural gas', tables: 'Appendix B, Tables 3–5' },
  { key: 'electricity', label: 'Electricity', tables: 'Appendix C, Tables 7–9' },
  { key: 'water', label: 'Water and wastewater', tables: 'Appendix D, Tables 11–13' },
]);

/** @type {readonly Criticality[]} */
export const CRITICALITY_ORDER = Object.freeze(['high', 'medium', 'low']);

// Rationales repeated across sectors, kept in one place so the same CISA item
// is never argued two different ways.
const R = {
  physical: 'Physical process equipment. ATT&CK for ICS models the devices that control and monitor it, not the equipment itself.',
  power: 'Power supply equipment. Not modelled as an ATT&CK for ICS asset.',
  facility: 'Facility equipment. Not modelled as an ATT&CK for ICS asset; if a building automation system runs it, that system’s server is a Control Server (ATT&CK lists BMS/BAS among A0007’s related assets) and belongs in its own inventory row.',
  process: 'A process system, not a device. Its controllers, sensors and HMIs are separate rows in CISA’s own tables, so mapping it again would double count.',
  esd: 'ATT&CK lists "Emergency Shutdown Systems (ESD) controller" as a related asset of Safety Controller.',
  dcs: 'ATT&CK’s DCS Controller is the core of a DCS. The HMIs and servers in a DCS are CISA rows of their own (HMIs, operator workstations, SCADA), so only the controller is mapped here.',
  plc: 'Same device class.',
  scada: 'ATT&CK lists "Supervisory Control And Data Acquisition (SCADA) Server" as a related asset of Control Server.',
  rtu: 'Same device class.',
  historian: 'Same device class.',
  hmi: 'Same device class.',
  ows: 'ATT&CK lists "Operator Workstation (OWS)" as a related asset of HMI; engineering workstations would be A0001.',
  sensor: 'Sensors are Field I/O; ATT&CK lists "Smart Sensors" as a related asset.',
  switchRouter: 'Same device classes: Switch (A0015) and Routers (A0014).',
};

/** @type {readonly TaxonomyItem[]} */
export const TAXONOMY_ITEMS = Object.freeze([
  // ── Oil and natural gas — Appendix B ─────────────────────────────────────
  // Table 3: High-Criticality Assets
  { key: 'oil-gas:drilling-rigs', sector: 'oil-gas', criticality: 'high', category: 'Primary Production Systems', item: 'Drilling rigs', assets: [], match: 'none', rationale: R.physical },
  { key: 'oil-gas:wellheads', sector: 'oil-gas', criticality: 'high', category: 'Primary Production Systems', item: 'Wellheads', assets: [], match: 'none', rationale: R.physical },
  { key: 'oil-gas:subsea-equipment', sector: 'oil-gas', criticality: 'high', category: 'Primary Production Systems', item: 'Subsea equipment', assets: [], match: 'none', rationale: R.physical },
  { key: 'oil-gas:esd', sector: 'oil-gas', criticality: 'high', category: 'Safety Systems', item: 'Emergency shutdown systems (ESD)', assets: ['A0010'], match: 'direct', rationale: R.esd },
  { key: 'oil-gas:fire-gas', sector: 'oil-gas', criticality: 'high', category: 'Safety Systems', item: 'Fire and gas detection systems', assets: ['A0010', 'A0013'], match: 'partial', rationale: 'A safety function: its logic runs on a safety controller (A0010) and its detectors are Field I/O (A0013). The alarm panels and suppression hardware are not modelled.' },
  { key: 'oil-gas:bop', sector: 'oil-gas', criticality: 'high', category: 'Safety Systems', item: 'Blowout preventers (BOP)', assets: [], match: 'none', rationale: 'Mechanical well-control equipment. Its control panel is not a distinct ATT&CK asset; if it is driven by a safety controller, that controller is the ESD/safety row.' },
  { key: 'oil-gas:dcs', sector: 'oil-gas', criticality: 'high', category: 'Control Systems', item: 'DCS', assets: ['A0017'], match: 'direct', rationale: R.dcs },
  { key: 'oil-gas:plcs-critical', sector: 'oil-gas', criticality: 'high', category: 'Control Systems', item: 'PLCs for critical processes', assets: ['A0003'], match: 'direct', rationale: R.plc },
  { key: 'oil-gas:backup-generators', sector: 'oil-gas', criticality: 'high', category: 'Power Systems', item: 'Backup generators', assets: [], match: 'none', rationale: R.power },
  { key: 'oil-gas:ups', sector: 'oil-gas', criticality: 'high', category: 'Power Systems', item: 'Uninterruptible power supplies (UPS)', assets: [], match: 'none', rationale: R.power },
  // Table 4: Medium-Criticality Assets
  { key: 'oil-gas:separators', sector: 'oil-gas', criticality: 'medium', category: 'Processing Equipment', item: 'Separators (oil, gas, water)', assets: [], match: 'none', rationale: R.physical },
  { key: 'oil-gas:compressors', sector: 'oil-gas', criticality: 'medium', category: 'Processing Equipment', item: 'Compressors', assets: [], match: 'none', rationale: R.physical },
  { key: 'oil-gas:heat-exchangers', sector: 'oil-gas', criticality: 'medium', category: 'Processing Equipment', item: 'Heat exchangers', assets: [], match: 'none', rationale: R.physical },
  { key: 'oil-gas:condition-sensors', sector: 'oil-gas', criticality: 'medium', category: 'Monitoring Systems', item: 'Condition monitoring sensors (vibration, temperature, pressure)', assets: ['A0013'], match: 'direct', rationale: R.sensor },
  { key: 'oil-gas:historians', sector: 'oil-gas', criticality: 'medium', category: 'Monitoring Systems', item: 'Data historians', assets: ['A0006'], match: 'direct', rationale: R.historian },
  { key: 'oil-gas:scada', sector: 'oil-gas', criticality: 'medium', category: 'Communications Systems', item: 'SCADA systems', assets: ['A0007'], match: 'direct', rationale: R.scada },
  { key: 'oil-gas:rtus', sector: 'oil-gas', criticality: 'medium', category: 'Communications Systems', item: 'Remote terminal units (RTUs)', assets: ['A0004'], match: 'direct', rationale: R.rtu },
  { key: 'oil-gas:switches-routers', sector: 'oil-gas', criticality: 'medium', category: 'Networking Equipment', item: 'Switches and routers for process control networks', assets: ['A0015', 'A0014'], match: 'direct', rationale: R.switchRouter },
  // Table 5: Low-Criticality Assets
  { key: 'oil-gas:hvac', sector: 'oil-gas', criticality: 'low', category: 'Auxiliary Systems', item: 'Heating, ventilation, and air conditioning (HVAC) systems', assets: [], match: 'none', rationale: R.facility },
  { key: 'oil-gas:lighting', sector: 'oil-gas', criticality: 'low', category: 'Auxiliary Systems', item: 'Lighting systems', assets: [], match: 'none', rationale: R.facility },
  { key: 'oil-gas:env-monitoring', sector: 'oil-gas', criticality: 'low', category: 'Non-Critical Monitoring', item: 'Environmental monitoring (e.g., emissions tracking)', assets: ['A0013'], match: 'partial', rationale: 'The analyzers and sensors are Field I/O; the reporting software around them is not distinguished.' },
  { key: 'oil-gas:data-logging', sector: 'oil-gas', criticality: 'low', category: 'Non-Critical Monitoring', item: 'Non-essential data logging', assets: ['A0006'], match: 'partial', rationale: 'Data logging is a historian function (A0006); a standalone data logger may instead be Field I/O or a gateway.' },
  { key: 'oil-gas:operator-workstations', sector: 'oil-gas', criticality: 'low', category: 'Peripheral Devices', item: 'Operator workstations', assets: ['A0002'], match: 'direct', rationale: R.ows },
  { key: 'oil-gas:hmis', sector: 'oil-gas', criticality: 'low', category: 'Peripheral Devices', item: 'Non-critical human-machine interfaces (HMI)', assets: ['A0002'], match: 'direct', rationale: R.hmi },

  // ── Electricity — Appendix C ─────────────────────────────────────────────
  // Table 7: High-Criticality Assets
  { key: 'electricity:transformers', sector: 'electricity', criticality: 'high', category: 'Primary Equipment', item: 'Power transformers', assets: [], match: 'none', rationale: R.physical },
  { key: 'electricity:circuit-breakers', sector: 'electricity', criticality: 'high', category: 'Primary Equipment', item: 'Circuit breakers', assets: [], match: 'none', rationale: 'Switching equipment. The relays and IEDs that trip it are the Protection Systems rows.' },
  { key: 'electricity:switchgear', sector: 'electricity', criticality: 'high', category: 'Primary Equipment', item: 'Switchgear', assets: [], match: 'none', rationale: R.physical },
  { key: 'electricity:busbars', sector: 'electricity', criticality: 'high', category: 'Primary Equipment', item: 'Busbars', assets: [], match: 'none', rationale: R.physical },
  { key: 'electricity:protection-relays', sector: 'electricity', criticality: 'high', category: 'Protection Systems', item: 'Protection relays (over/under current), distance type (impedance, reactance), differential (current, voltage)', assets: ['A0005'], match: 'direct', rationale: 'ATT&CK lists "Protection Relay" as a related asset of Intelligent Electronic Device.' },
  { key: 'electricity:fault-isolation', sector: 'electricity', criticality: 'high', category: 'Protection Systems', item: 'Fault detection and isolation mechanisms', assets: ['A0005'], match: 'partial', rationale: 'A function rather than a device; in substations it runs in relays and other IEDs.' },
  { key: 'electricity:voltage-regulators', sector: 'electricity', criticality: 'high', category: 'Protection Systems', item: 'Voltage regulators', assets: ['A0005'], match: 'partial', rationale: 'The regulator is physical equipment; its controller is an IED.' },
  { key: 'electricity:dcs', sector: 'electricity', criticality: 'high', category: 'Control Systems', item: 'DCS', assets: ['A0017'], match: 'direct', rationale: R.dcs },
  { key: 'electricity:plcs-critical', sector: 'electricity', criticality: 'high', category: 'Control Systems', item: 'PLCs managing critical functions', assets: ['A0003'], match: 'direct', rationale: R.plc },
  { key: 'electricity:scada', sector: 'electricity', criticality: 'high', category: 'Control Systems', item: 'SCADA systems', assets: ['A0007'], match: 'direct', rationale: R.scada },
  { key: 'electricity:backup-generators', sector: 'electricity', criticality: 'high', category: 'Power Supply Systems', item: 'Backup generators', assets: [], match: 'none', rationale: R.power },
  { key: 'electricity:ups', sector: 'electricity', criticality: 'high', category: 'Power Supply Systems', item: 'UPS for critical equipment', assets: [], match: 'none', rationale: R.power },
  // Table 8: Medium-Criticality Assets
  { key: 'electricity:ct-vt-sensors', sector: 'electricity', criticality: 'medium', category: 'Monitoring and Measurement Devices', item: 'Current and voltage sensors', assets: ['A0013'], match: 'direct', rationale: R.sensor },
  { key: 'electricity:meters', sector: 'electricity', criticality: 'medium', category: 'Monitoring and Measurement Devices', item: 'Metering devices for energy and power quality', assets: ['A0005'], match: 'partial', rationale: 'Power-quality and substation meters are IEDs; simple revenue meters may be closer to Field I/O.' },
  { key: 'electricity:historians', sector: 'electricity', criticality: 'medium', category: 'Monitoring and Measurement Devices', item: 'Data historians for operational insights', assets: ['A0006'], match: 'direct', rationale: R.historian },
  { key: 'electricity:rtus', sector: 'electricity', criticality: 'medium', category: 'Communications Systems', item: 'RTUs', assets: ['A0004'], match: 'direct', rationale: R.rtu },
  { key: 'electricity:gateways', sector: 'electricity', criticality: 'medium', category: 'Communications Systems', item: 'Gateways', assets: ['A0009'], match: 'direct', rationale: 'Same device class: Data Gateway covers protocol translation and media conversion.' },
  { key: 'electricity:networking', sector: 'electricity', criticality: 'medium', category: 'Communications Systems', item: 'Networking equipment (switches, routers)', assets: ['A0015', 'A0014'], match: 'direct', rationale: R.switchRouter },
  { key: 'electricity:cooling', sector: 'electricity', criticality: 'medium', category: 'Environmental Control Systems', item: 'Cooling systems for transformers or control rooms', assets: [], match: 'none', rationale: R.facility },
  { key: 'electricity:hvac', sector: 'electricity', criticality: 'medium', category: 'Environmental Control Systems', item: 'HVAC', assets: [], match: 'none', rationale: R.facility },
  // Table 9: Low-Criticality Assets
  { key: 'electricity:lighting', sector: 'electricity', criticality: 'low', category: 'Facility Support Systems', item: 'Lighting systems for indoor and outdoor facilities', assets: [], match: 'none', rationale: R.facility },
  { key: 'electricity:building-security', sector: 'electricity', criticality: 'low', category: 'Facility Support Systems', item: 'Building security systems (non-critical zones)', assets: [], match: 'none', rationale: 'Physical security systems are not modelled as ATT&CK for ICS assets.' },
  { key: 'electricity:hmis', sector: 'electricity', criticality: 'low', category: 'Peripheral and Non-Critical Devices', item: 'HMIs for secondary or non-urgent systems', assets: ['A0002'], match: 'direct', rationale: R.hmi },
  { key: 'electricity:operator-workstations', sector: 'electricity', criticality: 'low', category: 'Peripheral and Non-Critical Devices', item: 'Operator workstations used for administrative tasks', assets: ['A0002'], match: 'direct', rationale: R.ows },
  { key: 'electricity:ambient-sensors', sector: 'electricity', criticality: 'low', category: 'Non-Critical Monitoring', item: 'Ambient temperature sensors', assets: ['A0013'], match: 'direct', rationale: R.sensor },
  { key: 'electricity:alarm-systems', sector: 'electricity', criticality: 'low', category: 'Non-Critical Monitoring', item: 'Alarm systems for minor operational thresholds', assets: ['A0008'], match: 'partial', rationale: 'ATT&CK lists "Alarm Collector" as a related asset of Application Server; the alarm annunciators themselves are not modelled.' },

  // ── Water and wastewater — Appendix D ────────────────────────────────────
  // Table 11: High-Criticality Assets
  { key: 'water:pumps', sector: 'water', criticality: 'high', category: 'Primary Treatment Systems', item: 'Pumps (e.g., intake, discharge, high-pressure)', assets: [], match: 'none', rationale: 'Physical process equipment. A pump’s variable frequency drive is Field I/O in ATT&CK (VFD is a related asset of A0013) and belongs in its own inventory row.' },
  { key: 'water:screens-clarifiers', sector: 'water', criticality: 'high', category: 'Primary Treatment Systems', item: 'Screens, clarifiers, and grit removal systems', assets: [], match: 'none', rationale: R.physical },
  { key: 'water:aeration', sector: 'water', criticality: 'high', category: 'Secondary Treatment Systems', item: 'Aeration systems', assets: [], match: 'none', rationale: R.process },
  { key: 'water:bio-reactors', sector: 'water', criticality: 'high', category: 'Secondary Treatment Systems', item: 'Biological treatment reactors', assets: [], match: 'none', rationale: R.physical },
  { key: 'water:esd', sector: 'water', criticality: 'high', category: 'Safety and Environmental Systems', item: 'Emergency shutdown systems', assets: ['A0010'], match: 'direct', rationale: R.esd },
  { key: 'water:chemical-dosing', sector: 'water', criticality: 'high', category: 'Safety and Environmental Systems', item: 'Chemical dosing systems for pH control or disinfection', assets: [], match: 'none', rationale: R.process },
  { key: 'water:spill-containment', sector: 'water', criticality: 'high', category: 'Safety and Environmental Systems', item: 'Spill containment systems', assets: [], match: 'none', rationale: R.physical },
  { key: 'water:scada', sector: 'water', criticality: 'high', category: 'Control Systems', item: 'SCADA systems', assets: ['A0007'], match: 'direct', rationale: R.scada },
  { key: 'water:dcs', sector: 'water', criticality: 'high', category: 'Control Systems', item: 'DCS for core processes', assets: ['A0017'], match: 'direct', rationale: R.dcs },
  { key: 'water:ot-comms', sector: 'water', criticality: 'high', category: 'Control Systems', item: 'OT communications infrastructure', assets: ['A0015', 'A0014', 'A0009'], match: 'partial', rationale: 'A category, not a device: switches, routers and gateways are the parts ATT&CK models; radio and cellular links are not.' },
  { key: 'water:backup-generators', sector: 'water', criticality: 'high', category: 'Power Systems', item: 'Backup generators', assets: [], match: 'none', rationale: R.power },
  { key: 'water:ups', sector: 'water', criticality: 'high', category: 'Power Systems', item: 'UPS', assets: [], match: 'none', rationale: R.power },
  // Table 12: Medium-Criticality Assets
  { key: 'water:online-analyzers', sector: 'water', criticality: 'medium', category: 'Water Quality Monitoring', item: 'Online analyzers for turbidity, chlorine, or dissolved oxygen', assets: ['A0013'], match: 'direct', rationale: R.sensor },
  { key: 'water:sampling-stations', sector: 'water', criticality: 'medium', category: 'Water Quality Monitoring', item: 'Sampling stations', assets: [], match: 'none', rationale: 'A physical sampling point; any online analyzer at it is the row above.' },
  { key: 'water:rtus', sector: 'water', criticality: 'medium', category: 'Communications Systems', item: 'RTUs', assets: ['A0004'], match: 'direct', rationale: R.rtu },
  { key: 'water:plcs', sector: 'water', criticality: 'medium', category: 'Communications Systems', item: 'PLCs', assets: ['A0003'], match: 'direct', rationale: 'Same device class. CISA files PLCs under Communications Systems in this sector; the category is kept as published.' },
  { key: 'water:switches', sector: 'water', criticality: 'medium', category: 'Networking Equipment', item: 'Network switches', assets: ['A0015'], match: 'direct', rationale: 'Same device class.' },
  { key: 'water:firewalls', sector: 'water', criticality: 'medium', category: 'Networking Equipment', item: 'Firewalls for process control systems', assets: ['A0016'], match: 'direct', rationale: 'Same device class.' },
  { key: 'water:sludge', sector: 'water', criticality: 'medium', category: 'Auxiliary Systems', item: 'Sludge management equipment (e.g., pumps, centrifuges)', assets: [], match: 'none', rationale: R.physical },
  { key: 'water:non-essential-pumping', sector: 'water', criticality: 'medium', category: 'Auxiliary Systems', item: 'Non-essential pumping systems (e.g., irrigation or utility water)', assets: [], match: 'none', rationale: R.physical },
  // Table 13: Low-Criticality Assets
  { key: 'water:hvac', sector: 'water', criticality: 'low', category: 'Facility Support Systems', item: 'HVAC', assets: [], match: 'none', rationale: R.facility },
  { key: 'water:lighting', sector: 'water', criticality: 'low', category: 'Facility Support Systems', item: 'Lighting systems for buildings', assets: [], match: 'none', rationale: R.facility },
  { key: 'water:hmis', sector: 'water', criticality: 'low', category: 'Peripheral Devices', item: 'HMIs for non-critical processes', assets: ['A0002'], match: 'direct', rationale: R.hmi },
  { key: 'water:operator-workstations', sector: 'water', criticality: 'low', category: 'Peripheral Devices', item: 'Operator workstations', assets: ['A0002'], match: 'direct', rationale: R.ows },
  { key: 'water:facility-sensors', sector: 'water', criticality: 'low', category: 'Non-Critical Monitoring', item: 'Sensors for ambient temperature, facility water usage, or general alarms', assets: ['A0013'], match: 'direct', rationale: R.sensor },
]);

/**
 * Every taxonomy item that lands on one ATT&CK ICS asset, in sector, then
 * criticality, then source order. Feeds the asset 360 card.
 *
 * @param {string} attackId
 * @returns {TaxonomyItem[]}
 */
export function itemsForAsset(attackId) {
  const sectorRank = Object.fromEntries(SECTORS.map((s, i) => [s.key, i]));
  const critRank = Object.fromEntries(CRITICALITY_ORDER.map((c, i) => [c, i]));
  return TAXONOMY_ITEMS
    .map((it, i) => ({ it, i }))
    .filter(({ it }) => it.assets.includes(attackId))
    .sort(
      (a, b) =>
        sectorRank[a.it.sector] - sectorRank[b.it.sector] ||
        critRank[a.it.criticality] - critRank[b.it.criticality] ||
        a.i - b.i,
    )
    .map(({ it }) => it);
}

/**
 * The distinct ATT&CK asset ids a set of items maps to, sorted. The OT threat
 * profile ranks techniques against exactly this set, so it is de-duplicated —
 * the profile's lift denominator is a count of distinct assets.
 *
 * @param {readonly TaxonomyItem[]} items
 * @returns {string[]}
 */
export function assetsForItems(items) {
  return [...new Set(items.flatMap((it) => it.assets))].sort();
}

/**
 * Items in one sector, grouped for display: criticality in CRITICALITY_ORDER,
 * then category in the order CISA's table lists it.
 *
 * @param {SectorKey} sector
 * @returns {Array<{ criticality: Criticality; categories: Array<{ category: string; items: TaxonomyItem[] }> }>}
 */
export function sectorTable(sector) {
  return CRITICALITY_ORDER.map((criticality) => {
    const rows = TAXONOMY_ITEMS.filter((it) => it.sector === sector && it.criticality === criticality);
    const categories = [...new Set(rows.map((r) => r.category))].map((category) => ({
      category,
      items: rows.filter((r) => r.category === category),
    }));
    return { criticality, categories };
  }).filter((g) => g.categories.length > 0);
}

/**
 * Per-sector coverage counts — how many of CISA's rows reach an ATT&CK asset.
 * Shown on the page so the share of `none` rows is a number, not an impression.
 *
 * @param {SectorKey} sector
 * @returns {{ total: number; direct: number; partial: number; none: number; assets: string[] }}
 */
export function sectorCoverage(sector) {
  const rows = TAXONOMY_ITEMS.filter((it) => it.sector === sector);
  return {
    total: rows.length,
    direct: rows.filter((r) => r.match === 'direct').length,
    partial: rows.filter((r) => r.match === 'partial').length,
    none: rows.filter((r) => r.match === 'none').length,
    assets: assetsForItems(rows),
  };
}

/**
 * The OT threat-profile link for a set of asset ids, built by the same tested
 * builder the profile panel's Apply uses, so the URL is exactly the one
 * `src/views/OtProfile.tsx` reads (`assets` as a CSV, `domain` always written).
 *
 * @param {readonly string[]} assetIds
 * @returns {string}
 */
export function otProfileHref(assetIds) {
  return buildProfileUrl({ sector: null, domain: 'ics-attack', params: { assets: [...assetIds].sort() } });
}

/**
 * The asset ids one sector's rows at one criticality reach. This, not the
 * whole sector, is what the page offers to rank: a whole sector reaches most
 * of the 18 assets, at which point the OT profile's lift (exposure over reach)
 * flattens to ~1 and says nothing. One criticality level is a plausible
 * "these are the assets we protect first" selection.
 *
 * @param {SectorKey} sector
 * @param {Criticality} criticality
 * @returns {string[]}
 */
export function assetsForCriticality(sector, criticality) {
  return assetsForItems(TAXONOMY_ITEMS.filter((it) => it.sector === sector && it.criticality === criticality));
}
