// src/lib/purdue-registry.ts
//
// Hand-curated Purdue Model layer over the 18 ATT&CK ICS assets (A0001..A0018).
// Mirrors the src/lib/scf-framework-registry.ts pattern: curation lives in git
// so it is reviewable in PRs, and is seeded into Postgres idempotently by
// scripts/backfill-ics-assets.mjs.
//
// WHY THIS FILE EXISTS: ATT&CK ships no Purdue/level/zone field on assets —
// verified against ics-attack.json, no such key exists on any x-mitre-asset
// object. The level placement is therefore necessarily curation, not data.
// Every placement carries a `rationale` so the judgement is auditable, and
// `source` records what it was derived from.
//
// SCOPE: ICS-only. There is deliberately no Enterprise-technique mapping —
// the group-mediated derivation was measured and carries no boundary signal
// (Jump Host 185 enterprise techniques vs PLC 143, i.e. a boundary asset and a
// deep-OT asset look identical). Claiming otherwise would be inventing content.
//
// Schema: scripts/migrate-ics-assets.sql
// Levels reference: NIST SP 800-82r3 (public domain) + ISA-95 / Purdue (PERA).

export type PurdueZone = 'ot' | 'dmz' | 'it';

/** Stable slug. `l3_5` is the industrial DMZ — a first-class level, not a hack. */
export type PurdueLevelKey = 'l0' | 'l1' | 'l2' | 'l3' | 'l3_5' | 'l4' | 'l5';

export interface PurdueLevel {
  level_key: PurdueLevelKey;
  label: string;
  zone: PurdueZone;
  description: string;
  /** Gaps of 10 leave room if a sub-level is ever added. int2 -> real JS number. */
  sort_order: number;
}

export interface AssetPlacement {
  /** ATT&CK asset ID, A0001..A0018. */
  attack_id: string;
  /** Name is informational only — the seeder joins on attack_id. */
  name: string;
  primary_level: PurdueLevelKey;
  /** Must include primary_level (DB enforces via the primary_in_spans CHECK). */
  spans_levels: PurdueLevelKey[];
  rationale: string;
}

export interface FlowRule {
  from_level: PurdueLevelKey;
  to_level: PurdueLevelKey;
  /**
   * TRUE means exactly one thing: a DIRECT, SINGLE-HOP network adjacency is
   * permitted. It is NOT a reachability claim — a pair reachable only by
   * terminating a session at the DMZ has direct_allowed=false and names that
   * level in broker_level, so no consumer can mistake brokered for adjacent.
   */
  direct_allowed: boolean;
  /** Non-null => reachable only by terminating a session at this level. */
  broker_level?: PurdueLevelKey;
  note?: string;
}

// ---------------------------------------------------------------------------
// Levels (7)
// ---------------------------------------------------------------------------

export const PURDUE_LEVELS: PurdueLevel[] = [
  { level_key: 'l0',   label: 'Physical Process',     zone: 'ot',  sort_order: 0,
    description: 'Sensors, actuators and field devices that act on the physical process.' },
  { level_key: 'l1',   label: 'Basic Control',        zone: 'ot',  sort_order: 10,
    description: 'Controllers that automate the process — PLCs, RTUs, IEDs, safety and DCS controllers.' },
  { level_key: 'l2',   label: 'Supervisory Control',  zone: 'ot',  sort_order: 20,
    description: 'Area supervisory control — HMIs, SCADA and control servers operators work through.' },
  { level_key: 'l3',   label: 'Site Operations',      zone: 'ot',  sort_order: 30,
    description: 'Site-wide production management — historians, MES and application servers.' },
  { level_key: 'l3_5', label: 'Industrial DMZ',       zone: 'dmz', sort_order: 35,
    description: 'Enforced buffer between OT and IT. All external access terminates here; DMZ hosts must not initiate into OT.' },
  { level_key: 'l4',   label: 'Business Logistics',   zone: 'it',  sort_order: 40,
    description: 'Site business systems — scheduling, logistics and plant-level IT.' },
  { level_key: 'l5',   label: 'Enterprise IT',        zone: 'it',  sort_order: 50,
    description: 'Corporate network — directory services, ERP and central data centres.' },
];

// ---------------------------------------------------------------------------
// Asset placements (18) — one per ATT&CK ICS asset
// ---------------------------------------------------------------------------
// `is_boundary` is NOT stored here: it is a generated column in Postgres,
// derived as ('l3_5' = ANY(spans_levels)), so it can never contradict the span.

export const ASSET_PLACEMENTS: AssetPlacement[] = [
  // --- Level 0 — Physical Process ---
  { attack_id: 'A0013', name: 'Field I/O', primary_level: 'l0', spans_levels: ['l0', 'l1'],
    rationale: 'I/O modules are the interface to sensors and actuators, sitting on the L0/L1 seam. Placed at L0 as the process-facing end; spans L1 because the modules are addressed by the controller.' },

  // --- Level 1 — Basic Control ---
  { attack_id: 'A0003', name: 'Programmable Logic Controller (PLC)', primary_level: 'l1', spans_levels: ['l1'],
    rationale: 'Canonical L1 basic-control device: executes control logic directly against field I/O.' },
  { attack_id: 'A0004', name: 'Remote Terminal Unit (RTU)', primary_level: 'l1', spans_levels: ['l1'],
    rationale: 'Field control device performing the same L1 role as a PLC at a remote outstation.' },
  { attack_id: 'A0005', name: 'Intelligent Electronic Device (IED)', primary_level: 'l1', spans_levels: ['l1'],
    rationale: 'Protection and control device in electric substations — L1 basic control.' },
  { attack_id: 'A0010', name: 'Safety Controller', primary_level: 'l1', spans_levels: ['l1'],
    rationale: 'Safety Instrumented System logic solver. Purdue places it at L1. Note that IEC 61511 practice commonly segregates the SIS into its own zone independent of the basic process control system; this model records the Purdue level only.' },
  { attack_id: 'A0017', name: 'Distributed Control System (DCS) Controller', primary_level: 'l1', spans_levels: ['l1', 'l2'],
    rationale: 'DCS controllers execute L1 control but are architecturally coupled to their L2 supervisory layer, so the span covers both.' },
  { attack_id: 'A0018', name: 'Programmable Automation Controller (PAC)', primary_level: 'l1', spans_levels: ['l1'],
    rationale: 'PLC-class controller with extended capability; same L1 basic-control role.' },

  // --- Level 2 — Supervisory Control ---
  { attack_id: 'A0002', name: 'Human-Machine Interface (HMI)', primary_level: 'l2', spans_levels: ['l2'],
    rationale: 'Operator-facing supervisory interface — the defining L2 asset.' },
  { attack_id: 'A0007', name: 'Control Server', primary_level: 'l2', spans_levels: ['l2'],
    rationale: 'SCADA/supervisory server aggregating controller data for the control room.' },
  { attack_id: 'A0001', name: 'Workstation', primary_level: 'l2', spans_levels: ['l2', 'l3'],
    rationale: 'ATT&CK folds the engineering workstation into this asset. EWS placement is site-dependent — L2 in control rooms, L3 where engineering sits with site operations — so the span covers both.' },
  { attack_id: 'A0015', name: 'Switch', primary_level: 'l2', spans_levels: ['l1', 'l2', 'l3'],
    rationale: 'Network fabric rather than a process device. Switches carry traffic throughout the OT zone, so the span is L1-L3 with L2 as the representative level.' },

  // --- Level 3 — Site Operations ---
  { attack_id: 'A0008', name: 'Application Server', primary_level: 'l3', spans_levels: ['l3'],
    rationale: 'Site-level application hosting within operations — L3 site operations.' },
  { attack_id: 'A0006', name: 'Data Historian', primary_level: 'l3', spans_levels: ['l3', 'l3_5'],
    rationale: 'Collects process data at L3, and is the asset most often replicated into the DMZ so enterprise consumers never touch the control network. The dual placement is the point: it speaks both OT protocols and IT databases, which is what makes it the classic IT/OT crossing point.' },
  { attack_id: 'A0014', name: 'Routers', primary_level: 'l3', spans_levels: ['l2', 'l3', 'l3_5', 'l4'],
    rationale: 'Infrastructure that routes between zones rather than residing in one. Span covers the levels whose traffic it carries; L3 chosen as representative.' },

  // --- Level 3.5 — Industrial DMZ ---
  { attack_id: 'A0012', name: 'Jump Host', primary_level: 'l3_5', spans_levels: ['l3_5'],
    rationale: 'The DMZ asset by definition — vendor, contractor and employee sessions terminate here rather than reaching OT directly.' },
  { attack_id: 'A0011', name: 'Virtual Private Network (VPN) Server', primary_level: 'l3_5', spans_levels: ['l3_5'],
    rationale: 'Remote-access termination point. Purdue requires inbound access to land in the DMZ, not inside the OT zone.' },
  { attack_id: 'A0009', name: 'Data Gateway', primary_level: 'l3_5', spans_levels: ['l2', 'l3', 'l3_5'],
    rationale: 'Protocol translation and store-and-forward between control networks and upper layers. Primary placement is the DMZ; the span reflects the OT levels it brokers for.' },
  { attack_id: 'A0016', name: 'Firewall', primary_level: 'l3_5', spans_levels: ['l3', 'l3_5', 'l4'],
    rationale: 'Enforcement device for the boundary itself. A two-firewall industrial DMZ places one at the OT edge and one at the IT edge, hence the L3-L4 span.' },
];

// ---------------------------------------------------------------------------
// Flow rules — all 42 ordered pairs (7 x 6), explicit, no inference
// ---------------------------------------------------------------------------
// Adjacency chain: l0 <-> l1 <-> l2 <-> l3 <-> l3_5 <-> l4 <-> l5
// Cross-zone traffic between OT (l2,l3) and IT (l4,l5) is never a direct hop —
// it is brokered at l3_5. L0/L1 have no enterprise path at all, brokered or not.

const NEVER_ENTERPRISE =
  'Purdue forbids any path between basic control and enterprise IT; not brokerable.';
const VIA_DMZ =
  'Cross-zone traffic must terminate at the industrial DMZ; no direct adjacency.';
const NOT_ADJACENT =
  'Not adjacent in the Purdue chain; traffic transits the intervening levels.';
const DMZ_NO_INITIATE =
  'DMZ hosts must not initiate into the OT zone; the OT side opens the session.';

export const PURDUE_FLOW_RULES: FlowRule[] = [
  // ---- from l0 ----
  { from_level: 'l0', to_level: 'l1',   direct_allowed: true,  note: 'Field devices are read and driven by the controller.' },
  { from_level: 'l0', to_level: 'l2',   direct_allowed: false, note: NOT_ADJACENT },
  { from_level: 'l0', to_level: 'l3',   direct_allowed: false, note: NOT_ADJACENT },
  { from_level: 'l0', to_level: 'l3_5', direct_allowed: false, note: NOT_ADJACENT },
  { from_level: 'l0', to_level: 'l4',   direct_allowed: false, note: NEVER_ENTERPRISE },
  { from_level: 'l0', to_level: 'l5',   direct_allowed: false, note: NEVER_ENTERPRISE },

  // ---- from l1 ----
  { from_level: 'l1', to_level: 'l0',   direct_allowed: true,  note: 'Controller drives field I/O.' },
  { from_level: 'l1', to_level: 'l2',   direct_allowed: true,  note: 'Controller reports to supervisory control.' },
  { from_level: 'l1', to_level: 'l3',   direct_allowed: false, note: NOT_ADJACENT },
  { from_level: 'l1', to_level: 'l3_5', direct_allowed: false, note: NOT_ADJACENT },
  { from_level: 'l1', to_level: 'l4',   direct_allowed: false, note: NEVER_ENTERPRISE },
  { from_level: 'l1', to_level: 'l5',   direct_allowed: false, note: NEVER_ENTERPRISE },

  // ---- from l2 ----
  { from_level: 'l2', to_level: 'l0',   direct_allowed: false, note: NOT_ADJACENT },
  { from_level: 'l2', to_level: 'l1',   direct_allowed: true,  note: 'Supervisory control commands the controller.' },
  { from_level: 'l2', to_level: 'l3',   direct_allowed: true,  note: 'Supervisory data flows up to site operations.' },
  { from_level: 'l2', to_level: 'l3_5', direct_allowed: false, note: NOT_ADJACENT },
  { from_level: 'l2', to_level: 'l4',   direct_allowed: false, broker_level: 'l3_5', note: VIA_DMZ },
  { from_level: 'l2', to_level: 'l5',   direct_allowed: false, broker_level: 'l3_5', note: VIA_DMZ },

  // ---- from l3 ----
  { from_level: 'l3', to_level: 'l0',   direct_allowed: false, note: NOT_ADJACENT },
  { from_level: 'l3', to_level: 'l1',   direct_allowed: false, note: NOT_ADJACENT },
  { from_level: 'l3', to_level: 'l2',   direct_allowed: true,  note: 'Site operations queries supervisory systems.' },
  { from_level: 'l3', to_level: 'l3_5', direct_allowed: true,  note: 'Historian replication and brokered publishing into the DMZ.' },
  { from_level: 'l3', to_level: 'l4',   direct_allowed: false, broker_level: 'l3_5', note: VIA_DMZ },
  { from_level: 'l3', to_level: 'l5',   direct_allowed: false, broker_level: 'l3_5', note: VIA_DMZ },

  // ---- from l3_5 ----
  { from_level: 'l3_5', to_level: 'l0', direct_allowed: false, note: NEVER_ENTERPRISE },
  { from_level: 'l3_5', to_level: 'l1', direct_allowed: false, note: DMZ_NO_INITIATE },
  { from_level: 'l3_5', to_level: 'l2', direct_allowed: false, note: DMZ_NO_INITIATE },
  { from_level: 'l3_5', to_level: 'l3', direct_allowed: true,  note: 'Adjacent, but the OT side initiates; a DMZ host must not open sessions inward.' },
  { from_level: 'l3_5', to_level: 'l4', direct_allowed: true,  note: 'DMZ publishes to business systems.' },
  { from_level: 'l3_5', to_level: 'l5', direct_allowed: false, note: NOT_ADJACENT },

  // ---- from l4 ----
  { from_level: 'l4', to_level: 'l0',   direct_allowed: false, note: NEVER_ENTERPRISE },
  { from_level: 'l4', to_level: 'l1',   direct_allowed: false, note: NEVER_ENTERPRISE },
  { from_level: 'l4', to_level: 'l2',   direct_allowed: false, broker_level: 'l3_5', note: VIA_DMZ },
  { from_level: 'l4', to_level: 'l3',   direct_allowed: false, broker_level: 'l3_5', note: VIA_DMZ },
  { from_level: 'l4', to_level: 'l3_5', direct_allowed: true,  note: 'Business systems consume DMZ-published data and land remote sessions here.' },
  { from_level: 'l4', to_level: 'l5',   direct_allowed: true,  note: 'Site business systems to corporate IT.' },

  // ---- from l5 ----
  { from_level: 'l5', to_level: 'l0',   direct_allowed: false, note: NEVER_ENTERPRISE },
  { from_level: 'l5', to_level: 'l1',   direct_allowed: false, note: NEVER_ENTERPRISE },
  { from_level: 'l5', to_level: 'l2',   direct_allowed: false, broker_level: 'l3_5', note: VIA_DMZ },
  { from_level: 'l5', to_level: 'l3',   direct_allowed: false, broker_level: 'l3_5', note: VIA_DMZ },
  { from_level: 'l5', to_level: 'l3_5', direct_allowed: false, note: NOT_ADJACENT },
  { from_level: 'l5', to_level: 'l4',   direct_allowed: true,  note: 'Corporate IT to site business systems.' },
];

// ---------------------------------------------------------------------------
// Lookups + invariants
// ---------------------------------------------------------------------------

export const PURDUE_LEVEL_KEYS: PurdueLevelKey[] =
  PURDUE_LEVELS.map((l) => l.level_key);

export function getPurdueLevel(key: string): PurdueLevel | undefined {
  return PURDUE_LEVELS.find((l) => l.level_key === key);
}

export function getAssetPlacement(attackId: string): AssetPlacement | undefined {
  return ASSET_PLACEMENTS.find((p) => p.attack_id === attackId);
}

/** True when the asset is present in the industrial DMZ. Mirrors the generated
 *  column in Postgres — keep the two definitions in step. */
export function isBoundaryAsset(p: AssetPlacement): boolean {
  return p.spans_levels.includes('l3_5');
}

/**
 * Structural checks the database cannot express (CHECK constraints reject
 * subqueries, so cardinality and completeness rules have to live here).
 * Called by scripts/verify-ics-assets.mjs and by the seeder before it writes,
 * so a bad edit fails loudly instead of landing silently.
 */
export function validateRegistry(): string[] {
  const errors: string[] = [];
  const keys = new Set<string>(PURDUE_LEVEL_KEYS);

  if (PURDUE_LEVELS.length !== 7) {
    errors.push(`expected 7 Purdue levels, found ${PURDUE_LEVELS.length}`);
  }

  const seenAssets = new Set<string>();
  for (const p of ASSET_PLACEMENTS) {
    if (seenAssets.has(p.attack_id)) errors.push(`duplicate placement for ${p.attack_id}`);
    seenAssets.add(p.attack_id);
    if (!keys.has(p.primary_level)) {
      errors.push(`${p.attack_id}: unknown primary_level "${p.primary_level}"`);
    }
    if (!p.spans_levels.includes(p.primary_level)) {
      errors.push(`${p.attack_id}: primary_level "${p.primary_level}" not in spans_levels`);
    }
    for (const s of p.spans_levels) {
      if (!keys.has(s)) errors.push(`${p.attack_id}: unknown level "${s}" in spans_levels`);
    }
    if (!p.rationale.trim()) errors.push(`${p.attack_id}: empty rationale`);
  }

  // 7 levels x 6 destinations, self-pairs excluded.
  const EXPECTED_PAIRS = PURDUE_LEVELS.length * (PURDUE_LEVELS.length - 1);
  if (PURDUE_FLOW_RULES.length !== EXPECTED_PAIRS) {
    errors.push(`expected ${EXPECTED_PAIRS} flow rules, found ${PURDUE_FLOW_RULES.length}`);
  }

  const seenPairs = new Set<string>();
  for (const r of PURDUE_FLOW_RULES) {
    const pair = `${r.from_level}->${r.to_level}`;
    if (seenPairs.has(pair)) errors.push(`duplicate flow rule ${pair}`);
    seenPairs.add(pair);
    if (r.from_level === r.to_level) errors.push(`self-loop flow rule ${pair}`);
    if (!keys.has(r.from_level)) errors.push(`${pair}: unknown from_level`);
    if (!keys.has(r.to_level)) errors.push(`${pair}: unknown to_level`);
    if (r.broker_level) {
      if (!keys.has(r.broker_level)) errors.push(`${pair}: unknown broker_level`);
      if (r.broker_level === r.from_level || r.broker_level === r.to_level) {
        errors.push(`${pair}: broker_level must not be an endpoint`);
      }
      if (r.direct_allowed) errors.push(`${pair}: brokered pair cannot also be directly adjacent`);
    }
  }

  // Every ordered pair must be present — the design commits to an explicit
  // matrix rather than "absent means denied".
  for (const a of PURDUE_LEVEL_KEYS) {
    for (const b of PURDUE_LEVEL_KEYS) {
      if (a !== b && !seenPairs.has(`${a}->${b}`)) errors.push(`missing flow rule ${a}->${b}`);
    }
  }

  return errors;
}
