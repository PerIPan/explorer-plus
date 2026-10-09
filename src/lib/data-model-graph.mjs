// src/lib/data-model-graph.mjs — pure data + geometry, no React. Rendered by
// src/components/relationships/RelationshipModel.tsx (the header "Data Model"
// dialog); tested by scripts/lib/data-model-graph.test.mjs.
//
// WHY THE LAYOUT IS DATA WITH A TEST
// The diagram is hand-placed nodes and curved edges on a fixed canvas. The
// previous version had drifted into ten defects nobody could see in review —
// edges passing straight through unrelated nodes (ICS -> ICS Assets ran
// through Technique; GHSA -> CVEs through CTID) and two overlapping nodes —
// because coordinates are invisible in a diff. `layoutProblems` reproduces the
// renderer's own geometry (ellipse radii, the quadratic edge curve) and the
// test fails on any overlap, any edge crossing a node it does not connect, any
// node off the canvas, and any link to a page that does not exist. The 2026-10
// positions came from an annealing pass over those constraints, each node kept
// within ~120px of its previous place so the clusters stay where readers left
// them.
//
// One edge was dropped rather than routed: ICS -> ICS Assets. It could not be
// drawn without crossing the Technique hub, and it said less than the edge
// that stays (Technique -targets-> ICS Assets); the asset node's description
// now carries "catalogued by ATT&CK for ICS" instead.

/** Canvas the renderer's viewBox uses. */
export const MODEL_WIDTH = 1520;
export const MODEL_HEIGHT = 840;

/**
 * @typedef {'core' | 'defensive' | 'intelligence' | 'compliance'} ModelCategory
 * @typedef {Object} ModelNode
 * @property {string} id
 * @property {string} label
 * @property {number} x
 * @property {number} y
 * @property {string} path         In-app destination; tested to be a real page.
 * @property {string} description  Hover text.
 * @property {ModelCategory} category
 * @property {string} color        A theme token name (accentTeal …) or a hex.
 * @property {number} [scale]      Visual scale; Technique is the hub.
 *
 * @typedef {Object} ModelEdge
 * @property {string} from
 * @property {string} to
 * @property {string} label
 * @property {'solid' | 'dashed'} [style]  dashed = enrichment / mapping.
 */

/** @type {readonly ModelNode[]} */
export const MODEL_NODES = Object.freeze([
  // ── ATT&CK core ──────────────────────────────────────────────────────────
  { id: 'technique', label: 'Technique', x: 650, y: 360, color: 'accentTeal', path: '/techniques', category: 'core', scale: 1.4, description: 'Attack methods and sub-techniques used by adversaries — the hub every other entity maps onto' },
  { id: 'tactic', label: 'Tactic', x: 570, y: 140, color: 'accentYellow', path: '/tactics', category: 'core', description: 'Kill chain phases: Reconnaissance to Impact' },
  { id: 'atlas', label: 'ATLAS', x: 920, y: 70, color: '#a78bfa', path: '/matrix?domain=atlas-attack', category: 'core', description: 'MITRE ATLAS — AI/ML adversarial threat framework, cross-referenced to ATT&CK' },
  { id: 'group', label: 'Threat Group', x: 200, y: 180, color: 'accentOrange', path: '/groups', category: 'core', description: 'Tracked adversary groups (APT29, Lazarus, Sandworm …)' },
  { id: 'software', label: 'Malware', x: 150, y: 390, color: 'accentPurple', path: '/software', category: 'core', description: 'Attacker tools — malware and hacking tools used in attacks' },
  { id: 'campaign', label: 'Campaign', x: 350, y: 50, color: 'accentBlue', path: '/campaigns', category: 'core', description: 'Named intrusion operations with timelines' },
  { id: 'sector', label: 'Sector', x: 60, y: 70, color: 'accentPink', path: '/sectors', category: 'core', description: 'Industries targeted by threat groups' },
  { id: 'application', label: 'Application', x: 130, y: 590, color: '#3b82f6', path: '/applications', category: 'core', description: 'Defender view — vendor products with CVEs (Windows, PAN-OS …)' },
  { id: 'package', label: 'Package', x: 420, y: 780, color: '#60a5fa', path: '/packages', category: 'core', description: 'Library packages (npm, PyPI, Go, Maven, RubyGems, NuGet, Composer, Rust) with GHSA advisories' },
  { id: 'ics', label: 'ICS', x: 470, y: 220, color: '#f97316', path: '/matrix?domain=ics-attack', category: 'core', scale: 0.85, description: 'Industrial Control Systems ATT&CK domain — OT-specific techniques' },
  { id: 'mobile', label: 'Mobile', x: 810, y: 130, color: '#8b5cf6', path: '/matrix?domain=mobile-attack', category: 'core', scale: 0.85, description: 'Mobile ATT&CK domain — Android and iOS techniques' },
  { id: 'asset', label: 'ICS Assets', x: 1050, y: 670, color: '#f97316', path: '/assets', category: 'core', scale: 0.85, description: 'The 18 ATT&CK for ICS assets (PLCs, RTUs, HMIs, historians, safety controllers …), catalogued by ATT&CK for ICS, with the techniques that target each' },
  // ── Detection & prevention ───────────────────────────────────────────────
  { id: 'mitigation', label: 'Mitigation', x: 930, y: 150, color: 'accentGreen', path: '/mitigations', category: 'defensive', description: 'ATT&CK mitigations — countermeasures that prevent techniques' },
  { id: 'sigma', label: 'Sigma Rules', x: 1030, y: 410, color: '#c084fc', path: '/cti/sigma', category: 'defensive', description: 'Detection signatures from SigmaHQ mapped to techniques' },
  { id: 'detection', label: 'Detection Strategies', x: 1060, y: 320, color: 'accentGreen', path: '/frameworks/detection', category: 'defensive', scale: 0.85, description: 'ATT&CK detection strategies and analytics, with the data components they read' },
  { id: 'd3fend', label: 'D3FEND', x: 1120, y: 530, color: 'accentGreen', path: '/frameworks/d3fend', category: 'defensive', description: 'MITRE D3FEND countermeasures (Harden, Detect, Isolate, Evict, Restore …), Enterprise and ICS' },
  // ── Frameworks & compliance ──────────────────────────────────────────────
  { id: 'owasp', label: 'OWASP Top 10', x: 760, y: 70, color: '#059669', path: '/frameworks/owasp', category: 'compliance', description: 'Web, ML and LLM security risks mapped to techniques via CWE and ATLAS' },
  { id: 'csf', label: 'NIST CSF v2', x: 1080, y: 120, color: '#6366f1', path: '/frameworks/csf', category: 'compliance', description: 'NIST Cybersecurity Framework v2 subcategories mapped to techniques (CTID CRI Profile)' },
  { id: 'nist', label: 'NIST 800-53', x: 1280, y: 120, color: '#38bdf8', path: '/frameworks/nist', category: 'compliance', description: 'Federal security controls mapped to ATT&CK techniques (CTID)' },
  { id: 'nist80040', label: 'NIST 800-40', x: 1410, y: 40, color: '#38bdf8', path: '/frameworks/nist-800-40', category: 'compliance', scale: 0.85, description: 'NIST SP 800-40r4 patch-management planning — reaches techniques only through the eight SP 800-53 controls NIST itself names' },
  { id: 'iso', label: 'ISO 27001', x: 1260, y: 30, color: '#6366f1', path: '/frameworks/iso27001', category: 'compliance', scale: 0.85, description: 'ISO/IEC 27001:2022 Annex A controls, crosswalked to ATT&CK through NIST CSF v2' },
  { id: 'engage', label: 'MITRE Engage', x: 1240, y: 240, color: '#fb923c', path: '/frameworks/engage', category: 'compliance', description: 'Adversary deception and engagement activities per technique' },
  { id: 'react', label: 'RE&CT', x: 1180, y: 610, color: '#4ade80', path: '/frameworks/react', category: 'compliance', description: 'Incident response playbooks and actions' },
  { id: 'veris', label: 'VERIS', x: 1420, y: 130, color: '#e879f9', path: '/frameworks/veris', category: 'compliance', scale: 0.85, description: 'Incident classification categories mapped to ATT&CK techniques' },
  { id: 'azure', label: 'Azure', x: 1410, y: 340, color: '#38bdf8', path: '/frameworks/cloud', category: 'compliance', scale: 0.85, description: 'Azure security controls mapped to ATT&CK techniques' },
  { id: 'gcp', label: 'GCP', x: 1370, y: 520, color: '#34d399', path: '/frameworks/cloud', category: 'compliance', scale: 0.85, description: 'GCP security controls mapped to ATT&CK techniques' },
  { id: 'faircam', label: 'FAIR-CAM', x: 1220, y: 320, color: '#38bdf8', path: '/frameworks/fair-cam', category: 'compliance', scale: 0.85, description: 'FAIR Controls Analytics Model (FAIR Institute) — mitigations and D3FEND countermeasures classified (by this site) into loss-event, variance-management and decision-support functions' },
  { id: 'scf', label: 'SCF Compliance', x: 1200, y: 680, color: '#38bdf8', path: '/compliance', category: 'compliance', scale: 0.85, description: '224 regulatory frameworks (NIS2, DORA, PCI DSS, NIST AI RMF …) bridged to techniques through Secure Controls Framework control cross-references' },
  { id: 'purdue', label: 'Purdue Model', x: 1150, y: 770, color: '#fbbf24', path: '/frameworks/purdue', category: 'compliance', scale: 0.85, description: 'OT network segmentation — seven levels from the physical process to enterprise IT. Placement curated from NIST SP 800-82r3 and ISA-95.' },
  { id: 'otinv', label: 'CISA OT Inventory', x: 770, y: 810, color: '#fbbf24', path: '/frameworks/ot-inventory', category: 'compliance', scale: 0.85, description: 'CISA OT asset-inventory guidance — its sector taxonomy rows mapped (by this site) to ATT&CK ICS assets' },
  // ── Threat intelligence ──────────────────────────────────────────────────
  { id: 'report', label: 'Threat Reports', x: 230, y: 450, color: 'accentOrange', path: '/cti/reports', category: 'intelligence', description: 'Live threat intelligence from OTX and RSS feeds' },
  { id: 'cve', label: 'CVEs', x: 390, y: 510, color: 'accentPink', path: '/cti/cves', category: 'intelligence', description: 'Known vulnerabilities, enriched by NVD, flagged by CISA KEV and scored by EPSS' },
  { id: 'ghsa', label: 'GHSA', x: 570, y: 770, color: '#f472b6', path: '/cti/ghsa', category: 'intelligence', description: 'GitHub Security Advisories — library-level vulnerabilities for open-source packages' },
  { id: 'nvd', label: 'NVD', x: 310, y: 590, color: '#38bdf8', path: '/cti/cves', category: 'intelligence', description: 'National Vulnerability Database — CVSS scores, CWE, descriptions' },
  { id: 'capec', label: 'CAPEC', x: 370, y: 650, color: '#fbbf24', path: '/cti/capec', category: 'intelligence', scale: 0.85, description: 'MITRE attack patterns — bridge CWE weaknesses to ATT&CK techniques' },
  { id: 'ctid', label: 'CTID', x: 540, y: 610, color: '#f472b6', path: '/cti/cves?curated=1&since=', category: 'intelligence', scale: 0.85, description: 'Hand-curated CVE → ATT&CK mappings from the MITRE Center for Threat-Informed Defense' },
  { id: 'ioc', label: 'IOCs', x: 660, y: 610, color: '#fb923c', path: '/cti/iocs', category: 'intelligence', description: 'Hashes, domains, IPs from OTX, ThreatFox, MalwareBazaar' },
  { id: 'virustotal', label: 'VirusTotal', x: 780, y: 730, color: '#3b82f6', path: '/cti/iocs', category: 'intelligence', description: 'Sandbox verdicts and ATT&CK techniques for file hashes' },
  { id: 'atomic', label: 'Atomic Tests', x: 830, y: 630, color: '#ef4444', path: '/frameworks/atomic', category: 'intelligence', description: 'Atomic Red Team test procedures per technique' },
  { id: 'emulation', label: 'Emulation Plans', x: 340, y: 300, color: '#ef4444', path: '/frameworks/emulation', category: 'intelligence', scale: 0.85, description: 'MITRE CTID adversary emulation plans for 9 groups — every step tied to the technique it exercises' },
  { id: 'thaicert', label: 'ETDA Actors', x: 100, y: 290, color: 'accentNeutral', path: '/external-actors', category: 'intelligence', description: '500+ extended threat actors from the ThaiCERT encyclopedia' },
]);

/** @type {readonly ModelEdge[]} */
export const MODEL_EDGES = Object.freeze([
  { from: 'group', to: 'technique', label: 'uses' },
  { from: 'group', to: 'software', label: 'uses' },
  { from: 'campaign', to: 'group', label: 'attributed to' },
  { from: 'software', to: 'technique', label: 'implements' },
  { from: 'campaign', to: 'technique', label: 'uses' },
  { from: 'technique', to: 'tactic', label: 'accomplishes' },
  { from: 'group', to: 'sector', label: 'targets' },
  { from: 'mitigation', to: 'technique', label: 'prevents' },
  { from: 'sigma', to: 'technique', label: 'detects', style: 'dashed' },
  { from: 'detection', to: 'technique', label: 'detects', style: 'dashed' },
  { from: 'd3fend', to: 'technique', label: 'defends', style: 'dashed' },
  { from: 'nist', to: 'technique', label: 'governs', style: 'dashed' },
  { from: 'nist80040', to: 'nist', label: 'names controls', style: 'dashed' },
  { from: 'engage', to: 'technique', label: 'counters', style: 'dashed' },
  { from: 'react', to: 'technique', label: 'responds to', style: 'dashed' },
  { from: 'report', to: 'technique', label: 'mentions', style: 'dashed' },
  { from: 'atomic', to: 'technique', label: 'validates', style: 'dashed' },
  { from: 'emulation', to: 'technique', label: 'exercises', style: 'dashed' },
  { from: 'emulation', to: 'group', label: 'emulates', style: 'dashed' },
  { from: 'cve', to: 'technique', label: 'exploits', style: 'dashed' },
  { from: 'nvd', to: 'cve', label: 'enriches', style: 'dashed' },
  { from: 'ioc', to: 'technique', label: 'linked to', style: 'dashed' },
  { from: 'virustotal', to: 'ioc', label: 'enriches', style: 'dashed' },
  { from: 'virustotal', to: 'technique', label: 'sandbox verifies', style: 'dashed' },
  { from: 'thaicert', to: 'group', label: 'extends', style: 'dashed' },
  { from: 'veris', to: 'technique', label: 'classifies', style: 'dashed' },
  { from: 'azure', to: 'technique', label: 'defends', style: 'dashed' },
  { from: 'gcp', to: 'technique', label: 'defends', style: 'dashed' },
  { from: 'capec', to: 'cve', label: 'bridges', style: 'dashed' },
  { from: 'ctid', to: 'cve', label: 'curates', style: 'dashed' },
  { from: 'ctid', to: 'technique', label: 'maps directly', style: 'dashed' },
  { from: 'application', to: 'cve', label: 'affected by' },
  { from: 'capec', to: 'technique', label: 'maps to', style: 'dashed' },
  { from: 'application', to: 'technique', label: 'exploited via', style: 'dashed' },
  { from: 'ics', to: 'technique', label: 'contains', style: 'dashed' },
  { from: 'mobile', to: 'technique', label: 'contains', style: 'dashed' },
  { from: 'atlas', to: 'technique', label: 'cross-references', style: 'dashed' },
  { from: 'owasp', to: 'technique', label: 'maps via CWE', style: 'dashed' },
  { from: 'owasp', to: 'atlas', label: 'AI risks', style: 'dashed' },
  { from: 'owasp', to: 'cve', label: 'categorizes', style: 'dashed' },
  { from: 'csf', to: 'technique', label: 'outcomes', style: 'dashed' },
  { from: 'csf', to: 'nist', label: 'implemented by', style: 'dashed' },
  { from: 'iso', to: 'csf', label: 'crosswalk', style: 'dashed' },
  { from: 'scf', to: 'technique', label: 'bridges via controls', style: 'dashed' },
  { from: 'faircam', to: 'mitigation', label: 'classifies', style: 'dashed' },
  { from: 'faircam', to: 'd3fend', label: 'classifies', style: 'dashed' },
  { from: 'package', to: 'ghsa', label: 'affected by' },
  { from: 'ghsa', to: 'cve', label: 'alias', style: 'dashed' },
  { from: 'ghsa', to: 'technique', label: 'exploits via CWE', style: 'dashed' },
  { from: 'technique', to: 'asset', label: 'targets', style: 'dashed' },
  { from: 'purdue', to: 'asset', label: 'places', style: 'dashed' },
  { from: 'otinv', to: 'asset', label: 'classifies (curated)', style: 'dashed' },
]);

/**
 * A node's ellipse radii — the renderer draws exactly these.
 * @param {Pick<ModelNode, 'label' | 'scale'>} n
 * @returns {{ rx: number, ry: number }}
 */
export function nodeRadii(n) {
  const s = n.scale ?? 1;
  return { rx: Math.max(48, n.label.length * 5.5 + 10) * s, ry: 26 * s };
}

/**
 * The quadratic control point for an edge: the chord's midpoint pushed 15px
 * to one side, so parallel edges do not sit on top of each other.
 * @param {{x:number,y:number}} a
 * @param {{x:number,y:number}} b
 */
export function edgeControl(a, b) {
  const dx = b.x - a.x;
  const dy = b.y - a.y;
  const len = Math.hypot(dx, dy) || 1;
  return { x: (a.x + b.x) / 2 + (dy / len) * 15, y: (a.y + b.y) / 2 - (dx / len) * 15 };
}

/**
 * Where an edge leaves `from` and meets `to`: on each ellipse boundary along
 * the centre line, 2px out, plus the curve's control point and midpoint.
 * @param {ModelNode} from
 * @param {ModelNode} to
 */
export function edgeGeometry(from, to) {
  const angle = Math.atan2(to.y - from.y, to.x - from.x);
  const boundary = (n, a) => {
    const { rx, ry } = nodeRadii(n);
    return (rx * ry) / Math.sqrt((ry * Math.cos(a)) ** 2 + (rx * Math.sin(a)) ** 2);
  };
  const fr = boundary(from, angle) + 2;
  const tr = boundary(to, angle + Math.PI) + 2;
  const sx = from.x + Math.cos(angle) * fr;
  const sy = from.y + Math.sin(angle) * fr;
  const ex = to.x - Math.cos(angle) * tr;
  const ey = to.y - Math.sin(angle) * tr;
  const c = edgeControl({ x: sx, y: sy }, { x: ex, y: ey });
  return {
    path: `M ${sx} ${sy} Q ${c.x} ${c.y} ${ex} ${ey}`,
    midX: (sx + ex) / 2,
    midY: (sy + ey) / 2,
    /** Point on the drawn curve at t in [0, 1] — what the layout check samples. */
    at: (t) => ({
      x: (1 - t) ** 2 * sx + 2 * (1 - t) * t * c.x + t ** 2 * ex,
      y: (1 - t) ** 2 * sy + 2 * (1 - t) * t * c.y + t ** 2 * ey,
    }),
  };
}

/**
 * Everything wrong with a layout, as readable strings; empty means clean.
 * Checks: nodes inside the canvas, no two nodes overlapping (bounding boxes
 * plus `pad`), no edge passing through a node it does not connect, and no
 * edge naming a node that does not exist.
 *
 * @param {readonly ModelNode[]} nodes
 * @param {readonly ModelEdge[]} edges
 * @param {{ pad?: number, width?: number, height?: number }} [opts]
 * @returns {string[]}
 */
export function layoutProblems(nodes, edges, { pad = 6, width = MODEL_WIDTH, height = MODEL_HEIGHT } = {}) {
  const out = [];
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const inside = (p, n, grow) => {
    const { rx, ry } = nodeRadii(n);
    return ((p.x - n.x) / (rx + grow)) ** 2 + ((p.y - n.y) / (ry + grow)) ** 2 < 1;
  };
  for (const n of nodes) {
    const { rx, ry } = nodeRadii(n);
    if (n.x - rx < 4 || n.x + rx > width - 4 || n.y - ry < 4 || n.y + ry > height - 4) out.push(`off canvas: ${n.id}`);
  }
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      const a = nodes[i], b = nodes[j], ra = nodeRadii(a), rb = nodeRadii(b);
      if (Math.abs(a.x - b.x) < ra.rx + rb.rx + pad && Math.abs(a.y - b.y) < ra.ry + rb.ry + pad) {
        out.push(`overlap: ${a.id} / ${b.id}`);
      }
    }
  }
  for (const e of edges) {
    const a = byId.get(e.from), b = byId.get(e.to);
    if (!a || !b) { out.push(`dangling edge: ${e.from} -> ${e.to}`); continue; }
    // The exact curve the renderer draws (boundary to boundary).
    const { at } = edgeGeometry(a, b);
    for (const n of nodes) {
      if (n === a || n === b) continue;
      for (let k = 0; k <= 60; k++) {
        if (inside(at(k / 60), n, pad)) { out.push(`edge ${e.from} -> ${e.to} crosses ${n.id}`); break; }
      }
    }
  }
  return out;
}
