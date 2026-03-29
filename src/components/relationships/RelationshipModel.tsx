import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useThemeColors } from '../../hooks/useThemeColors';

interface ModelNode {
  id: string;
  label: string;
  x: number;
  y: number;
  color: string;
  bg: string;
  path: string;
  description: string;
  category: 'core' | 'defensive' | 'intelligence' | 'compliance';
  /** Visual scale factor — defaults to 1. Technique uses 1.8 as the central hub. */
  scale?: number;
}

interface ModelEdge {
  from: string;
  to: string;
  label: string;
  style?: 'solid' | 'dashed';
}

function makeNodes(c: ReturnType<typeof useThemeColors>): ModelNode[] {
  const alpha = (hex: string, a: string) => `${hex}${a}`;
  return [
    // Core entities — center cluster with more spacing
    { id: 'technique', label: 'Technique', x: 650, y: 330, color: c.accentTeal, bg: alpha(c.accentTeal, '18'), path: '/techniques', description: 'Attack methods and sub-techniques used by adversaries', category: 'core', scale: 1.4 },
    { id: 'tactic', label: 'Tactic', x: 550, y: 100, color: c.accentYellow, bg: alpha(c.accentYellow, '18'), path: '/tactics', description: 'Kill chain phases: Reconnaissance to Impact', category: 'core' },
    { id: 'atlas', label: 'ATLAS', x: 850, y: 60, color: '#a78bfa', bg: '#a78bfa18', path: '/matrix?domain=atlas-attack', description: 'MITRE ATLAS — AI/ML adversarial threat framework with 155 techniques', category: 'core' },
    { id: 'group', label: 'Threat Group', x: 180, y: 190, color: c.accentOrange, bg: alpha(c.accentOrange, '18'), path: '/groups', description: 'Tracked adversary groups (APT29, Lazarus, etc.)', category: 'core' },
    { id: 'software', label: 'Software', x: 180, y: 400, color: c.accentPurple, bg: alpha(c.accentPurple, '18'), path: '/software', description: 'Attacker tools — malware and hacking tools used in attacks', category: 'core' },
    { id: 'campaign', label: 'Campaign', x: 400, y: 100, color: c.accentBlue, bg: alpha(c.accentBlue, '18'), path: '/campaigns', description: 'Named intrusion operations with timelines', category: 'core' },
    { id: 'sector', label: 'Sector', x: 70, y: 80, color: c.accentPink, bg: alpha(c.accentPink, '18'), path: '/sectors', description: 'Industries targeted by threat groups', category: 'core' },
    { id: 'application', label: 'Application', x: 180, y: 560, color: '#3b82f6', bg: '#3b82f618', path: '/applications', description: 'Defender view — vendor products with CVEs (Windows, PAN-OS, etc.)', category: 'core' },
    // Defensive
    { id: 'mitigation', label: 'Mitigation', x: 1000, y: 140, color: c.accentGreen, bg: alpha(c.accentGreen, '18'), path: '/mitigations', description: 'Countermeasures to prevent techniques', category: 'defensive' },
    { id: 'sigma', label: 'Sigma Rules', x: 1000, y: 400, color: '#c084fc', bg: '#c084fc18', path: '/cti/sigma', description: 'Detection signatures from SigmaHQ mapped to techniques', category: 'defensive' },
    // Compliance & frameworks
    { id: 'nist', label: 'NIST 800-53', x: 1240, y: 140, color: '#38bdf8', bg: '#38bdf818', path: '/frameworks/nist', description: 'Federal security controls mapped to ATT&CK techniques', category: 'compliance' },
    { id: 'engage', label: 'MITRE Engage', x: 1240, y: 310, color: '#fb923c', bg: '#fb923c18', path: '/frameworks/engage', description: 'Adversary deception & engagement activities per technique', category: 'compliance' },
    { id: 'react', label: 'RE&CT', x: 1240, y: 490, color: '#4ade80', bg: '#4ade8018', path: '/frameworks/react', description: 'Incident response playbooks and actions per technique', category: 'compliance' },
    { id: 'veris', label: 'VERIS', x: 1420, y: 140, color: '#e879f9', bg: '#e879f918', path: '/techniques', description: 'Incident classification categories mapped to ATT&CK techniques', category: 'compliance', scale: 0.85 },
    { id: 'azure', label: 'Azure', x: 1420, y: 260, color: '#38bdf8', bg: '#38bdf818', path: '/techniques', description: 'Azure security controls mapped to ATT&CK techniques', category: 'compliance', scale: 0.85 },
    { id: 'gcp', label: 'GCP', x: 1420, y: 450, color: '#34d399', bg: '#34d39918', path: '/techniques', description: 'GCP security controls mapped to ATT&CK techniques', category: 'compliance', scale: 0.85 },
    // Intelligence
    { id: 'report', label: 'Threat Reports', x: 240, y: 490, color: c.accentOrange, bg: alpha(c.accentOrange, '18'), path: '/cti/reports', description: 'Live threat intelligence from OTX, RSS feeds', category: 'intelligence' },
    { id: 'cve', label: 'CVEs', x: 440, y: 500, color: c.accentPink, bg: alpha(c.accentPink, '18'), path: '/cti/cves', description: 'Known vulnerabilities enriched with NVD metadata', category: 'intelligence' },
    { id: 'nvd', label: 'NVD', x: 320, y: 560, color: '#38bdf8', bg: '#38bdf818', path: '/cti/cves', description: 'National Vulnerability Database — CVSS scores, CWE, descriptions', category: 'intelligence' },
    { id: 'capec', label: 'CAPEC', x: 440, y: 600, color: '#fbbf24', bg: '#fbbf2418', path: '/cti/cves', description: 'CWE→CAPEC→ATT&CK bridge linking CVEs to techniques', category: 'intelligence', scale: 0.85 },
    { id: 'ioc', label: 'IOCs', x: 650, y: 500, color: '#fb923c', bg: '#fb923c18', path: '/cti/iocs', description: 'Hashes, domains, IPs from OTX, ThreatFox, MalwareBazaar', category: 'intelligence' },
    { id: 'virustotal', label: 'VirusTotal', x: 790, y: 560, color: '#3b82f6', bg: '#3b82f618', path: '/cti/iocs', description: 'Sandbox verdicts and ATT&CK techniques for file hashes', category: 'intelligence' },
    { id: 'atomic', label: 'Atomic Tests', x: 860, y: 490, color: '#ef4444', bg: '#ef444418', path: '/techniques', description: 'Red team test procedures from Atomic Red Team per technique', category: 'intelligence' },
    { id: 'd3fend', label: 'D3FEND', x: 1060, y: 490, color: c.accentGreen, bg: alpha(c.accentGreen, '18'), path: '/techniques', description: 'Defensive countermeasures from MITRE D3FEND', category: 'intelligence' },
    { id: 'thaicert', label: 'ETDA Actors', x: 80, y: 300, color: c.accentNeutral, bg: alpha(c.accentNeutral, '18'), path: '/external-actors', description: '500+ extended threat actors from ThaiCERT encyclopedia', category: 'intelligence' },
    // Domain variants
    { id: 'ics', label: 'ICS', x: 460, y: 220, color: '#f97316', bg: '#f9731618', path: '/matrix?domain=ics-attack', description: 'Industrial Control Systems ATT&CK domain — OT-specific techniques', category: 'core', scale: 0.85 },
    { id: 'mobile', label: 'Mobile', x: 830, y: 170, color: '#8b5cf6', bg: '#8b5cf618', path: '/matrix?domain=mobile-attack', description: 'Mobile ATT&CK domain — Android and iOS specific techniques', category: 'core', scale: 0.85 },
  ];
}

const EDGES: ModelEdge[] = [
  { from: 'group', to: 'technique', label: 'uses' },
  { from: 'group', to: 'software', label: 'uses' },
  { from: 'campaign', to: 'group', label: 'attributed to' },
  { from: 'software', to: 'technique', label: 'implements' },
  { from: 'campaign', to: 'technique', label: 'uses' },
  { from: 'technique', to: 'tactic', label: 'accomplishes' },
  { from: 'group', to: 'sector', label: 'targets' },
  { from: 'mitigation', to: 'technique', label: 'prevents' },
  { from: 'sigma', to: 'technique', label: 'detects', style: 'dashed' },
  { from: 'nist', to: 'technique', label: 'governs', style: 'dashed' },
  { from: 'engage', to: 'technique', label: 'counters', style: 'dashed' },
  { from: 'react', to: 'technique', label: 'responds to', style: 'dashed' },
  { from: 'report', to: 'technique', label: 'mentions', style: 'dashed' },
  { from: 'atomic', to: 'technique', label: 'validates', style: 'dashed' },
  { from: 'cve', to: 'technique', label: 'exploits', style: 'dashed' },
  { from: 'nvd', to: 'cve', label: 'enriches', style: 'dashed' },
  { from: 'ioc', to: 'technique', label: 'linked to', style: 'dashed' },
  { from: 'virustotal', to: 'ioc', label: 'enriches', style: 'dashed' },
  { from: 'virustotal', to: 'technique', label: 'sandbox verifies', style: 'dashed' },
  { from: 'd3fend', to: 'technique', label: 'defends', style: 'dashed' },
  { from: 'thaicert', to: 'group', label: 'extends', style: 'dashed' },
  { from: 'veris', to: 'technique', label: 'classifies', style: 'dashed' },
  { from: 'azure', to: 'technique', label: 'defends', style: 'dashed' },
  { from: 'gcp', to: 'technique', label: 'defends', style: 'dashed' },
  { from: 'capec', to: 'cve', label: 'bridges', style: 'dashed' },
  { from: 'application', to: 'cve', label: 'affected by' },
  { from: 'capec', to: 'technique', label: 'maps to', style: 'dashed' },
  { from: 'application', to: 'technique', label: 'exploited via', style: 'dashed' },
  { from: 'ics', to: 'technique', label: 'contains', style: 'dashed' },
  { from: 'mobile', to: 'technique', label: 'contains', style: 'dashed' },
  { from: 'atlas', to: 'technique', label: 'cross-references', style: 'dashed' },
];

function getEdgePath(from: ModelNode, to: ModelNode): { path: string; midX: number; midY: number; angle: number } {
  const dx = to.x - from.x;
  const dy = to.y - from.y;
  const angle = Math.atan2(dy, dx);

  // Calculate actual ellipse radii for each node
  const fromScale = from.scale ?? 1;
  const fromRx = Math.max(48, from.label.length * 5.5 + 10) * fromScale;
  const fromRy = 26 * fromScale;

  const toScale = to.scale ?? 1;
  const toRx = Math.max(48, to.label.length * 5.5 + 10) * toScale;
  const toRy = 26 * toScale;

  // Ellipse boundary point: parametric form
  const fromR = (fromRx * fromRy) / Math.sqrt((fromRy * Math.cos(angle)) ** 2 + (fromRx * Math.sin(angle)) ** 2);
  const toR = (toRx * toRy) / Math.sqrt((toRy * Math.cos(angle + Math.PI)) ** 2 + (toRx * Math.sin(angle + Math.PI)) ** 2);

  const sx = from.x + Math.cos(angle) * (fromR + 2);
  const sy = from.y + Math.sin(angle) * (fromR + 2);
  const ex = to.x - Math.cos(angle) * (toR + 2);
  const ey = to.y - Math.sin(angle) * (toR + 2);

  const len = Math.sqrt(dx * dx + dy * dy);
  const cx = (sx + ex) / 2 + (dy / len) * 15;
  const cy = (sy + ey) / 2 - (dx / len) * 15;
  const midX = (sx + ex) / 2;
  const midY = (sy + ey) / 2;
  const angleDeg = Math.atan2(ey - sy, ex - sx) * (180 / Math.PI);
  return { path: `M ${sx} ${sy} Q ${cx} ${cy} ${ex} ${ey}`, midX, midY, angle: angleDeg };
}

interface Props {
  open: boolean;
  onClose: () => void;
}

export function RelationshipModel({ open, onClose }: Props) {
  const navigate = useNavigate();
  const c = useThemeColors();
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [hoveredEdge, setHoveredEdge] = useState<number | null>(null);
  const [allActive, setAllActive] = useState(false);

  const NODES = makeNodes(c);
  const CATEGORIES = [
    { key: 'core', label: 'ATT&CK Core', color: c.accentTeal },
    { key: 'defensive', label: 'Detection & Prevention', color: c.accentGreen },
    { key: 'compliance', label: 'Frameworks & Compliance', color: '#38bdf8' },
    { key: 'intelligence', label: 'Threat Intelligence', color: c.accentOrange },
  ];

  useEffect(() => {
    if (open) {
      setAllActive(true);
      const timer = setTimeout(() => setAllActive(false), 2000);
      return () => clearTimeout(timer);
    }
  }, [open]);

  if (!open) return null;

  const nodeMap = Object.fromEntries(NODES.map(n => [n.id, n]));

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70 backdrop-blur-sm" onClick={onClose}>
      <div
        className="bg-[var(--surface-deep)] border border-[var(--border-color)] rounded-xl shadow-2xl w-[95vw] max-w-[1400px] max-h-[90vh] overflow-hidden flex flex-col"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[var(--border-color)]">
          <div>
            <h2 className="text-lg font-semibold text-[var(--text-primary)]">ATT&CK Object Model Relationships</h2>
            <p className="text-xs text-[var(--text-secondary)] mt-0.5">click any node to navigate — hover for details</p>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-md text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--hover-overlay)] transition-colors"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Diagram */}
        <div className="flex-1 overflow-auto p-4">
          <svg viewBox="0 0 1520 660" className="w-full h-auto min-h-[550px]">
            <defs>
              <marker id="arrow" viewBox="0 0 10 7" refX="10" refY="3.5" markerWidth="8" markerHeight="6" orient="auto-start-reverse">
                <polygon points="0 0, 10 3.5, 0 7" fill={c.borderColor} />
              </marker>
              <marker id="arrow-active" viewBox="0 0 10 7" refX="10" refY="3.5" markerWidth="8" markerHeight="6" orient="auto-start-reverse">
                <polygon points="0 0, 10 3.5, 0 7" fill={c.accentTeal} />
              </marker>
            </defs>

            {/* Edges */}
            {EDGES.map((edge, i) => {
              const from = nodeMap[edge.from];
              const to = nodeMap[edge.to];
              if (!from || !to) return null;
              const { path, midX, midY } = getEdgePath(from, to);
              const isActive = allActive || hoveredNode === edge.from || hoveredNode === edge.to || hoveredEdge === i;

              return (
                <g key={i}
                  onMouseEnter={() => setHoveredEdge(i)}
                  onMouseLeave={() => setHoveredEdge(null)}
                >
                  <path
                    d={path}
                    fill="none"
                    stroke={isActive ? c.accentTeal : c.borderColor}
                    strokeWidth={isActive ? 2 : 1}
                    strokeDasharray={edge.style === 'dashed' ? '6 4' : undefined}
                    markerEnd={isActive ? 'url(#arrow-active)' : 'url(#arrow)'}
                    className={`transition-all ${allActive ? 'duration-500' : 'duration-200'}`}
                  />
                  {isActive && (
                    <>
                      <rect
                        x={midX - Math.max(30, edge.label.length * 3.5)} y={midY - 8}
                        width={Math.max(60, edge.label.length * 7)} height={16}
                        rx={3}
                        fill={c.surfaceCard}
                        stroke={`${c.accentTeal}33`}
                      />
                      <text
                        x={midX} y={midY + 4}
                        textAnchor="middle"
                        fontSize={9}
                        fill={c.accentTeal}
                        className="select-none"
                      >
                        {edge.label}
                      </text>
                    </>
                  )}
                </g>
              );
            })}

            {/* Nodes */}
            {NODES.map((node) => {
              const isHovered = hoveredNode === node.id;
              return (
                <g
                  key={node.id}
                  className="cursor-pointer"
                  onMouseEnter={() => setHoveredNode(node.id)}
                  onMouseLeave={() => setHoveredNode(null)}
                  onClick={() => { navigate(node.path); onClose(); }}
                >
                  {(() => {
                    const s = node.scale ?? 1;
                    const rx = Math.max(48, node.label.length * 5.5 + 10) * s;
                    const ry = 26 * s;
                    const fontSize = Math.round(11 * s);
                    return (
                      <>
                      {isHovered && (
                        <ellipse
                          cx={node.x} cy={node.y}
                          rx={rx + 7} ry={ry + 6}
                          fill="none"
                          stroke={node.color}
                          strokeWidth={1}
                          opacity={0.3}
                        />
                      )}
                  <ellipse
                    cx={node.x} cy={node.y}
                    rx={rx} ry={ry}
                    fill={isHovered ? node.bg.replace('18', '30') : node.bg}
                    stroke={node.color}
                    strokeWidth={isHovered ? 2 : (s > 1 ? 2 : 1)}
                    opacity={isHovered ? 1 : (s > 1 ? 1 : 0.85)}
                    className="transition-all duration-200"
                  />
                  <text
                    x={node.x} y={node.y + 1}
                    textAnchor="middle"
                    dominantBaseline="central"
                    fontSize={fontSize}
                    fontWeight={s > 1 ? 700 : 600}
                    fill={isHovered ? node.color : c.textPrimary}
                    className="transition-colors duration-200 select-none pointer-events-none"
                  >
                    {node.label}
                  </text>
                      </>
                    );
                  })()}
                </g>
              );
            })}

            {/* Tooltip */}
            {hoveredNode && (() => {
              const node = nodeMap[hoveredNode];
              if (!node) return null;
              const tooltipY = node.y < 100 ? node.y + 40 : node.y - 45;
              const tooltipW = Math.max(280, Math.min(420, node.description.length * 4.5 + 20));
              return (
                <g className="pointer-events-none">
                  <rect
                    x={node.x - tooltipW / 2} y={tooltipY - 12}
                    width={tooltipW} height={24}
                    rx={4}
                    fill={c.surfaceCard}
                    stroke={c.borderColor}
                  />
                  <text
                    x={node.x} y={tooltipY + 2}
                    textAnchor="middle"
                    fontSize={9}
                    fill={c.textSecondary}
                    className="select-none"
                  >
                    {node.description}
                  </text>
                </g>
              );
            })()}
          </svg>
        </div>

        {/* Legend */}
        <div className="px-6 py-3 border-t border-[var(--border-color)] flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-4">
            {CATEGORIES.map(cat => (
              <div key={cat.key} className="flex items-center gap-1.5">
                <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: cat.color, opacity: 0.7 }} />
                <span className="text-[10px] text-[var(--text-secondary)]">{cat.label}</span>
              </div>
            ))}
          </div>
          <div className="flex items-center gap-4 text-[10px] text-[var(--text-secondary)]">
            <span className="flex items-center gap-1.5">
              <svg width="20" height="2"><line x1="0" y1="1" x2="20" y2="1" stroke={c.borderColor} strokeWidth="1" /></svg>
              direct relationship
            </span>
            <span className="flex items-center gap-1.5">
              <svg width="20" height="2"><line x1="0" y1="1" x2="20" y2="1" stroke={c.borderColor} strokeWidth="1" strokeDasharray="4 3" /></svg>
              enrichment mapping
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
