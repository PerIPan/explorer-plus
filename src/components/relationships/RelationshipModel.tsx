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
    { id: 'technique', label: 'Technique', x: 550, y: 330, color: c.accentTeal, bg: alpha(c.accentTeal, '18'), path: '/techniques', description: 'Attack methods and sub-techniques used by adversaries', category: 'core', scale: 1.8 },
    { id: 'tactic', label: 'Tactic', x: 550, y: 120, color: c.accentYellow, bg: alpha(c.accentYellow, '18'), path: '/tactics', description: 'Kill chain phases: Reconnaissance to Impact', category: 'core' },
    { id: 'group', label: 'Threat Group', x: 160, y: 200, color: c.accentOrange, bg: alpha(c.accentOrange, '18'), path: '/groups', description: 'Tracked adversary groups (APT29, Lazarus, etc.)', category: 'core' },
    { id: 'software', label: 'Software', x: 160, y: 400, color: c.accentPurple, bg: alpha(c.accentPurple, '18'), path: '/software', description: 'Malware and tools used in attacks', category: 'core' },
    { id: 'campaign', label: 'Campaign', x: 340, y: 120, color: c.accentBlue, bg: alpha(c.accentBlue, '18'), path: '/campaigns', description: 'Named intrusion operations with timelines', category: 'core' },
    { id: 'sector', label: 'Sector', x: 50, y: 100, color: c.accentPink, bg: alpha(c.accentPink, '18'), path: '/sectors', description: 'Industries targeted by threat groups', category: 'core' },
    { id: 'mitigation', label: 'Mitigation', x: 850, y: 160, color: c.accentGreen, bg: alpha(c.accentGreen, '18'), path: '/mitigations', description: 'Countermeasures to prevent techniques', category: 'defensive' },
    { id: 'sigma', label: 'Sigma Rules', x: 850, y: 370, color: '#c084fc', bg: '#c084fc18', path: '/cti/sigma', description: 'Detection signatures from SigmaHQ mapped to techniques', category: 'defensive' },
    { id: 'nist', label: 'NIST 800-53', x: 1050, y: 160, color: '#38bdf8', bg: '#38bdf818', path: '/frameworks/nist', description: 'Federal security controls mapped to ATT&CK techniques', category: 'compliance' },
    { id: 'engage', label: 'MITRE Engage', x: 1050, y: 330, color: '#fb923c', bg: '#fb923c18', path: '/frameworks/engage', description: 'Adversary deception & engagement activities per technique', category: 'compliance' },
    { id: 'react', label: 'RE&CT', x: 1050, y: 500, color: '#4ade80', bg: '#4ade8018', path: '/frameworks/react', description: 'Incident response playbooks and actions per technique', category: 'compliance' },
    { id: 'report', label: 'Threat Reports', x: 200, y: 490, color: c.accentOrange, bg: alpha(c.accentOrange, '18'), path: '/cti/reports', description: 'Live threat intelligence from OTX, RSS feeds', category: 'intelligence' },
    { id: 'cve', label: 'CVEs', x: 380, y: 500, color: c.accentPink, bg: alpha(c.accentPink, '18'), path: '/cti/cves', description: 'Known vulnerabilities enriched with NVD metadata', category: 'intelligence' },
    { id: 'nvd', label: 'NVD', x: 260, y: 555, color: '#38bdf8', bg: '#38bdf818', path: '/cti/cves', description: 'National Vulnerability Database — CVSS scores, CWE, descriptions', category: 'intelligence' },
    { id: 'ioc', label: 'IOCs', x: 550, y: 500, color: '#fb923c', bg: '#fb923c18', path: '/cti/iocs', description: 'Hashes, domains, IPs from OTX, ThreatFox, MalwareBazaar', category: 'intelligence' },
    { id: 'virustotal', label: 'VirusTotal', x: 680, y: 555, color: '#3b82f6', bg: '#3b82f618', path: '/cti/iocs', description: 'Sandbox verdicts and ATT&CK techniques for file hashes', category: 'intelligence' },
    { id: 'atomic', label: 'Atomic Tests', x: 750, y: 490, color: '#ef4444', bg: '#ef444418', path: '/techniques', description: 'Red team test procedures from Atomic Red Team per technique', category: 'intelligence' },
    { id: 'd3fend', label: 'D3FEND', x: 900, y: 500, color: c.accentGreen, bg: alpha(c.accentGreen, '18'), path: '/techniques', description: 'Defensive countermeasures from MITRE D3FEND', category: 'intelligence' },
    { id: 'thaicert', label: 'ETDA Actors', x: 50, y: 260, color: c.accentNeutral, bg: alpha(c.accentNeutral, '18'), path: '/external-actors', description: '500+ extended threat actors from ThaiCERT encyclopedia', category: 'intelligence' },
  ];
}

const EDGES: ModelEdge[] = [
  { from: 'group', to: 'technique', label: 'uses' },
  { from: 'group', to: 'software', label: 'uses' },
  { from: 'group', to: 'campaign', label: 'attributed to' },
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
];

function getEdgePath(from: ModelNode, to: ModelNode): { path: string; midX: number; midY: number; angle: number } {
  const dx = to.x - from.x;
  const dy = to.y - from.y;
  const len = Math.sqrt(dx * dx + dy * dy);
  // Scale-aware radii — larger nodes push edge endpoints further out
  const rFrom = 45 * (from.scale ?? 1);
  const rTo = 45 * (to.scale ?? 1);
  const sx = from.x + (dx / len) * rFrom;
  const sy = from.y + (dy / len) * rFrom;
  const ex = to.x - (dx / len) * rTo;
  const ey = to.y - (dy / len) * rTo;
  const cx = (sx + ex) / 2 + (dy / len) * 15;
  const cy = (sy + ey) / 2 - (dx / len) * 15;
  const midX = (sx + ex) / 2;
  const midY = (sy + ey) / 2;
  const angle = Math.atan2(ey - sy, ex - sx) * (180 / Math.PI);
  return { path: `M ${sx} ${sy} Q ${cx} ${cy} ${ex} ${ey}`, midX, midY, angle };
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
        className="bg-[var(--surface-deep)] border border-[var(--border-color)] rounded-xl shadow-2xl w-[95vw] max-w-[1200px] max-h-[90vh] overflow-hidden flex flex-col"
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
          <svg viewBox="0 0 1150 620" className="w-full h-auto min-h-[500px]">
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
                        x={midX - 30} y={midY - 8}
                        width={60} height={16}
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
              return (
                <g className="pointer-events-none">
                  <rect
                    x={node.x - 120} y={tooltipY - 12}
                    width={240} height={24}
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
