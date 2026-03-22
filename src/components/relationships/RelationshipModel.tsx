import { useState } from 'react';
import { useNavigate } from 'react-router-dom';

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
}

interface ModelEdge {
  from: string;
  to: string;
  label: string;
  style?: 'solid' | 'dashed';
}

const NODES: ModelNode[] = [
  // Core ATT&CK (center cluster)
  { id: 'technique', label: 'Technique', x: 450, y: 280, color: '#64ffda', bg: '#64ffda18', path: '/techniques', description: 'Attack methods and sub-techniques used by adversaries', category: 'core' },
  { id: 'group', label: 'Threat Group', x: 150, y: 140, color: '#f97316', bg: '#f9731618', path: '/groups', description: 'Tracked adversary groups (APT29, Lazarus, etc.)', category: 'core' },
  { id: 'campaign', label: 'Campaign', x: 150, y: 420, color: '#60a5fa', bg: '#60a5fa18', path: '/campaigns', description: 'Named intrusion operations with timelines', category: 'core' },
  { id: 'software', label: 'Software', x: 150, y: 280, color: '#a78bfa', bg: '#a78bfa18', path: '/software', description: 'Malware and tools used in attacks', category: 'core' },
  { id: 'tactic', label: 'Tactic', x: 450, y: 480, color: '#fbbf24', bg: '#fbbf2418', path: '/tactics', description: 'Kill chain phases: Reconnaissance to Impact', category: 'core' },
  { id: 'sector', label: 'Sector', x: 150, y: 30, color: '#f472b6', bg: '#f472b618', path: '/sectors', description: 'Industries targeted by threat groups', category: 'core' },

  // Defensive (right side)
  { id: 'mitigation', label: 'Mitigation', x: 750, y: 140, color: '#34d399', bg: '#34d39918', path: '/mitigations', description: 'Countermeasures to prevent techniques', category: 'defensive' },
  { id: 'datasource', label: 'Data Source', x: 750, y: 280, color: '#f472b6', bg: '#f472b618', path: '/data-sources', description: 'Telemetry for detecting techniques', category: 'defensive' },
  { id: 'sigma', label: 'Sigma Rules', x: 750, y: 420, color: '#c084fc', bg: '#c084fc18', path: '/cti/sigma', description: 'Detection signatures mapped to techniques', category: 'defensive' },

  // Compliance (far right)
  { id: 'nist', label: 'NIST 800-53', x: 950, y: 140, color: '#38bdf8', bg: '#38bdf818', path: '/frameworks/nist', description: 'Federal security controls', category: 'compliance' },
  { id: 'engage', label: 'MITRE Engage', x: 950, y: 280, color: '#fb923c', bg: '#fb923c18', path: '/frameworks/engage', description: 'Adversary deception & engagement', category: 'compliance' },
  { id: 'react', label: 'RE&CT', x: 950, y: 420, color: '#4ade80', bg: '#4ade8018', path: '/frameworks/react', description: 'Incident response playbooks', category: 'compliance' },

  // Intelligence (bottom)
  { id: 'report', label: 'Threat Reports', x: 450, y: 600, color: '#f97316', bg: '#f9731618', path: '/cti/reports', description: 'Live threat intelligence from OTX, RSS feeds', category: 'intelligence' },
  { id: 'atomic', label: 'Atomic Tests', x: 750, y: 540, color: '#ef4444', bg: '#ef444418', path: '/cti/sigma', description: 'Red team test procedures per technique', category: 'intelligence' },
];

const EDGES: ModelEdge[] = [
  // Core relationships
  { from: 'group', to: 'technique', label: 'uses' },
  { from: 'group', to: 'software', label: 'uses' },
  { from: 'group', to: 'campaign', label: 'attributed to' },
  { from: 'software', to: 'technique', label: 'implements' },
  { from: 'campaign', to: 'technique', label: 'uses' },
  { from: 'technique', to: 'tactic', label: 'accomplishes' },
  { from: 'sector', to: 'group', label: 'targeted by' },

  // Defensive
  { from: 'mitigation', to: 'technique', label: 'prevents' },
  { from: 'datasource', to: 'technique', label: 'detects' },
  { from: 'sigma', to: 'technique', label: 'detects', style: 'dashed' },

  // Compliance & Frameworks
  { from: 'nist', to: 'technique', label: 'governs', style: 'dashed' },
  { from: 'engage', to: 'technique', label: 'counters', style: 'dashed' },
  { from: 'react', to: 'technique', label: 'responds to', style: 'dashed' },

  // Intelligence
  { from: 'report', to: 'technique', label: 'mentions', style: 'dashed' },
  { from: 'atomic', to: 'technique', label: 'validates', style: 'dashed' },
];

const CATEGORIES = [
  { key: 'core', label: 'ATT&CK Core', color: '#64ffda' },
  { key: 'defensive', label: 'Detection & Prevention', color: '#34d399' },
  { key: 'compliance', label: 'Frameworks & Compliance', color: '#38bdf8' },
  { key: 'intelligence', label: 'Threat Intelligence', color: '#f97316' },
];

function getEdgePath(from: ModelNode, to: ModelNode): { path: string; midX: number; midY: number; angle: number } {
  const dx = to.x - from.x;
  const dy = to.y - from.y;
  const len = Math.sqrt(dx * dx + dy * dy);

  // Offset start/end by node radius
  const r = 45;
  const sx = from.x + (dx / len) * r;
  const sy = from.y + (dy / len) * r;
  const ex = to.x - (dx / len) * r;
  const ey = to.y - (dy / len) * r;

  // Curve control point
  const cx = (sx + ex) / 2 + (dy / len) * 30;
  const cy = (sy + ey) / 2 - (dx / len) * 30;

  const midX = (sx + ex) / 2;
  const midY = (sy + ey) / 2;
  const angle = Math.atan2(ey - sy, ex - sx) * (180 / Math.PI);

  return {
    path: `M ${sx} ${sy} Q ${cx} ${cy} ${ex} ${ey}`,
    midX, midY, angle,
  };
}

interface Props {
  open: boolean;
  onClose: () => void;
}

export function RelationshipModel({ open, onClose }: Props) {
  const navigate = useNavigate();
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [hoveredEdge, setHoveredEdge] = useState<number | null>(null);

  if (!open) return null;

  const nodeMap = Object.fromEntries(NODES.map(n => [n.id, n]));

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70 backdrop-blur-sm" onClick={onClose}>
      <div
        className="bg-[#0a0a1a] border border-[#2a2a4a] rounded-xl shadow-2xl w-[95vw] max-w-[1200px] max-h-[90vh] overflow-hidden flex flex-col"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#2a2a4a]">
          <div>
            <h2 className="text-lg font-semibold text-[#ccd6f6]">ATT&CK Object Model Relationships</h2>
            <p className="text-xs text-[#8892b0] mt-0.5">click any node to navigate — hover for details</p>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-md text-[#8892b0] hover:text-[#ccd6f6] hover:bg-[#ffffff08] transition-colors"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Diagram */}
        <div className="flex-1 overflow-auto p-4">
          <svg viewBox="0 0 1100 660" className="w-full h-auto min-h-[500px]">
            <defs>
              <marker id="arrow" viewBox="0 0 10 7" refX="10" refY="3.5" markerWidth="8" markerHeight="6" orient="auto-start-reverse">
                <polygon points="0 0, 10 3.5, 0 7" fill="#4a4a6a" />
              </marker>
              <marker id="arrow-active" viewBox="0 0 10 7" refX="10" refY="3.5" markerWidth="8" markerHeight="6" orient="auto-start-reverse">
                <polygon points="0 0, 10 3.5, 0 7" fill="#64ffda" />
              </marker>
            </defs>

            {/* Edges */}
            {EDGES.map((edge, i) => {
              const from = nodeMap[edge.from];
              const to = nodeMap[edge.to];
              if (!from || !to) return null;
              const { path, midX, midY } = getEdgePath(from, to);
              const isActive = hoveredNode === edge.from || hoveredNode === edge.to || hoveredEdge === i;

              return (
                <g key={i}
                  onMouseEnter={() => setHoveredEdge(i)}
                  onMouseLeave={() => setHoveredEdge(null)}
                >
                  <path
                    d={path}
                    fill="none"
                    stroke={isActive ? '#64ffda' : '#2a2a4a'}
                    strokeWidth={isActive ? 2 : 1}
                    strokeDasharray={edge.style === 'dashed' ? '6 4' : undefined}
                    markerEnd={isActive ? 'url(#arrow-active)' : 'url(#arrow)'}
                    className="transition-all duration-200"
                  />
                  <rect
                    x={midX - 30} y={midY - 8}
                    width={60} height={16}
                    rx={3}
                    fill={isActive ? '#16213e' : '#0a0a1a'}
                    stroke={isActive ? '#64ffda33' : 'none'}
                  />
                  <text
                    x={midX} y={midY + 4}
                    textAnchor="middle"
                    fontSize={9}
                    fill={isActive ? '#64ffda' : '#4a4a6a'}
                    className="transition-colors duration-200 select-none"
                  >
                    {edge.label}
                  </text>
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
                  {/* Glow on hover */}
                  {isHovered && (
                    <ellipse
                      cx={node.x} cy={node.y}
                      rx={55} ry={32}
                      fill="none"
                      stroke={node.color}
                      strokeWidth={1}
                      opacity={0.3}
                    />
                  )}
                  {/* Node shape */}
                  <ellipse
                    cx={node.x} cy={node.y}
                    rx={48} ry={26}
                    fill={isHovered ? node.bg.replace('18', '30') : node.bg}
                    stroke={node.color}
                    strokeWidth={isHovered ? 2 : 1}
                    opacity={isHovered ? 1 : 0.85}
                    className="transition-all duration-200"
                  />
                  {/* Label */}
                  <text
                    x={node.x} y={node.y + 1}
                    textAnchor="middle"
                    dominantBaseline="central"
                    fontSize={11}
                    fontWeight={600}
                    fill={isHovered ? node.color : '#ccd6f6'}
                    className="transition-colors duration-200 select-none pointer-events-none"
                  >
                    {node.label}
                  </text>
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
                    fill="#16213e"
                    stroke="#2a2a4a"
                  />
                  <text
                    x={node.x} y={tooltipY + 2}
                    textAnchor="middle"
                    fontSize={9}
                    fill="#8892b0"
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
        <div className="px-6 py-3 border-t border-[#2a2a4a] flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-4">
            {CATEGORIES.map(cat => (
              <div key={cat.key} className="flex items-center gap-1.5">
                <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: cat.color, opacity: 0.7 }} />
                <span className="text-[10px] text-[#8892b0]">{cat.label}</span>
              </div>
            ))}
          </div>
          <div className="flex items-center gap-4 text-[10px] text-[#4a4a6a]">
            <span className="flex items-center gap-1.5">
              <svg width="20" height="2"><line x1="0" y1="1" x2="20" y2="1" stroke="#4a4a6a" strokeWidth="1" /></svg>
              direct relationship
            </span>
            <span className="flex items-center gap-1.5">
              <svg width="20" height="2"><line x1="0" y1="1" x2="20" y2="1" stroke="#4a4a6a" strokeWidth="1" strokeDasharray="4 3" /></svg>
              enrichment mapping
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
