'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useThemeColors } from '../../hooks/useThemeColors';
import {
  MODEL_NODES,
  MODEL_EDGES,
  MODEL_WIDTH,
  MODEL_HEIGHT,
  nodeRadii,
  edgeGeometry,
} from '../../lib/data-model-graph.mjs';

/**
 * The header "Data Model" diagram: every entity and source on the site and
 * how each maps onto ATT&CK techniques.
 *
 * Only the CONTENT lives here. The chrome — scrim, title, close button, focus
 * trap, Escape, inert background, focus return — is the shared `<Dialog>` in
 * AppShell, which lazy-loads this panel so the diagram's data never ships in
 * the chunk every page downloads. Node positions and edges are data in
 * src/lib/data-model-graph.mjs, where a test keeps the layout free of overlaps
 * and of edges running through nodes they do not connect.
 *
 * Nodes are links: click, or Tab to one and press Enter. Hover or focus shows
 * the description and lights up the node's edges with their labels.
 */

type ThemeColors = ReturnType<typeof useThemeColors>;

const CATEGORIES = [
  { key: 'core', label: 'ATT&CK Core', token: 'accentTeal' },
  { key: 'defensive', label: 'Detection & Prevention', token: 'accentGreen' },
  { key: 'compliance', label: 'Frameworks & Compliance', token: '#38bdf8' },
  { key: 'intelligence', label: 'Threat Intelligence', token: 'accentOrange' },
] as const;

/** A node colour is either a theme token name or a literal hex. */
function resolveColor(c: ThemeColors, value: string): string {
  return (c as unknown as Record<string, string>)[value] ?? value;
}

/** Word-wrap a description so the tooltip box always contains the text. */
function wrap(text: string, max = 55): string[] {
  const lines: string[] = [];
  let current = '';
  for (const w of text.split(/\s+/)) {
    if (current.length + w.length + 1 > max && current) {
      lines.push(current);
      current = w;
    } else {
      current = current ? `${current} ${w}` : w;
    }
  }
  if (current) lines.push(current);
  return lines;
}

export function RelationshipModelPanel({ onClose }: { onClose: () => void }) {
  const router = useRouter();
  const c = useThemeColors();
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [hoveredEdge, setHoveredEdge] = useState<number | null>(null);
  const [allActive, setAllActive] = useState(true);
  const [hidden, setHidden] = useState<Set<string>>(new Set());

  // The panel mounts each time the dialog opens: light every edge for two
  // seconds so the shape of the model reads at a glance, then settle.
  useEffect(() => {
    const t = setTimeout(() => setAllActive(false), 2000);
    return () => clearTimeout(t);
  }, []);

  const go = (path: string) => {
    router.push(path);
    onClose();
  };

  const toggle = (key: string) =>
    setHidden((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  const visibleNodes = MODEL_NODES.filter((n) => !hidden.has(n.category));
  const nodeMap = new Map(visibleNodes.map((n) => [n.id, n]));
  const visibleEdges = MODEL_EDGES.map((e, i) => ({ e, i })).filter(({ e }) => nodeMap.has(e.from) && nodeMap.has(e.to));
  const hovered = hoveredNode ? nodeMap.get(hoveredNode) : undefined;

  return (
    <div className="flex flex-col">
      {/* Phones scroll the canvas sideways rather than shrink 40 labels to dust. */}
      <div className="overflow-x-auto px-2 py-3 md:px-4">
        <svg
          viewBox={`0 0 ${MODEL_WIDTH} ${MODEL_HEIGHT}`}
          className="mx-auto h-auto w-full min-w-[900px]"
          style={{ maxHeight: 'calc(88vh - 9rem)' }}
          role="group"
          aria-label="Data model: entities and sources, and how each maps onto ATT&CK techniques"
        >
          <defs>
            <marker id="dm-arrow" viewBox="0 0 10 7" refX="10" refY="3.5" markerWidth="8" markerHeight="6" orient="auto-start-reverse">
              <polygon points="0 0, 10 3.5, 0 7" fill={c.borderColor} />
            </marker>
            <marker id="dm-arrow-active" viewBox="0 0 10 7" refX="10" refY="3.5" markerWidth="8" markerHeight="6" orient="auto-start-reverse">
              <polygon points="0 0, 10 3.5, 0 7" fill={c.accentTeal} />
            </marker>
          </defs>

          {/* Edges */}
          {visibleEdges.map(({ e, i }) => {
            const from = nodeMap.get(e.from)!;
            const to = nodeMap.get(e.to)!;
            const { path, midX, midY } = edgeGeometry(from, to);
            const active = allActive || hoveredNode === e.from || hoveredNode === e.to || hoveredEdge === i;
            return (
              <g key={i} onMouseEnter={() => setHoveredEdge(i)} onMouseLeave={() => setHoveredEdge(null)}>
                <path
                  d={path}
                  fill="none"
                  stroke={active ? c.accentTeal : c.borderColor}
                  strokeWidth={active ? 2 : 1}
                  strokeDasharray={e.style === 'dashed' ? '6 4' : undefined}
                  markerEnd={active ? 'url(#dm-arrow-active)' : 'url(#dm-arrow)'}
                  className={`transition-all ${allActive ? 'duration-500' : 'duration-200'}`}
                />
                {active && !allActive && (
                  <>
                    <rect
                      x={midX - Math.max(30, e.label.length * 3.5)}
                      y={midY - 8}
                      width={Math.max(60, e.label.length * 7)}
                      height={16}
                      rx={3}
                      fill={c.surfaceCard}
                      stroke={`${c.accentTeal}33`}
                    />
                    <text x={midX} y={midY + 4} textAnchor="middle" fontSize={9} fill={c.accentTeal} className="select-none">
                      {e.label}
                    </text>
                  </>
                )}
              </g>
            );
          })}

          {/* Nodes — focusable links */}
          {visibleNodes.map((n) => {
            const color = resolveColor(c, n.color);
            const isHovered = hoveredNode === n.id;
            const s = n.scale ?? 1;
            const { rx, ry } = nodeRadii(n);
            return (
              <g
                key={n.id}
                role="link"
                tabIndex={0}
                aria-label={`${n.label}: ${n.description}`}
                className="cursor-pointer focus:outline-none"
                onMouseEnter={() => setHoveredNode(n.id)}
                onMouseLeave={() => setHoveredNode(null)}
                onFocus={() => setHoveredNode(n.id)}
                onBlur={() => setHoveredNode(null)}
                onClick={() => go(n.path)}
                onKeyDown={(ev) => {
                  if (ev.key === 'Enter' || ev.key === ' ') {
                    ev.preventDefault();
                    go(n.path);
                  }
                }}
              >
                {isHovered && (
                  <ellipse cx={n.x} cy={n.y} rx={rx + 7} ry={ry + 6} fill="none" stroke={color} strokeWidth={1.5} opacity={0.5} />
                )}
                <ellipse
                  cx={n.x}
                  cy={n.y}
                  rx={rx}
                  ry={ry}
                  fill={`${color}${isHovered ? '30' : '18'}`}
                  stroke={color}
                  strokeWidth={isHovered || s > 1 ? 2 : 1}
                  strokeDasharray={n.referenceOnly ? '2 3' : undefined}
                  opacity={isHovered || s > 1 ? 1 : n.referenceOnly ? 0.7 : 0.85}
                  className="transition-all duration-200"
                />
                <text
                  x={n.x}
                  y={n.y + 1}
                  textAnchor="middle"
                  dominantBaseline="central"
                  fontSize={Math.round(11 * s)}
                  fontWeight={s > 1 ? 700 : 600}
                  fill={isHovered ? color : c.textPrimary}
                  className="pointer-events-none select-none transition-colors duration-200"
                >
                  {n.label}
                </text>
              </g>
            );
          })}

          {/* Tooltip, drawn last so it sits above every node */}
          {hovered &&
            (() => {
              const lines = wrap(hovered.description);
              const w = Math.max(200, Math.max(...lines.map((l) => l.length)) * 5 + 20);
              const lineH = 12;
              const padY = 6;
              const h = lines.length * lineH + padY * 2;
              const y = hovered.y < 120 ? hovered.y + 40 : hovered.y - (h + 14);
              const x = Math.min(Math.max(hovered.x, w / 2 + 4), MODEL_WIDTH - w / 2 - 4);
              return (
                <g className="pointer-events-none">
                  <rect x={x - w / 2} y={y} width={w} height={h} rx={4} fill={c.surfaceCard} stroke={c.borderColor} />
                  <text x={x} y={y + padY + 9} textAnchor="middle" fontSize={9} fill={c.textSecondary} className="select-none">
                    {lines.map((line, i) => (
                      <tspan key={i} x={x} dy={i === 0 ? 0 : lineH}>
                        {line}
                      </tspan>
                    ))}
                  </text>
                </g>
              );
            })()}
        </svg>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-t border-[var(--border-color)] px-4 py-3 md:px-6">
        <div className="flex flex-wrap items-center gap-4">
          {CATEGORIES.map((cat) => {
            const off = hidden.has(cat.key);
            return (
              <button
                key={cat.key}
                type="button"
                onClick={() => toggle(cat.key)}
                aria-pressed={!off}
                className={`flex items-center gap-1.5 transition-opacity hover:opacity-80 ${off ? 'opacity-40' : 'opacity-100'}`}
                title={off ? `Show ${cat.label}` : `Hide ${cat.label}`}
              >
                <span
                  aria-hidden="true"
                  className="h-2.5 w-2.5 rounded-full"
                  style={{ backgroundColor: resolveColor(c, cat.token), opacity: off ? 0.3 : 0.75 }}
                />
                <span className={`text-[10px] text-[var(--text-secondary)] ${off ? 'line-through' : ''}`}>{cat.label}</span>
              </button>
            );
          })}
        </div>
        <div className="flex flex-wrap items-center gap-4 text-[10px] text-[var(--text-secondary)]">
          <span className="flex items-center gap-1.5">
            <svg width="20" height="2" aria-hidden="true">
              <line x1="0" y1="1" x2="20" y2="1" stroke={c.borderColor} strokeWidth="1" />
            </svg>
            direct relationship
          </span>
          <span className="flex items-center gap-1.5">
            <svg width="20" height="2" aria-hidden="true">
              <line x1="0" y1="1" x2="20" y2="1" stroke={c.borderColor} strokeWidth="1" strokeDasharray="4 3" />
            </svg>
            enrichment / mapping
          </span>
          <span className="flex items-center gap-1.5">
            <svg width="14" height="10" aria-hidden="true">
              <ellipse cx="7" cy="5" rx="6" ry="4" fill="none" stroke={c.borderColor} strokeWidth="1" strokeDasharray="2 2" />
            </svg>
            reference only — nothing to join on
          </span>
        </div>
      </div>
    </div>
  );
}
