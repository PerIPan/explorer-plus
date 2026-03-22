import {
  useEffect,
  useRef,
  useCallback,
  useState,
  forwardRef,
  useImperativeHandle,
} from 'react';
import * as d3 from 'd3';
import type { GraphData, GraphNode, GraphEdge } from '../../lib/types';
import { GraphTooltip } from './GraphTooltip';

interface ForceGraphProps {
  data: GraphData;
  onNodeClick: (node: GraphNode) => void;
  width?: number;
  height?: number;
}

export interface ForceGraphHandle {
  reset: () => void;
}

/** Entity type → accent color mapping (mirrors EntityLink colors) */
const NODE_COLORS: Record<string, string> = {
  technique: '#64ffda',
  group: '#f97316',
  software: '#a78bfa',
  campaign: '#60a5fa',
  mitigation: '#34d399',
  data_source: '#f472b6',
  tactic: '#fbbf24',
};

function nodeColor(type: string): string {
  return NODE_COLORS[type] ?? '#8892b0';
}

interface SimNode extends d3.SimulationNodeDatum, GraphNode {}
interface SimEdge extends d3.SimulationLinkDatum<SimNode> {
  relationship: string;
  sourceId: string;
  targetId: string;
}

interface TooltipState {
  x: number;
  y: number;
  content: React.ReactNode;
}

/**
 * D3-powered force-directed graph.
 * Uses textContent only — never innerHTML — for all SVG text.
 */
export const ForceGraph = forwardRef<ForceGraphHandle, ForceGraphProps>(
  function ForceGraph({ data, onNodeClick, width = 1200, height = 800 }, ref) {
    const svgRef = useRef<SVGSVGElement>(null);
    const simulationRef = useRef<d3.Simulation<SimNode, SimEdge> | null>(null);
    const [tooltip, setTooltip] = useState<TooltipState | null>(null);

    useImperativeHandle(ref, () => ({
      reset() {
        simulationRef.current?.alpha(0.5).restart();
      },
    }));

    const hideTooltip = useCallback(() => setTooltip(null), []);

    useEffect(() => {
      const svg = d3.select(svgRef.current!);
      svg.selectAll('*').remove();

      if (!data.nodes.length && !data.center) return;

      // Include center node in the simulation
      const allNodeData = [data.center, ...data.nodes];
      const nodes: SimNode[] = allNodeData.map((n) => ({ ...n }));
      const nodeById = new Map(nodes.map((n) => [n.id, n]));

      const edges: SimEdge[] = data.edges
        .map((e) => ({
          source: nodeById.get(e.source) ?? e.source,
          target: nodeById.get(e.target) ?? e.target,
          relationship: e.relationship,
          sourceId: e.source,
          targetId: e.target,
        }))
        .filter((e) => e.source && e.target);

      /* ── Simulation ── */
      const sim = d3
        .forceSimulation<SimNode>(nodes)
        .force(
          'link',
          d3
            .forceLink<SimNode, SimEdge>(edges)
            .id((d) => d.id)
            .distance(90)
        )
        .force('charge', d3.forceManyBody().strength(-200))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collide', d3.forceCollide(22));
      simulationRef.current = sim;

      /* ── SVG setup ── */
      svg
        .attr('viewBox', `0 0 ${width} ${height}`)
        .attr('width', '100%')
        .attr('height', height)
        .style('background', '#0a0a1a');

      const g = svg.append('g');

      /* ── Zoom ── */
      const zoomBehavior = d3.zoom<SVGSVGElement, unknown>()
        .scaleExtent([0.2, 3])
        .on('zoom', (event) => g.attr('transform', event.transform));
      svg.call(zoomBehavior);

      /* ── Edge marker ── */
      svg
        .append('defs')
        .append('marker')
        .attr('id', 'arrow')
        .attr('viewBox', '0 -4 8 8')
        .attr('refX', 18)
        .attr('refY', 0)
        .attr('markerWidth', 6)
        .attr('markerHeight', 6)
        .attr('orient', 'auto')
        .append('path')
        .attr('d', 'M0,-4L8,0L0,4')
        .attr('fill', '#2a2a4a');

      /* ── Edges ── */
      const edgeSel = g
        .append('g')
        .selectAll<SVGLineElement, SimEdge>('line')
        .data(edges)
        .join('line')
        .attr('stroke', '#2a2a4a')
        .attr('stroke-width', 1.5)
        .attr('marker-end', 'url(#arrow)')
        .style('cursor', 'default');

      edgeSel
        .on('mousemove', (event, d) => {
          setTooltip({
            x: event.clientX,
            y: event.clientY,
            content: (
              <span className="text-[#8892b0]">
                {d.relationship}
              </span>
            ),
          });
        })
        .on('mouseleave', hideTooltip);

      /* ── Nodes (group) ── */
      const nodeSel = g
        .append('g')
        .selectAll<SVGGElement, SimNode>('g')
        .data(nodes)
        .join('g')
        .style('cursor', 'pointer')
        .call(
          d3
            .drag<SVGGElement, SimNode>()
            .on('start', (event, d) => {
              if (!event.active) sim.alphaTarget(0.3).restart();
              d.fx = d.x;
              d.fy = d.y;
            })
            .on('drag', (event, d) => {
              d.fx = event.x;
              d.fy = event.y;
            })
            .on('end', (event, d) => {
              if (!event.active) sim.alphaTarget(0);
              d.fx = null;
              d.fy = null;
            })
        );

      /* Outer ring on center node (FIX 32) */
      nodeSel
        .filter((d) => d.id === data.center.id)
        .append('circle')
        .attr('r', 20)
        .attr('fill', 'none')
        .attr('stroke', (d) => nodeColor(d.type))
        .attr('stroke-width', 1.5)
        .attr('opacity', 0.25);

      /* Circle */
      nodeSel
        .append('circle')
        .attr('r', (d) => (d.id === data.center.id ? 14 : 10))
        .attr('fill', (d) => nodeColor(d.type))
        .attr('fill-opacity', 0.18)
        .attr('stroke', (d) => nodeColor(d.type))
        .attr('stroke-width', (d) => (d.id === data.center.id ? 2.5 : 1.5));

      /* Label (textContent only) */
      nodeSel
        .append('text')
        .attr('y', 24)
        .attr('text-anchor', 'middle')
        .attr('font-size', 11)
        .attr('fill', '#8892b0')
        .attr('paint-order', 'stroke')
        .attr('stroke', '#0a0a1a')
        .attr('stroke-width', 3)
        .each(function (d) {
          // Use textContent — never innerHTML
          this.textContent = d.label.length > 18
            ? d.label.slice(0, 16) + '…'
            : d.label;
        });

      /* Click + hover */
      nodeSel
        .on('click', (_event, d) => onNodeClick(d))
        .on('mousemove', (event, d) => {
          setTooltip({
            x: event.clientX,
            y: event.clientY,
            content: (
              <div className="space-y-0.5">
                <div className="font-medium" style={{ color: nodeColor(d.type) }}>
                  {d.label}
                </div>
                {d.attackId && (
                  <div className="font-mono text-[#8892b0]">{d.attackId}</div>
                )}
                <div className="text-[#8892b0] capitalize">{d.type.replace('_', ' ')}</div>
              </div>
            ),
          });
        })
        .on('mouseleave', hideTooltip);

      /* ── Tick ── */
      sim.on('tick', () => {
        edgeSel
          .attr('x1', (d) => (d.source as SimNode).x ?? 0)
          .attr('y1', (d) => (d.source as SimNode).y ?? 0)
          .attr('x2', (d) => (d.target as SimNode).x ?? 0)
          .attr('y2', (d) => (d.target as SimNode).y ?? 0);

        nodeSel.attr('transform', (d) => `translate(${d.x ?? 0},${d.y ?? 0})`);
      });

      return () => {
        sim.stop();
        svg.on('.zoom', null);
      };
    }, [data, width, height, onNodeClick, hideTooltip]);

    return (
      <div className="relative">
        <svg ref={svgRef} className="rounded-lg border border-[#2a2a4a]" />
        {tooltip && (
          <GraphTooltip x={tooltip.x} y={tooltip.y} content={tooltip.content} />
        )}
      </div>
    );
  }
);
