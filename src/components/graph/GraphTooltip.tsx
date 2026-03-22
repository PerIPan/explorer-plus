import type { ReactNode } from 'react';
interface GraphTooltipProps {
  x: number;
  y: number;
  content: ReactNode;
}

/**
 * Floating tooltip positioned near a graph node or edge.
 */
export function GraphTooltip({ x, y, content }: GraphTooltipProps) {
  return (
    <div
      className="
        fixed z-50 pointer-events-none
        bg-[#16213e] border border-[#2a2a4a] rounded-lg
        px-3 py-2 text-xs text-[#ccd6f6]
        shadow-xl max-w-[220px]
      "
      style={{ left: Math.min(x + 12, window.innerWidth - 260), top: y - 8 }}
    >
      {content}
    </div>
  );
}
