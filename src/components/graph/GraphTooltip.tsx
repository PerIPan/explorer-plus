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
        bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg
        px-3 py-2 text-xs text-[var(--text-primary)]
        shadow-xl max-w-[220px]
      "
      style={{
        left: Math.min(x + 12, window.innerWidth - 260),
        top: Math.max(8, Math.min(y - 8, window.innerHeight - 80)),
      }}
    >
      {content}
    </div>
  );
}
