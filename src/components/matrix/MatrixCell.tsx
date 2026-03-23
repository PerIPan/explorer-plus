import { useNavigate } from 'react-router-dom';
import type { MatrixTechniqueCell } from '../../lib/types';
import { useTheme } from '../../contexts/ThemeContext';

interface MatrixCellProps {
  technique: MatrixTechniqueCell;
  groupUsageCount: number;
  maxUsage: number;
}

/**
 * A single cell in the ATT&CK matrix.
 * Background intensity scales with groupUsageCount relative to maxUsage.
 */
export function MatrixCell({ technique, groupUsageCount, maxUsage }: MatrixCellProps) {
  const navigate = useNavigate();
  const { theme } = useTheme();
  const ratio = maxUsage > 0 ? groupUsageCount / maxUsage : 0;

  /** Interpolate opacity from 0.08 (unused) to 0.75 (most used) */
  const tealOpacity = groupUsageCount === 0
    ? 0
    : Math.round((0.12 + ratio * 0.63) * 100) / 100;

  const heatColor = theme === 'dark' ? 'rgba(100,255,218,' : 'rgba(13,148,136,';
  const bgStyle =
    groupUsageCount > 0
      ? { backgroundColor: `${heatColor}${tealOpacity})` }
      : {};

  return (
    <button
      type="button"
      title={`${technique.attackId} — ${technique.name}${groupUsageCount > 0 ? ` (${groupUsageCount} groups)` : ''}`}
      onClick={() => navigate(`/techniques/${technique.attackId}`)}
      className="
        w-full text-left px-1.5 py-1 rounded text-[11px] leading-tight
        border border-[var(--border-color)] transition-all duration-150
        hover:border-[var(--teal-muted)] hover:brightness-125 focus:outline-none
        focus:ring-1 focus:ring-[var(--teal-muted)]
        cursor-pointer
      "
      style={bgStyle}
    >
      <div className="font-mono text-[10px] text-[var(--text-secondary)] mb-0.5">
        {technique.attackId}
      </div>
      <div
        className="text-[var(--text-primary)] overflow-hidden"
        style={{
          display: '-webkit-box',
          WebkitLineClamp: 2,
          WebkitBoxOrient: 'vertical',
        }}
      >
        {technique.name}
      </div>
      {technique.subTechniques.length > 0 && (
        <div className="text-[10px] text-[var(--accent-teal)] font-medium mt-0.5">
          ▸ {technique.subTechniques.length} sub
        </div>
      )}
    </button>
  );
}
