import { useNavigate } from 'react-router-dom';
import type { MatrixTechniqueCell } from '../../lib/types';

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
  const ratio = maxUsage > 0 ? groupUsageCount / maxUsage : 0;

  /** Interpolate opacity from 0.08 (unused) to 0.75 (most used) */
  const tealOpacity = groupUsageCount === 0
    ? 0
    : Math.round((0.12 + ratio * 0.63) * 100) / 100;

  const bgStyle =
    groupUsageCount > 0
      ? { backgroundColor: `rgba(100,255,218,${tealOpacity})` }
      : {};

  return (
    <button
      type="button"
      title={`${technique.attackId} — ${technique.name}${groupUsageCount > 0 ? ` (${groupUsageCount} groups)` : ''}`}
      onClick={() => navigate(`/techniques/${technique.attackId}`)}
      className="
        w-full text-left px-1.5 py-1 rounded text-[10px] leading-tight
        border border-[#2a2a4a] transition-all duration-150
        hover:border-[#64ffda55] hover:brightness-125 focus:outline-none
        focus:ring-1 focus:ring-[#64ffda55]
        cursor-pointer
      "
      style={bgStyle}
    >
      <div className="font-mono text-[9px] text-[#8892b0] mb-0.5">
        {technique.attackId}
      </div>
      <div
        className="text-[#ccd6f6] overflow-hidden"
        style={{
          display: '-webkit-box',
          WebkitLineClamp: 2,
          WebkitBoxOrient: 'vertical',
        }}
      >
        {technique.name}
      </div>
      {technique.subTechniques.length > 0 && (
        <div className="text-[9px] text-[#64ffda88] mt-0.5">
          +{technique.subTechniques.length} sub
        </div>
      )}
    </button>
  );
}
