import { useMemo } from 'react';
import type { MatrixData } from '../../lib/types';
import { MatrixCell } from './MatrixCell';
import { MatrixLegend } from './MatrixLegend';

interface MatrixGridProps {
  data: MatrixData;
  platformFilter: string;
}

/**
 * Full ATT&CK matrix — tactics as columns, techniques as cells.
 * groupUsageCount is derived from the number of sub-techniques + a mock usage
 * since the API's MatrixData doesn't include usage counts directly.
 * We use subTechniques.length as a rough proxy for "richness".
 */
export function MatrixGrid({ data, platformFilter }: MatrixGridProps) {
  const filtered = useMemo(() => {
    if (!platformFilter) return data;
    return data.map((col) => ({
      ...col,
      techniques: col.techniques.filter((t) => {
        /** MatrixTechniqueCell doesn't carry platforms — filter at column level isn't possible,
         *  so we show all techniques when platform filter is active (API doesn't return platform per cell).
         *  Filtering would require a separate API call; we mark this as best-effort. */
        return true;
      }),
    }));
  }, [data, platformFilter]);

  /** Compute max sub-technique count for color scaling */
  const maxUsage = useMemo(() => {
    let max = 0;
    filtered.forEach((col) =>
      col.techniques.forEach((t) => {
        if (t.subTechniques.length > max) max = t.subTechniques.length;
      })
    );
    return max || 1;
  }, [filtered]);

  return (
    <div className="space-y-3">
      <MatrixLegend />

      <div className="overflow-x-auto">
        <div
          className="inline-flex gap-1 min-w-max pb-2"
          role="grid"
          aria-label="ATT&CK Matrix"
        >
          {filtered.map((col) => (
            <div
              key={col.tactic.attackId}
              className="w-[120px] flex-shrink-0"
              role="columnheader"
            >
              {/* Tactic header */}
              <div
                className="
                  bg-[#1a1a2e] border border-[#2a2a4a] rounded-t px-2 py-2 mb-1
                  text-center text-[11px] font-semibold text-[#fbbf24] uppercase tracking-wide
                  sticky top-0 z-10
                "
              >
                <div>{col.tactic.name}</div>
                <div className="text-[9px] text-[#8892b0] font-normal font-mono mt-0.5">
                  {col.tactic.attackId}
                </div>
              </div>

              {/* Technique cells */}
              <div className="flex flex-col gap-0.5">
                {col.techniques.map((tech) => (
                  <MatrixCell
                    key={tech.attackId}
                    technique={tech}
                    groupUsageCount={tech.subTechniques.length}
                    maxUsage={maxUsage}
                  />
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
