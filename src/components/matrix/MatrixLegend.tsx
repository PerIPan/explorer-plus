/**
 * Color scale legend for the ATT&CK matrix heat map.
 */
export function MatrixLegend() {
  const steps = [0, 0.15, 0.30, 0.50, 0.65, 0.80, 1.0];

  return (
    <div className="flex items-center gap-3 text-xs text-[#8892b0]">
      <span title="Color intensity = number of sub-techniques (proxy for group usage frequency)">
        Sub-technique count:
      </span>
      <span>None</span>
      <div className="flex rounded overflow-hidden border border-[#2a2a4a]">
        {steps.map((opacity, i) => (
          <div
            key={i}
            className="w-6 h-4"
            style={{
              backgroundColor:
                opacity === 0
                  ? '#16213e'
                  : `rgba(100,255,218,${0.12 + opacity * 0.63})`,
            }}
            aria-hidden="true"
          />
        ))}
      </div>
      <span>High</span>
    </div>
  );
}
