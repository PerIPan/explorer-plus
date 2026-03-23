import { useTheme } from '../../contexts/ThemeContext';

/**
 * Color scale legend for the ATT&CK matrix heat map.
 */
export function MatrixLegend() {
  const { theme } = useTheme();
  const steps = [0, 0.15, 0.30, 0.50, 0.65, 0.80, 1.0];
  const emptyBg = theme === 'dark' ? '#16213e' : '#ffffff';
  const heatColor = theme === 'dark' ? 'rgba(100,255,218,' : 'rgba(13,148,136,';

  return (
    <div className="flex items-center gap-3 text-xs text-[var(--text-secondary)]">
      <span title="Color intensity = number of sub-techniques (proxy for group usage frequency)">
        Sub-technique count:
      </span>
      <span>None</span>
      <div className="flex rounded overflow-hidden border border-[var(--border-color)]">
        {steps.map((opacity, i) => (
          <div
            key={i}
            className="w-6 h-4"
            style={{
              backgroundColor:
                opacity === 0
                  ? emptyBg
                  : `${heatColor}${0.12 + opacity * 0.63})`,
            }}
            aria-hidden="true"
          />
        ))}
      </div>
      <span>High</span>
    </div>
  );
}
