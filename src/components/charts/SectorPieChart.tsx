import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';
import type { SectorBreakdown } from '../../lib/types';
import { useThemeColors } from '../../hooks/useThemeColors';

interface SectorPieChartProps {
  data: SectorBreakdown[];
}

/**
 * Pie chart showing group distribution by sector.
 */
export function SectorPieChart({ data }: SectorPieChartProps) {
  const c = useThemeColors();
  const COLORS = [
    c.accentTeal, c.accentOrange, c.accentPurple, c.accentBlue,
    c.accentGreen, c.accentPink, c.accentYellow,
    '#4ade80', '#fb7185', '#38bdf8',
  ];

  const chartData = data.map((d) => ({
    name: d.sectorName,
    value: d.groupCount,
  }));

  return (
    <ResponsiveContainer width="100%" height={320}>
      <PieChart>
        <Pie
          data={chartData}
          cx="50%"
          cy="45%"
          outerRadius={110}
          dataKey="value"
          labelLine={false}
        >
          {chartData.map((entry, i) => (
            <Cell
              key={entry.name}
              fill={COLORS[i % COLORS.length]}
              fillOpacity={0.85}
              stroke={c.surfaceDeep}
              strokeWidth={2}
            />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{
            background: c.surfaceCard,
            border: `1px solid ${c.borderColor}`,
            borderRadius: 6,
            fontSize: 12,
          }}
          labelStyle={{ color: c.textSecondary }}
          itemStyle={{ color: c.textPrimary }}
          formatter={(value: any, name: any) => [value, name]}
        />
        <Legend
          formatter={(value: string) => (
            <span style={{ color: c.textSecondary, fontSize: 11 }}>{value}</span>
          )}
        />
      </PieChart>
    </ResponsiveContainer>
  );
}
