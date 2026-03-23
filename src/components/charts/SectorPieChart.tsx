import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';
import type { SectorBreakdown } from '../../lib/types';

interface SectorPieChartProps {
  data: SectorBreakdown[];
}

const COLORS = [
  '#64ffda',
  '#f97316',
  '#a78bfa',
  '#60a5fa',
  '#34d399',
  '#f472b6',
  '#fbbf24',
  '#4ade80',
  '#fb7185',
  '#38bdf8',
];

/**
 * Pie chart showing group distribution by sector.
 */
export function SectorPieChart({ data }: SectorPieChartProps) {
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
              stroke="#0a0a1a"
              strokeWidth={2}
            />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{
            background: '#16213e',
            border: '1px solid #2a2a4a',
            borderRadius: 6,
            fontSize: 12,
          }}
          labelStyle={{ color: '#8892b0' }}
          itemStyle={{ color: '#ccd6f6' }}
          formatter={(value: any, name: any) => [value, name]}
        />
        <Legend
          formatter={(value: string) => (
            <span style={{ color: '#8892b0', fontSize: 11 }}>{value}</span>
          )}
        />
      </PieChart>
    </ResponsiveContainer>
  );
}
