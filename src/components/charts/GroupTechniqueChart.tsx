import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';
import type { TopGroup } from '../../lib/types';

interface GroupTechniqueChartProps {
  data: TopGroup[];
}

/**
 * Horizontal bar chart for top groups by technique count.
 */
export function GroupTechniqueChart({ data }: GroupTechniqueChartProps) {
  return (
    <ResponsiveContainer width="100%" height={280}>
      <BarChart
        layout="vertical"
        data={data}
        margin={{ top: 4, right: 24, left: 8, bottom: 4 }}
      >
        <CartesianGrid
          strokeDasharray="3 3"
          stroke="#2a2a4a"
          horizontal={false}
        />
        <XAxis
          type="number"
          tick={{ fill: '#8892b0', fontSize: 11 }}
          axisLine={{ stroke: '#2a2a4a' }}
          tickLine={false}
        />
        <YAxis
          type="category"
          dataKey="name"
          width={100}
          tick={{ fill: '#ccd6f6', fontSize: 11 }}
          axisLine={false}
          tickLine={false}
        />
        <Tooltip
          cursor={{ fill: '#f9731608' }}
          contentStyle={{
            background: '#16213e',
            border: '1px solid #2a2a4a',
            borderRadius: 6,
            color: '#ccd6f6',
            fontSize: 12,
          }}
          formatter={(value: number) => [value, 'Techniques']}
        />
        <Bar dataKey="techniqueCount" radius={[0, 4, 4, 0]}>
          {data.map((entry, i) => (
            <Cell key={entry.attackId} fill="#f97316" fillOpacity={0.75 + (i % 4) * 0.05} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
