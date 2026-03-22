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
import type { TacticDistribution } from '../../lib/types';

interface TacticBarChartProps {
  data: TacticDistribution[];
  /** Called with the tactic's ATT&CK ID when a bar is clicked. */
  onBarClick?: (tacticId: string) => void;
}

const TEAL = '#64ffda';

/**
 * Horizontal bar chart showing technique count per tactic.
 * Bars are clickable when onBarClick is provided.
 */
export function TacticBarChart({ data, onBarClick }: TacticBarChartProps) {
  return (
    <ResponsiveContainer width="100%" height={320}>
      <BarChart
        layout="vertical"
        data={data}
        margin={{ top: 4, right: 24, left: 8, bottom: 4 }}
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        onClick={(payload: any) => {
          if (!onBarClick || !payload?.activePayload?.[0]) return;
          const entry = payload.activePayload[0].payload as TacticDistribution;
          if (entry.tacticId) onBarClick(entry.tacticId);
        }}
        style={{ cursor: onBarClick ? 'pointer' : 'default' }}
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
          dataKey="tacticName"
          width={130}
          tick={{ fill: '#ccd6f6', fontSize: 11 }}
          axisLine={false}
          tickLine={false}
        />
        <Tooltip
          cursor={{ fill: '#64ffda08' }}
          contentStyle={{
            background: '#16213e',
            border: '1px solid #2a2a4a',
            borderRadius: 6,
            color: '#ccd6f6',
            fontSize: 12,
          }}
          formatter={(value) => [value, 'Techniques']}
        />
        <Bar dataKey="count" radius={[0, 4, 4, 0]}>
          {data.map((entry, i) => (
            <Cell
              key={entry.tacticName}
              fill={TEAL}
              fillOpacity={0.7 + (i % 3) * 0.1}
            />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
