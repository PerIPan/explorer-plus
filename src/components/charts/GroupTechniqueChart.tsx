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
import { useThemeColors } from '../../hooks/useThemeColors';

interface GroupTechniqueChartProps {
  data: TopGroup[];
  /** Called with the group's ATT&CK ID when a bar is clicked. */
  onBarClick?: (attackId: string) => void;
}

/**
 * Horizontal bar chart for top groups by technique count.
 * Bars are clickable when onBarClick is provided.
 */
export function GroupTechniqueChart({ data, onBarClick }: GroupTechniqueChartProps) {
  const c = useThemeColors();

  return (
    <ResponsiveContainer width="100%" height={280}>
      <BarChart
        layout="vertical"
        data={data}
        margin={{ top: 4, right: 24, left: 8, bottom: 4 }}
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        onClick={(payload: any) => {
          if (!onBarClick || !payload?.activePayload?.[0]) return;
          const entry = payload.activePayload[0].payload as TopGroup;
          if (entry.attackId) onBarClick(entry.attackId);
        }}
        style={{ cursor: onBarClick ? 'pointer' : 'default' }}
      >
        <CartesianGrid
          strokeDasharray="3 3"
          stroke={c.borderColor}
          horizontal={false}
        />
        <XAxis
          type="number"
          tick={{ fill: c.textSecondary, fontSize: 11 }}
          axisLine={{ stroke: c.borderColor }}
          tickLine={false}
        />
        <YAxis
          type="category"
          dataKey="name"
          width={100}
          tick={{ fill: c.textPrimary, fontSize: 11 }}
          axisLine={false}
          tickLine={false}
        />
        <Tooltip
          cursor={{ fill: `${c.accentOrange}08` }}
          contentStyle={{
            background: c.surfaceCard,
            border: `1px solid ${c.borderColor}`,
            borderRadius: 6,
            fontSize: 12,
          }}
          labelStyle={{ color: c.textSecondary }}
          itemStyle={{ color: c.textPrimary }}
          formatter={(value) => [value, 'Techniques']}
        />
        <Bar dataKey="techniqueCount" radius={[0, 4, 4, 0]}>
          {data.map((entry, i) => (
            <Cell key={entry.attackId} fill={c.accentOrange} fillOpacity={0.75 + (i % 4) * 0.05} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
