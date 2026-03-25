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
import { useThemeColors } from '../../hooks/useThemeColors';

interface TacticBarChartProps {
  data: TacticDistribution[];
  /** Called with the tactic's ATT&CK ID when a bar is clicked. */
  onBarClick?: (tacticId: string) => void;
}

/**
 * Horizontal bar chart showing technique count per tactic.
 * Bars are clickable when onBarClick is provided.
 */
export function TacticBarChart({ data, onBarClick }: TacticBarChartProps) {
  const c = useThemeColors();

  // Show domain prefix only when multiple domains are present (All Domains mode)
  const uniqueDomains = new Set(data.map((d) => d.domain).filter(Boolean));
  const multiDomain = uniqueDomains.size > 1;
  const chartData = data.map((d) => ({
    ...d,
    label: multiDomain && d.domain
      ? `[${d.domain.replace('-attack', '').replace('enterprise', 'ENT').toUpperCase()}] ${d.tacticName}`
      : d.tacticName,
  }));

  return (
    <ResponsiveContainer width="100%" height={Math.max(320, chartData.length * 40)}>
      <BarChart
        layout="vertical"
        data={chartData}
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
          dataKey="label"
          width={220}
          tick={{ fill: c.textPrimary, fontSize: 11 }}
          axisLine={false}
          tickLine={false}
        />
        <Tooltip
          cursor={{ fill: `${c.accentTeal}08` }}
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
        <Bar dataKey="count" radius={[0, 4, 4, 0]}>
          {data.map((entry, i) => (
            <Cell
              key={entry.tacticName}
              fill={c.accentTeal}
              fillOpacity={0.7 + (i % 3) * 0.1}
            />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
