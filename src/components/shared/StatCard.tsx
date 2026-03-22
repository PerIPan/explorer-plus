interface StatCardProps {
  label: string;
  value: number | string;
  /** Accent color class for the value. Defaults to teal. */
  accent?: string;
  description?: string;
}

/**
 * Dashboard stat card — shows a large number with a label.
 */
export function StatCard({
  label,
  value,
  accent = 'text-[#64ffda]',
  description,
}: StatCardProps) {
  return (
    <div className="bg-[#16213e] border border-[#2a2a4a] rounded-lg p-5 flex flex-col gap-1">
      <div className={`text-3xl font-bold tabular-nums ${accent}`}>
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>
      <div className="text-sm font-medium text-[#ccd6f6]">{label}</div>
      {description && (
        <div className="text-xs text-[#8892b0] mt-0.5">{description}</div>
      )}
    </div>
  );
}
