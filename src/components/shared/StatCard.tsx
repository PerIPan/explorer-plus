import { Link } from 'react-router-dom';

interface StatCardProps {
  label: string;
  value: number | string;
  /** Accent color class for the value. Defaults to teal. */
  accent?: string;
  description?: string;
  /** If provided, card is rendered as a link to this path. */
  href?: string;
  /** Border color on hover (e.g. 'hover:border-[#64ffda]'). Used when href is set. */
  hoverBorder?: string;
}

/**
 * Dashboard stat card — shows a large number with a label.
 * Optionally wrapped in a Link when href is provided.
 */
export function StatCard({
  label,
  value,
  accent = 'text-[#64ffda]',
  description,
  href,
  hoverBorder = 'hover:border-[#64ffda]',
}: StatCardProps) {
  const inner = (
    <>
      <div className={`text-3xl font-bold tabular-nums ${accent}`}>
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>
      <div className="text-sm font-medium text-[#ccd6f6]">{label}</div>
      {description && (
        <div className="text-xs text-[#8892b0] mt-0.5">{description}</div>
      )}
    </>
  );

  const baseClass = `bg-[#16213e] border border-[#2a2a4a] rounded-lg p-5 flex flex-col gap-1 transition-colors duration-150`;

  if (href) {
    return (
      <Link
        to={href}
        className={`${baseClass} ${hoverBorder} cursor-pointer`}
      >
        {inner}
      </Link>
    );
  }

  return <div className={baseClass}>{inner}</div>;
}
