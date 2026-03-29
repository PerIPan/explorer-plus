import { Link } from 'react-router-dom';
import type { EntityType } from '../../lib/types';

interface EntityLinkProps {
  type: EntityType;
  attackId: string;
  name: string;
  className?: string;
  /** Link to 360 map view instead of detail page */
  useMap?: boolean;
}

const entityConfig: Record<
  EntityType,
  { color: string; bg: string; border: string; path: string }
> = {
  technique: {
    color: 'text-[var(--accent-teal)]',
    bg: 'bg-[var(--teal-faint)]',
    border: 'border-[var(--teal-dim)]',
    path: 'techniques',
  },
  group: {
    color: 'text-[var(--accent-orange)]',
    bg: 'bg-[var(--orange-faint)]',
    border: 'border-[var(--orange-dim)]',
    path: 'groups',
  },
  software: {
    color: 'text-[var(--accent-purple)]',
    bg: 'bg-[var(--purple-faint)]',
    border: 'border-[var(--purple-dim)]',
    path: 'software',
  },
  mitigation: {
    color: 'text-[var(--accent-green)]',
    bg: 'bg-[var(--green-faint)]',
    border: 'border-[var(--green-dim)]',
    path: 'mitigations',
  },
  campaign: {
    color: 'text-[var(--accent-blue)]',
    bg: 'bg-[var(--blue-faint)]',
    border: 'border-[var(--blue-dim)]',
    path: 'campaigns',
  },
  data_source: {
    color: 'text-[var(--accent-neutral)]',
    bg: 'bg-[var(--neutral-faint)]',
    border: 'border-[var(--neutral-dim)]',
    path: 'data-sources',
  },
  tactic: {
    color: 'text-[var(--accent-yellow)]',
    bg: 'bg-[var(--yellow-faint)]',
    border: 'border-[var(--yellow-dim)]',
    path: 'tactics',
  },
};

const MAP_TABS: Record<EntityType, string> = {
  technique: 'technique-map',
  group: 'actor',
  software: 'software-map',
  mitigation: 'mitigation-map',
  campaign: 'actor',
  data_source: 'data-source-map',
  tactic: 'tactic-map',
};

/**
 * Color-coded pill that links to an entity's detail page or 360 map view.
 */
export function EntityLink({ type, attackId, name, className = '', useMap }: EntityLinkProps) {
  const { color, bg, border, path } = entityConfig[type];
  const href = useMap
    ? `/?entity=${encodeURIComponent(attackId)}&tab=${MAP_TABS[type]}`
    : `/${path}/${attackId}`;
  return (
    <Link
      to={href}
      title={`${attackId} — ${name}`}
      className={`
        inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-medium
        border ${color} ${bg} ${border}
        hover:brightness-125 hover:underline transition-all duration-150
        ${className}
      `}
    >
      <span className="opacity-70 font-mono">{attackId}</span>
      <span>{name}</span>
    </Link>
  );
}
