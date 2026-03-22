import { Link } from 'react-router-dom';
import type { EntityType } from '../../lib/types';

interface EntityLinkProps {
  type: EntityType;
  attackId: string;
  name: string;
  className?: string;
}

const entityConfig: Record<
  EntityType,
  { color: string; bg: string; border: string; path: string }
> = {
  technique: {
    color: 'text-[#64ffda]',
    bg: 'bg-[#64ffda18]',
    border: 'border-[#64ffda33]',
    path: 'techniques',
  },
  group: {
    color: 'text-[#f97316]',
    bg: 'bg-[#f9731618]',
    border: 'border-[#f9731633]',
    path: 'groups',
  },
  software: {
    color: 'text-[#a78bfa]',
    bg: 'bg-[#a78bfa18]',
    border: 'border-[#a78bfa33]',
    path: 'software',
  },
  mitigation: {
    color: 'text-[#34d399]',
    bg: 'bg-[#34d39918]',
    border: 'border-[#34d39933]',
    path: 'mitigations',
  },
  campaign: {
    color: 'text-[#60a5fa]',
    bg: 'bg-[#60a5fa18]',
    border: 'border-[#60a5fa33]',
    path: 'campaigns',
  },
  data_source: {
    color: 'text-[#f472b6]',
    bg: 'bg-[#f472b618]',
    border: 'border-[#f472b633]',
    path: 'data-sources',
  },
  tactic: {
    color: 'text-[#fbbf24]',
    bg: 'bg-[#fbbf2418]',
    border: 'border-[#fbbf2433]',
    path: 'tactics',
  },
};

/**
 * Color-coded pill that links to an entity's detail page.
 */
export function EntityLink({ type, attackId, name, className = '' }: EntityLinkProps) {
  const { color, bg, border, path } = entityConfig[type];
  return (
    <Link
      to={`/${path}/${attackId}`}
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
