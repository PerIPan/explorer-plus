import { useCallback, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useReactActions } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { Badge } from '../components/shared/Badge';
import type { ReactAction } from '../lib/types';

const STAGES = [
  'preparation',
  'identification',
  'containment',
  'eradication',
  'recovery',
  'lessons_learned',
] as const;

type Stage = typeof STAGES[number];

const STAGE_COLORS: Record<Stage, string> = {
  preparation:      'bg-[#60a5fa18] text-[#60a5fa] border-[#60a5fa33]',
  identification:   'bg-[#fbbf2418] text-[#fbbf24] border-[#fbbf2433]',
  containment:      'bg-[#f9731618] text-[#f97316] border-[#f9731633]',
  eradication:      'bg-[#f472b618] text-[#f472b6] border-[#f472b633]',
  recovery:         'bg-[#34d39918] text-[#34d399] border-[#34d39933]',
  lessons_learned:  'bg-[#a78bfa18] text-[#a78bfa] border-[#a78bfa33]',
};

const STAGE_LABELS: Record<Stage, string> = {
  preparation:     'Preparation',
  identification:  'Identification',
  containment:     'Containment',
  eradication:     'Eradication',
  recovery:        'Recovery',
  lessons_learned: 'Lessons Learned',
};

function StageBadge({ stage }: { stage: string | null }) {
  if (!stage) return <span className="text-[#8892b0] text-xs">—</span>;
  const classes =
    STAGE_COLORS[stage as Stage] ?? 'bg-[#ffffff08] text-[#8892b0] border-[#2a2a4a]';
  const label = STAGE_LABELS[stage as Stage] ?? stage;
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${classes}`}
    >
      {label}
    </span>
  );
}

function ActionCard({
  action,
  expanded,
  onToggle,
}: {
  action: ReactAction;
  expanded: boolean;
  onToggle: () => void;
}) {
  return (
    <div className="rounded-lg bg-[#16213e] border border-[#2a2a4a] overflow-hidden">
      <button
        type="button"
        onClick={onToggle}
        className="w-full flex items-start gap-3 px-4 py-3 text-left hover:bg-[#ffffff05] transition-colors"
      >
        <span className="font-mono text-xs text-[#64ffda] mt-0.5 shrink-0 w-16">
          {action.actionId}
        </span>
        <span className="flex-1 text-[#ccd6f6] text-sm">{action.title}</span>
        <div className="flex items-center gap-2 shrink-0">
          <StageBadge stage={action.stage} />
          <svg
            className={`w-4 h-4 text-[#8892b0] transition-transform ${expanded ? 'rotate-180' : ''}`}
            fill="none"
            stroke="currentColor"
            strokeWidth={2}
            viewBox="0 0 24 24"
            aria-hidden="true"
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </button>

      {expanded && (
        <div className="px-4 pb-4 pt-1 space-y-3 border-t border-[#2a2a4a]">
          {action.description && (
            <div>
              <div className="text-[10px] font-semibold text-[#a8b2d8] uppercase tracking-wider mb-1">
                Description
              </div>
              <p className="text-[#8892b0] text-sm leading-relaxed whitespace-pre-wrap">
                {action.description}
              </p>
            </div>
          )}
          {action.workflow && (
            <div>
              <div className="text-[10px] font-semibold text-[#a8b2d8] uppercase tracking-wider mb-1">
                Workflow
              </div>
              <pre className="text-[#8892b0] text-xs leading-relaxed whitespace-pre-wrap font-mono bg-[#0a0a1a] rounded p-3">
                {action.workflow}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export function ReactActions() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());

  const search = searchParams.get('search') ?? '';
  const stage  = searchParams.get('stage') ?? '';
  const page   = parseInt(searchParams.get('page') ?? '1', 10);

  const params: Record<string, string> = { page: String(page), limit: '100' };
  if (search) params.search = search;
  if (stage) params.stage = stage;

  const { data, isLoading } = useReactActions(params);

  const setParam = useCallback(
    (key: string, value: string) => {
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        if (value) next.set(key, value);
        else next.delete(key);
        if (key !== 'page') next.delete('page');
        return next;
      });
    },
    [setSearchParams],
  );

  const toggleExpanded = useCallback((id: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  // Group actions by stage
  const grouped = STAGES.reduce<Record<string, ReactAction[]>>((acc, s) => {
    acc[s] = [];
    return acc;
  }, {} as Record<string, ReactAction[]>);

  const unstagedActions: ReactAction[] = [];
  for (const action of data?.data ?? []) {
    if (action.stage && action.stage in grouped) {
      grouped[action.stage].push(action);
    } else {
      unstagedActions.push(action);
    }
  }

  const filteredStages = stage
    ? STAGES.filter((s) => s === stage)
    : STAGES;

  return (
    <div className="space-y-6">
      <PageHeader
        title="RE&CT Response Actions"
        subtitle={`${data?.pagination.total ?? 0} incident response actions across IR lifecycle stages`}
      />

      {/* Info banner */}
      <div className="px-4 py-3 rounded-lg bg-[#16213e] border border-[#2a2a4a] text-sm text-[#8892b0]">
        RE&CT is an Incident Response framework by the ATC Project that maps
        response actions to the IR lifecycle. Actions cover detection, analysis,
        containment, and recovery phases.{' '}
        <a
          href="https://github.com/atc-project/atc-react"
          target="_blank"
          rel="noopener noreferrer"
          className="text-[#64ffda] hover:underline"
        >
          atc-project/atc-react
        </a>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <input
          type="search"
          placeholder="Search actions..."
          value={search}
          onChange={(e) => setParam('search', e.target.value)}
          className="
            flex-1 min-w-[200px] max-w-sm px-3 py-2 rounded-md text-sm
            bg-[#16213e] border border-[#2a2a4a] text-[#ccd6f6]
            placeholder:text-[#4a5568]
            focus:outline-none focus:ring-1 focus:ring-[#64ffda] focus:border-[#64ffda]
          "
        />
        <select
          value={stage}
          onChange={(e) => setParam('stage', e.target.value)}
          className="
            px-3 py-2 rounded-md text-sm
            bg-[#16213e] border border-[#2a2a4a] text-[#ccd6f6]
            focus:outline-none focus:ring-1 focus:ring-[#64ffda] focus:border-[#64ffda]
          "
        >
          <option value="">All stages</option>
          {STAGES.map((s) => (
            <option key={s} value={s}>{STAGE_LABELS[s]}</option>
          ))}
        </select>
      </div>

      {isLoading ? (
        <div className="flex items-center gap-2 text-[#8892b0] text-sm py-6">
          <span className="inline-block w-4 h-4 border-2 border-[#64ffda33] border-t-[#64ffda] rounded-full animate-spin" />
          Loading...
        </div>
      ) : (
        <div className="space-y-8">
          {filteredStages.map((s) => {
            const actions = grouped[s];
            if (!actions || actions.length === 0) return null;
            return (
              <section key={s}>
                <h3 className="flex items-center gap-2 text-sm font-semibold text-[#a8b2d8] uppercase tracking-wider mb-3">
                  <StageBadge stage={s} />
                  <span>{STAGE_LABELS[s]}</span>
                  <span className="text-[#8892b0] font-normal normal-case tracking-normal">
                    ({actions.length})
                  </span>
                </h3>
                <div className="space-y-2">
                  {actions.map((action) => (
                    <ActionCard
                      key={action.actionId}
                      action={action}
                      expanded={expandedIds.has(action.actionId)}
                      onToggle={() => toggleExpanded(action.actionId)}
                    />
                  ))}
                </div>
              </section>
            );
          })}

          {unstagedActions.length > 0 && (
            <section>
              <h3 className="text-sm font-semibold text-[#a8b2d8] uppercase tracking-wider mb-3">
                Other ({unstagedActions.length})
              </h3>
              <div className="space-y-2">
                {unstagedActions.map((action) => (
                  <ActionCard
                    key={action.actionId}
                    action={action}
                    expanded={expandedIds.has(action.actionId)}
                    onToggle={() => toggleExpanded(action.actionId)}
                  />
                ))}
              </div>
            </section>
          )}

          {(data?.data ?? []).length === 0 && (
            <p className="text-[#8892b0] text-sm py-6">
              No RE&CT actions found. Run the sync script to populate data.
            </p>
          )}
        </div>
      )}
    </div>
  );
}
