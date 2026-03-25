import { useCallback, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useReactActions } from '../hooks/useApi';
import { useFuseFilter } from '../hooks/useFuseFilter';
import { PageHeader } from '../components/layout/PageHeader';
import { Badge } from '../components/shared/Badge';
import type { ReactAction } from '../lib/types';
import { reactActionUrl } from '../lib/urlSafety';

const FUSE_KEYS = ['title', 'description', 'stage'];

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
  preparation:      'bg-[var(--blue-faint)] text-[var(--accent-blue)] border-[var(--blue-dim)]',
  identification:   'bg-[var(--yellow-faint)] text-[var(--accent-yellow)] border-[var(--yellow-dim)]',
  containment:      'bg-[var(--orange-faint)] text-[var(--accent-orange)] border-[var(--orange-dim)]',
  eradication:      'bg-[var(--pink-faint)] text-[var(--accent-pink)] border-[var(--pink-dim)]',
  recovery:         'bg-[var(--green-faint)] text-[var(--accent-green)] border-[var(--green-dim)]',
  lessons_learned:  'bg-[var(--purple-faint)] text-[var(--accent-purple)] border-[var(--purple-dim)]',
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
  if (!stage) return <span className="text-[var(--text-secondary)] text-xs">—</span>;
  const classes =
    STAGE_COLORS[stage as Stage] ?? 'bg-[var(--hover-overlay)] text-[var(--text-secondary)] border-[var(--border-color)]';
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
    <div className="rounded-lg bg-[var(--surface-card)] border border-[var(--border-color)] overflow-hidden">
      <button
        type="button"
        onClick={onToggle}
        className="w-full flex items-start gap-3 px-4 py-3 text-left hover:bg-[var(--hover-subtle)] transition-colors"
      >
        <a
          href={reactActionUrl(action.actionId, action.title)}
          target="_blank"
          rel="noopener noreferrer"
          onClick={(e) => e.stopPropagation()}
          className="font-mono text-xs text-[var(--accent-teal)] mt-0.5 shrink-0 w-16 hover:underline"
          title="View on ATC RE&CT docs"
        >
          {action.actionId} ↗
        </a>
        <span className="flex-1 text-[var(--text-primary)] text-sm select-text">{action.title}</span>
        <div className="flex items-center gap-2 shrink-0">
          <StageBadge stage={action.stage} />
          <svg
            className={`w-4 h-4 text-[var(--text-secondary)] transition-transform ${expanded ? 'rotate-180' : ''}`}
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
        <div className="px-4 pb-4 pt-1 space-y-3 border-t border-[var(--border-color)]">
          {action.description && (
            <div>
              <div className="text-[10px] font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-1">
                Description
              </div>
              <p className="text-[var(--text-secondary)] text-sm leading-relaxed whitespace-pre-wrap">
                {action.description}
              </p>
            </div>
          )}
          {action.workflow && (
            <div>
              <div className="text-[10px] font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-1">
                Workflow
              </div>
              <pre className="text-[var(--text-secondary)] text-xs leading-relaxed whitespace-pre-wrap font-mono bg-[var(--surface-deep)] rounded p-3">
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
  const [search, setSearch] = useState(searchParams.get('q') ?? '');

  const stage = searchParams.get('stage') ?? '';

  const params: Record<string, string> = { limit: '5000' };
  if (stage) params.stage = stage;

  const { data, isLoading } = useReactActions(params);

  const filteredData = useFuseFilter(data?.data ?? [], FUSE_KEYS, search);

  const setParam = useCallback(
    (key: string, value: string) => {
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        if (value) next.set(key, value);
        else next.delete(key);
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

  // Group Fuse-filtered actions by stage
  const grouped = STAGES.reduce<Record<string, ReactAction[]>>((acc, s) => {
    acc[s] = [];
    return acc;
  }, {} as Record<string, ReactAction[]>);

  const unstagedActions: ReactAction[] = [];
  for (const action of filteredData) {
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
        subtitle={`${data?.pagination?.total ?? 0} incident response actions across IR lifecycle stages`}
      />

      {/* Info banner */}
      <div className="px-4 py-3 rounded-lg bg-[var(--surface-card)] border border-[var(--border-color)] text-sm text-[var(--text-secondary)]">
        RE&CT is an Incident Response framework by the ATC Project that maps
        response actions to the IR lifecycle. Actions cover detection, analysis,
        containment, and recovery phases.{' '}
        <a
          href="https://github.com/atc-project/atc-react"
          target="_blank"
          rel="noopener noreferrer"
          className="text-[var(--accent-teal)] hover:underline"
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
          onChange={(e) => setSearch(e.target.value)}
          className="
            flex-1 min-w-[200px] max-w-sm px-3 py-2 rounded-md text-sm
            bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)]
            placeholder:text-[var(--text-secondary)]
            focus:outline-none focus:ring-1 focus:ring-[var(--accent-teal)] focus:border-[var(--accent-teal)]
          "
        />
        <select
          value={stage}
          onChange={(e) => setParam('stage', e.target.value)}
          className="
            px-3 py-2 rounded-md text-sm
            bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)]
            focus:outline-none focus:ring-1 focus:ring-[var(--accent-teal)] focus:border-[var(--accent-teal)]
          "
        >
          <option value="">All stages</option>
          {STAGES.map((s) => (
            <option key={s} value={s}>{STAGE_LABELS[s]}</option>
          ))}
        </select>
      </div>

      {isLoading ? (
        <div className="flex items-center gap-2 text-[var(--text-secondary)] text-sm py-6">
          <span className="inline-block w-4 h-4 border-2 border-[var(--teal-dim)] border-t-[var(--accent-teal)] rounded-full animate-spin" />
          Loading...
        </div>
      ) : (
        <div className="space-y-8">
          {filteredStages.map((s) => {
            const actions = grouped[s];
            if (!actions || actions.length === 0) return null;
            return (
              <section key={s}>
                <h3 className="flex items-center gap-2 text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-3">
                  <StageBadge stage={s} />
                  <span>{STAGE_LABELS[s]}</span>
                  <span className="text-[var(--text-secondary)] font-normal normal-case tracking-normal">
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
              <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-3">
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

          {filteredData.length === 0 && (
            <p className="text-[var(--text-secondary)] text-sm py-6">
              {search ? 'No actions match your search.' : 'No RE&CT actions found. Run the sync script to populate data.'}
            </p>
          )}
        </div>
      )}
    </div>
  );
}
