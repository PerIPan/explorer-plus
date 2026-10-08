'use client';

import { useEffect } from 'react';
import { useSearchParams } from 'next/navigation';
import { useUpdateParams } from '../hooks/useUpdateParams';
import { useEmulationPlans, useEmulationPlan } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { EntityLink } from '../components/shared/EntityLink';
import { Badge } from '../components/shared/Badge';
import { DiamondLoader } from '../components/shared/FoldingDiamond';
import type { EmulationPlanSummary, EmulationResolution } from '../lib/types';

/**
 * MITRE CTID's adversary emulation plans, as ingested by
 * scripts/sync-emulation.mjs.
 *
 * Every technique link on this page is the plan's own `attack_id`, resolved
 * to current ATT&CK — nothing is inferred. Where resolution changed or lost
 * the id, the step says so (badge + the id the plan wrote), because a plan
 * written at ATT&CK v8 can name ids that have since been revoked or
 * deprecated. The group-overlap sentence is derived and labelled as such.
 *
 * `?plan=` opens one plan (the 360 cards link here); `?technique=` lists only
 * the plans that exercise that technique or its sub-techniques.
 */

const H2 = 'text-sm font-bold uppercase tracking-wider text-[var(--accent-teal)]';

const RESOLUTION: Record<EmulationResolution, { label: string; variant: 'teal' | 'yellow' | 'neutral' | 'orange' }> = {
  exact: { label: 'current', variant: 'teal' },
  deprecated: { label: 'deprecated', variant: 'yellow' },
  revoked_replaced: { label: 'id replaced', variant: 'yellow' },
  unresolved: { label: 'not in ATT&CK', variant: 'orange' },
  none: { label: 'no technique id', variant: 'neutral' },
};

export function EmulationPlans() {
  const searchParams = useSearchParams();
  const updateParams = useUpdateParams();
  const openPlan = searchParams.get('plan') ?? '';
  const technique = searchParams.get('technique')?.toUpperCase() ?? '';

  const { data, isLoading, error } = useEmulationPlans(technique ? { technique } : {});

  if (isLoading) return <DiamondLoader text="Loading emulation plans..." />;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Adversary Emulation Plans"
        subtitle="MITRE Center for Threat-Informed Defense plans that re-enact a named group's operations step by step — each step tied to the ATT&CK technique it exercises."
        breadcrumb={[{ label: 'Frameworks' }, { label: 'Emulation Plans' }]}
      />

      <section className="rounded-lg border border-[var(--border-color)] bg-[var(--surface-card)] p-4">
        <h2 className={`${H2} mb-2`}>How these connect to ATT&amp;CK</h2>
        <p className="text-sm text-[var(--text-secondary)] leading-relaxed">
          Each plan step names its technique; that id is resolved to current ATT&amp;CK, following revocations to
          their replacement. Technique links are not inferred; the group-overlap line under each plan is derived
          and says so. Steps whose id changed or could not be resolved are marked, with
          the id the plan wrote. Commands and payloads are not reproduced — they only run inside CTID&rsquo;s kit;
          each plan links to its source file. The same steps appear on each technique&rsquo;s 360 view under
          &ldquo;How to Test&rdquo;, and each plan on its group&rsquo;s profile.
        </p>
      </section>

      {error || !data ? (
        <p className="text-sm text-[var(--accent-orange)]">Failed to load emulation plans.</p>
      ) : !data.available ? (
        <p className="text-sm text-[var(--text-secondary)]">Emulation plans are not loaded on this deployment yet.</p>
      ) : (
        <section className="space-y-3">
          <div className="flex flex-wrap items-baseline gap-2">
            <h2 className={H2}>{technique ? `Plans exercising ${technique}` : 'Plans'}</h2>
            <span className="text-xs text-[var(--text-secondary)] tabular-nums">{data.data.length}</span>
            {technique && (
              <button
                type="button"
                onClick={() => updateParams({ technique: null })}
                className="text-xs text-[var(--accent-teal)] hover:underline"
              >
                show all plans
              </button>
            )}
          </div>
          {data.data.length === 0 && (
            <p className="text-sm text-[var(--text-secondary)]">No ingested plan exercises this technique.</p>
          )}
          {data.data.map((p) => (
            <PlanCard
              key={p.planKey}
              plan={p}
              open={openPlan === p.planKey}
              onToggle={() => updateParams({ plan: openPlan === p.planKey ? null : p.planKey })}
              highlight={technique}
            />
          ))}
        </section>
      )}

      {data && (
        <section>
          <h2 className={`${H2} mb-2`}>Not ingested</h2>
          <ul className="space-y-1.5">
            {data.notIngested.map((n) => (
              <li key={n.path} className="text-sm">
                <a
                  href={`${data.repo}/tree/master/${n.path}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[var(--accent-teal)] hover:underline"
                >
                  {n.label}
                </a>
                {n.attackGroupId && <span className="ml-1.5 font-mono text-xs text-[var(--text-secondary)]">{n.attackGroupId}</span>}
                <span className="text-[var(--text-secondary)]"> — {n.reason}</span>
              </li>
            ))}
          </ul>
        </section>
      )}

      <section>
        <h2 className={`${H2} mb-2`}>Source</h2>
        <p className="text-sm text-[var(--text-secondary)] leading-relaxed">
          MITRE Center for Threat-Informed Defense,{' '}
          <a
            href={data?.repo ?? 'https://github.com/center-for-threat-informed-defense/adversary_emulation_library'}
            target="_blank"
            rel="noopener noreferrer"
            className="text-[var(--accent-teal)] hover:underline"
          >
            Adversary Emulation Library
          </a>{' '}
          ({data?.license ?? 'Apache-2.0'}). Plan names, step names and descriptions are reproduced from the plan
          files; each plan links to the commit it was read at. Not affiliated with or endorsed by MITRE.
        </p>
      </section>
    </div>
  );
}

function PlanCard({
  plan,
  open,
  onToggle,
  highlight,
}: {
  plan: EmulationPlanSummary;
  open: boolean;
  onToggle: () => void;
  highlight: string;
}) {
  const cardId = `plan-${plan.planKey}`;
  // A ?plan= deep link (from a 360 card) opens the plan; bring it into view
  // once, on mount — not on every toggle, which would yank the page around.
  useEffect(() => {
    if (open) document.getElementById(cardId)?.scrollIntoView({ block: 'start' });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return (
    <div id={cardId} className="rounded-lg border border-[var(--border-color)] overflow-hidden scroll-mt-20">
      <div className="px-4 py-3 bg-[var(--surface-card)] space-y-1.5">
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={onToggle}
            aria-expanded={open}
            aria-controls={`${cardId}-steps`}
            className="text-sm font-semibold text-[var(--text-primary)] hover:text-[var(--accent-teal)] text-left"
          >
            <span aria-hidden="true">{open ? '▾' : '▸'}</span> {plan.name}
          </button>
          <EntityLink type="group" attackId={plan.groupAttackId} name={plan.groupName ?? plan.groupAttackId} useMap />
          <Badge label={`${plan.stepCount} steps`} variant="neutral" />
          <Badge label={`${plan.techniqueCount} techniques`} variant="teal" />
          {plan.unlinkedStepCount > 0 && <Badge label={`${plan.unlinkedStepCount} steps without a technique`} variant="neutral" />}
          {plan.attackVersion && (
            <span className="text-[11px] text-[var(--text-secondary)]">written for ATT&amp;CK v{plan.attackVersion}</span>
          )}
          <a
            href={plan.sourceUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="ml-auto text-[11px] text-[var(--accent-teal)] hover:underline"
          >
            source file ↗
          </a>
        </div>
        <p className="text-[11px] text-[var(--text-secondary)]">
          Derived: exercises {plan.overlapCount} of the {plan.groupTechniqueCount} Enterprise techniques ATT&amp;CK
          attributes to {plan.groupName ?? plan.groupAttackId} by exact id ({plan.familyOverlapCount} counting
          parent/sub-technique matches).
        </p>
      </div>
      {open && (
        <div id={`${cardId}-steps`}>
          <PlanSteps planKey={plan.planKey} highlight={highlight} />
        </div>
      )}
    </div>
  );
}

function PlanSteps({ planKey, highlight }: { planKey: string; highlight: string }) {
  const { data, isLoading, error } = useEmulationPlan(planKey);
  if (isLoading) return <div className="px-4 py-3 text-xs text-[var(--text-secondary)] italic">Loading steps...</div>;
  if (error || !data) return <div className="px-4 py-3 text-xs text-[var(--accent-orange)]">Failed to load steps.</div>;

  const matches = (id: string | null) => Boolean(highlight && id && (id === highlight || id.startsWith(`${highlight}.`)));

  return (
    <div className="overflow-x-auto bg-[var(--surface-alt)]">
      <table className="w-full text-xs">
        <thead className="text-[var(--text-secondary)] uppercase tracking-wider text-[10px]">
          <tr>
            <th className="text-left px-3 py-2">Step</th>
            <th className="text-left px-3 py-2">What it does</th>
            <th className="text-left px-3 py-2">Technique</th>
            <th className="text-left px-3 py-2">Tactic</th>
            <th className="text-left px-3 py-2">Platform</th>
          </tr>
        </thead>
        <tbody>
          {data.steps.map((s) => {
            const r = RESOLUTION[s.resolution];
            return (
              <tr
                key={s.ordinal}
                className={`border-t border-[var(--border-color)] align-top ${matches(s.resolvedAttackId) ? 'bg-[var(--teal-faint)]' : ''}`}
              >
                <td className="px-3 py-1.5 font-mono text-[var(--accent-orange)] whitespace-nowrap">
                  {s.procedureStep && s.procedureStep !== 'x' ? s.procedureStep : `#${s.ordinal}`}
                </td>
                <td className="px-3 py-1.5">
                  <div className="text-[var(--text-primary)]">{s.name}</div>
                  {s.description && (
                    <div className="text-[11px] text-[var(--text-secondary)] line-clamp-2">{s.description}</div>
                  )}
                </td>
                <td className="px-3 py-1.5">
                  <div className="flex flex-wrap items-center gap-1">
                    {s.resolvedAttackId ? (
                      <EntityLink
                        type="technique"
                        attackId={s.resolvedAttackId}
                        name={s.techniqueName ? `${s.resolvedAttackId} ${s.techniqueName}` : s.resolvedAttackId}
                        useMap
                      />
                    ) : null}
                    {s.resolution !== 'exact' && <Badge label={r.label} variant={r.variant} />}
                    {s.resolution === 'revoked_replaced' && s.upstreamAttackId && (
                      <span className="text-[10px] text-[var(--text-secondary)]">plan wrote {s.upstreamAttackId}</span>
                    )}
                  </div>
                </td>
                <td className="px-3 py-1.5 text-[var(--text-secondary)]">
                  {s.tactics?.length ? s.tactics.join(', ') : '—'}
                </td>
                <td className="px-3 py-1.5 text-[var(--text-secondary)]">{s.platforms.join(', ') || '—'}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
