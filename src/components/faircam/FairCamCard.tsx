'use client';

import { useFairCamCoverage } from '../../hooks/useApi';
import { techniqueState, detectionState, missingSources, PREVENTION, RESPONSE, NOT_MODELLED } from '../../lib/fair-cam-state.mjs';
import { FN_NAME, FN_UNIT, GROUP_OF, DOMAIN_PLURAL, StateBadge, StateLegend, ControlChips, useDomainSources, FairCamAttribution } from './shared';
import { FAIR_CAM_FUNCTIONS } from '../../lib/fair-cam.mjs';
import type { FairCamCoverage, FairCamTechniqueRow } from '../../lib/types';

/**
 * The technique 360 "FAIR-CAM lens": this technique's candidate controls,
 * sorted into FAIR-CAM functions. Lazy-loaded by TechniqueMapView and mounted
 * only when its card is opened, so neither this code nor the coverage
 * response is fetched for a visitor who never looks.
 *
 * It reads the same coverage response as the profile and group panels, so the
 * three can never disagree about a technique.
 */

/** Functions outside the three Loss Event sides — Variance Management and Decision Support. Monitoring is never a candidate. */
const isSupport = (fn: string) =>
  !PREVENTION.includes(fn) && !RESPONSE.includes(fn) && fn !== 'visibility' && fn !== 'recognition' && !NOT_MODELLED.includes(fn);

function FnLine({ fn, row, data, extra }: { fn: string; row: FairCamTechniqueRow; data: FairCamCoverage; extra?: React.ReactNode }) {
  const ids = row.functions[fn] ?? [];
  const notModelled = NOT_MODELLED.includes(fn);
  return (
    <div className="flex flex-col gap-1 sm:flex-row sm:gap-3">
      <span className="sm:w-36 sm:shrink-0 text-xs text-[var(--text-secondary)]">{FN_NAME[fn]}</span>
      <div className="min-w-0 flex-1 space-y-1">
        {extra}
        <ControlChips ids={ids} data={data} />
        {ids.length === 0 && !extra && (
          <span className="text-[10px] text-[var(--text-secondary)] italic">
            {notModelled ? 'barely modelled by these sources — not counted as a gap' : 'no candidate'}
          </span>
        )}
      </div>
    </div>
  );
}

function Side({ title, state, children }: { title: string; state: ReturnType<typeof techniqueState>['prevention']; children: React.ReactNode }) {
  return (
    <div className="rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-3 py-2 space-y-1.5">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-semibold uppercase tracking-wider text-[var(--text-primary)]">{title}</span>
        <StateBadge state={state} />
      </div>
      {children}
    </div>
  );
}

export function FairCamCard({ attackId }: { attackId: string }) {
  const { data, isLoading, error } = useFairCamCoverage(true);
  const sources = useDomainSources(data);

  if (isLoading) return <p className="text-xs italic text-[var(--text-secondary)]">Loading FAIR-CAM coverage…</p>;
  if (error || !data) return <p className="text-xs text-[var(--accent-orange)]">FAIR-CAM coverage could not be loaded.</p>;
  const row = data.techniques.find((t) => t.attackId === attackId);
  if (!row) return <p className="text-xs text-[var(--text-secondary)]">This technique is not in the coverage set (revoked or deprecated).</p>;

  const src = sources[row.domain];
  const st = techniqueState(row, src);
  const support = Object.keys(row.functions).filter(isSupport).sort();
  const supportDomains = [...new Set(support.map((fn) => FAIR_CAM_FUNCTIONS.find((f) => f.id === fn)?.domain).filter(Boolean))] as string[];
  const hasUnmapped = row.unmapped.length > 0;
  /** Why a side is not covered, named from what is actually missing for this domain. */
  const why = (side: 'prevention' | 'visibility' | 'recognition' | 'response') =>
    st[side] === 'not-covered' ? (
      <span className="text-[10px] text-[var(--text-secondary)]">Not covered: {missingSources(side, src, hasUnmapped).join(', ')} not loaded for this domain.</span>
    ) : null;
  const isParent = !attackId.includes('.');

  return (
    <div className="space-y-2">
      <p className="text-[11px] text-[var(--text-secondary)] leading-relaxed">
        Candidate controls from ATT&amp;CK and D3FEND, sorted by what they do to risk — availability, not
        efficacy. {isParent && 'Includes this technique’s sub-techniques. '}Whether they are deployed, how much
        they cover and how reliably they run is yours to measure.
      </p>
      <StateLegend />

      <Side title={GROUP_OF.avoidance} state={st.prevention}>
        {why('prevention')}
        {PREVENTION.map((fn) => <FnLine key={fn} fn={fn} row={row} data={data} />)}
      </Side>

      <Side title={GROUP_OF.visibility} state={detectionState(st)}>
        <FnLine
          fn="visibility"
          row={row}
          data={data}
          extra={
            <span className="flex flex-wrap items-center gap-2 text-[11px] text-[var(--text-primary)]">
              <StateBadge state={st.visibility} />
              {row.counts.dataComponents > 0 && <span>{row.counts.dataComponents} ATT&amp;CK data component{row.counts.dataComponents === 1 ? '' : 's'}</span>}
              {why('visibility')}
            </span>
          }
        />
        <div className="flex flex-col gap-1 sm:flex-row sm:gap-3">
          <span className="sm:w-36 sm:shrink-0 text-xs text-[var(--text-secondary)]">{FN_NAME.monitoring}</span>
          <span className="text-[11px] text-[var(--text-secondary)]">
            Yours to measure — FAIR-CAM&rsquo;s unit is &ldquo;{FN_UNIT.monitoring}&rdquo;.
          </span>
        </div>
        <FnLine
          fn="recognition"
          row={row}
          data={data}
          extra={
            <span className="flex flex-wrap items-center gap-2 text-[11px] text-[var(--text-primary)]">
              <StateBadge state={st.recognition} />
              {row.counts.detectionStrategies > 0 && <span>{row.counts.detectionStrategies} ATT&amp;CK detection strateg{row.counts.detectionStrategies === 1 ? 'y' : 'ies'}</span>}
              {row.counts.sigmaRules > 0 && <span>{row.counts.sigmaRules} Sigma rule{row.counts.sigmaRules === 1 ? '' : 's'}</span>}
              {why('recognition')}
            </span>
          }
        />
      </Side>

      <Side title={GROUP_OF.eventTermination} state={st.response}>
        {why('response')}
        {RESPONSE.map((fn) => <FnLine key={fn} fn={fn} row={row} data={data} />)}
      </Side>

      {support.length > 0 && (
        <div className="rounded-md border border-dashed border-[var(--border-color)] px-3 py-2 space-y-1.5">
          <div className="text-xs font-semibold uppercase tracking-wider text-[var(--text-secondary)]">{supportDomains.map((d) => DOMAIN_PLURAL[d]).join(' · ')}</div>
          {support.map((fn) => <FnLine key={fn} fn={fn} row={row} data={data} />)}
        </div>
      )}

      {(row.defaultRule.length > 0 || row.unmapped.length > 0) && (
        <p className="text-[10px] text-[var(--text-secondary)]">
          {row.defaultRule.length > 0 && <>New D3FEND id{row.defaultRule.length === 1 ? '' : 's'} {row.defaultRule.join(', ')} placed by tactic default rule, not reviewed. </>}
          {row.unmapped.length > 0 && <>{row.unmapped.length} control{row.unmapped.length === 1 ? '' : 's'} not classified yet ({row.unmapped.join(', ')}).</>}
        </p>
      )}

      <FairCamAttribution />
    </div>
  );
}
