'use client';

import { useFairCamCoverage } from '../../hooks/useApi';
import { techniqueState, PREVENTION, RESPONSE, NOT_MODELLED } from '../../lib/fair-cam-state.mjs';
import { FN_NAME, FN_UNIT, StateBadge, useDomainSources, FairCamAttribution } from './shared';
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

const LEC_VMC_DSC_SUPPORT = (fn: string) => !PREVENTION.includes(fn) && !RESPONSE.includes(fn) && fn !== 'visibility' && fn !== 'recognition';
const MAX_CHIPS = 10;

function Chips({ ids, data }: { ids: string[]; data: FairCamCoverage }) {
  if (ids.length === 0) return null;
  const shown = ids.slice(0, MAX_CHIPS);
  return (
    <div className="flex flex-wrap gap-1">
      {shown.map((id) => {
        const c = data.controls[id];
        const kind = c?.kind ?? (id.startsWith('D3-') ? 'd3fend' : 'mitigation');
        return (
          <span
            key={id}
            title={kind === 'd3fend' ? 'D3FEND countermeasure — link to this technique inferred through the D3FEND ontology' : 'ATT&CK mitigation — curated by MITRE'}
            className="inline-flex items-center gap-1 rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-1.5 py-0.5 text-[10px]"
          >
            <span className={`font-mono ${kind === 'd3fend' ? 'text-[var(--accent-green)]' : 'text-[var(--accent-teal)]'}`}>{id}</span>
            <span className="text-[var(--text-primary)]">{c?.name ?? ''}</span>
          </span>
        );
      })}
      {ids.length > MAX_CHIPS && <span className="text-[10px] text-[var(--text-secondary)] self-center">+{ids.length - MAX_CHIPS} more</span>}
    </div>
  );
}

function FnLine({ fn, row, data, extra }: { fn: string; row: FairCamTechniqueRow; data: FairCamCoverage; extra?: React.ReactNode }) {
  const ids = row.functions[fn] ?? [];
  const notModelled = NOT_MODELLED.includes(fn);
  return (
    <div className="flex flex-col gap-1 sm:flex-row sm:gap-3">
      <span className="w-36 shrink-0 text-xs text-[var(--text-secondary)]">{FN_NAME[fn]}</span>
      <div className="min-w-0 flex-1 space-y-1">
        {extra}
        <Chips ids={ids} data={data} />
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

/**
 * One badge for the detection side: FAIR-CAM's AND (§3.2) means a real gap on
 * either visible half is a gap for the side; a half that is merely not covered
 * by our data does not make the side a gap.
 */
function detectionSide(st: ReturnType<typeof techniqueState>) {
  if (st.visibility === 'none-found' || st.recognition === 'none-found') return 'none-found' as const;
  if (st.visibility === 'found' || st.recognition === 'found') return 'found' as const;
  return 'not-covered' as const;
}

export function FairCamCard({ attackId }: { attackId: string }) {
  const { data, isLoading, error } = useFairCamCoverage(true);
  const sources = useDomainSources(data);

  if (isLoading) return <p className="text-xs italic text-[var(--text-secondary)]">Loading FAIR-CAM coverage…</p>;
  if (error || !data) return <p className="text-xs text-[var(--accent-orange)]">FAIR-CAM coverage could not be loaded.</p>;
  const row = data.techniques.find((t) => t.attackId === attackId);
  if (!row) return <p className="text-xs text-[var(--text-secondary)]">This technique is not in the coverage set (revoked or deprecated).</p>;

  const st = techniqueState(row, sources[row.domain]);
  const support = Object.keys(row.functions).filter(LEC_VMC_DSC_SUPPORT).sort();
  const isParent = !attackId.includes('.');

  return (
    <div className="space-y-2">
      <p className="text-[11px] text-[var(--text-secondary)] leading-relaxed">
        Candidate controls from ATT&amp;CK and D3FEND, sorted by what they do to risk — availability, not
        efficacy. {isParent && 'Includes this technique’s sub-techniques. '}Whether they are deployed, how much
        they cover and how reliably they run is yours to measure.
      </p>

      <Side title="Prevention" state={st.prevention}>
        {PREVENTION.map((fn) => <FnLine key={fn} fn={fn} row={row} data={data} />)}
      </Side>

      <Side title="Detection" state={detectionSide(st)}>
        <FnLine
          fn="visibility"
          row={row}
          data={data}
          extra={
            <span className="flex flex-wrap items-center gap-2 text-[11px] text-[var(--text-primary)]">
              <StateBadge state={st.visibility} />
              {row.counts.dataComponents > 0 && <span>{row.counts.dataComponents} ATT&amp;CK data component{row.counts.dataComponents === 1 ? '' : 's'}</span>}
            </span>
          }
        />
        <div className="flex flex-col gap-1 sm:flex-row sm:gap-3">
          <span className="w-36 shrink-0 text-xs text-[var(--text-secondary)]">{FN_NAME.monitoring}</span>
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
              {st.recognition === 'not-covered' && <span className="text-[var(--text-secondary)]">ATT&amp;CK detection strategies and Sigma rules are not loaded for this domain</span>}
            </span>
          }
        />
      </Side>

      <Side title="Response" state={st.response}>
        {RESPONSE.map((fn) => <FnLine key={fn} fn={fn} row={row} data={data} />)}
      </Side>

      {support.length > 0 && (
        <div className="rounded-md border border-dashed border-[var(--border-color)] px-3 py-2 space-y-1.5">
          <div className="text-xs font-semibold uppercase tracking-wider text-[var(--text-secondary)]">Supporting — variance management &amp; decision support</div>
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
