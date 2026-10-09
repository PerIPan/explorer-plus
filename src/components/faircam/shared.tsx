'use client';

import Link from 'next/link';
import { useMemo, useState } from 'react';
import { Badge } from '../shared/Badge';
import { FAIR_CAM_FUNCTIONS, FAIR_CAM_DOMAINS, FAIR_CAM_SOURCE, FAIR_CAM_ATTRIBUTION } from '../../lib/fair-cam.mjs';
import { domainSources, type DomainSources, type SideState } from '../../lib/fair-cam-state.mjs';
import type { FairCamCoverage } from '../../lib/types';

/** FAIR-CAM's own function names (quoted), keyed by our ids. */
export const FN_NAME: Record<string, string> = Object.fromEntries(FAIR_CAM_FUNCTIONS.map((f) => [f.id, f.name]));
export const FN_UNIT: Record<string, string> = Object.fromEntries(FAIR_CAM_FUNCTIONS.map((f) => [f.id, f.unit]));
/** The Standard's group headings (quoted), keyed by a function in the group. */
export const GROUP_OF: Record<string, string> = Object.fromEntries(FAIR_CAM_FUNCTIONS.map((f) => [f.id, f.group]));
/** The Standard's domain names (quoted), keyed by domain id. */
export const DOMAIN_PLURAL: Record<string, string> = Object.fromEntries(FAIR_CAM_DOMAINS.map((d) => [d.id, d.plural]));

const STATE: Record<SideState, { label: string; variant: 'teal' | 'orange' | 'neutral'; title: string }> = {
  found: { label: 'candidates found', variant: 'teal', title: 'At least one candidate control exists in the loaded sources.' },
  'none-found': { label: 'none found', variant: 'orange', title: 'Every source that could supply this is loaded for this domain, and none lists a candidate.' },
  'not-covered': { label: 'not covered by loaded sources', variant: 'neutral', title: 'A source that could supply this is not loaded for this ATT&CK domain (or its mitigations are not classified yet) — a gap in this site’s data, not a finding.' },
};

export function StateBadge({ state }: { state: SideState }) {
  const s = STATE[state];
  return (
    <span title={s.title}>
      <Badge label={s.label} variant={s.variant} />
    </span>
  );
}

/** The three states, spelled out once per surface — a tooltip alone is invisible on touch and to most readers. */
export function StateLegend() {
  return (
    <p className="text-[10px] text-[var(--text-secondary)] leading-relaxed">
      <span className="font-semibold">candidates found</span>: a public knowledge base lists at least one control.{' '}
      <span className="font-semibold">none found</span>: every source that could list one is loaded, and none does.{' '}
      <span className="font-semibold">not covered by loaded sources</span>: a gap in this site&rsquo;s data, not a finding.
    </p>
  );
}

const MAX_CHIPS = 10;

/**
 * Candidate-control chips, linked: ATT&CK mitigations to their page,
 * D3FEND countermeasures to the D3FEND browser. Long lists collapse to ten
 * with a "show all" toggle.
 */
export function ControlChips({ ids, data }: { ids: string[]; data: FairCamCoverage }) {
  const [all, setAll] = useState(false);
  if (ids.length === 0) return null;
  const shown = all ? ids : ids.slice(0, MAX_CHIPS);
  return (
    <div className="flex flex-wrap gap-1">
      {shown.map((id) => {
        const c = data.controls[id];
        const kind = c?.kind ?? (id.startsWith('D3-') ? 'd3fend' : 'mitigation');
        return (
          <Link
            key={id}
            href={kind === 'd3fend' ? `/frameworks/d3fend/${id}` : `/mitigations/${id}`}
            title={kind === 'd3fend' ? 'D3FEND countermeasure — link to this technique inferred through the D3FEND ontology' : 'ATT&CK mitigation — curated by MITRE'}
            className="inline-flex items-center gap-1 rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-1.5 py-0.5 text-[10px] hover:border-[var(--teal-dim)] transition-colors"
          >
            <span className={`font-mono ${kind === 'd3fend' ? 'text-[var(--accent-green)]' : 'text-[var(--accent-teal)]'}`}>{id}</span>
            <span className="text-[var(--text-primary)]">{c?.name ?? ''}</span>
          </Link>
        );
      })}
      {ids.length > MAX_CHIPS && (
        <button
          type="button"
          onClick={() => setAll((v) => !v)}
          aria-expanded={all}
          className="self-center text-[10px] text-[var(--accent-teal)] hover:underline"
        >
          {all ? 'show fewer' : `show all ${ids.length}`}
        </button>
      )}
    </div>
  );
}

/** Per-domain loaded sources, derived from the coverage response itself. */
export function useDomainSources(data: FairCamCoverage | undefined): Record<string, DomainSources> {
  return useMemo(
    () => (data ? domainSources(data.techniques, (id: string) => data.controls[id]?.kind ?? (id.startsWith('D3-') ? 'd3fend' : 'mitigation')) : {}),
    [data],
  );
}

/** The credit line every FAIR-CAM surface carries (Standard §1.2), plus our-curation note. */
export function FairCamAttribution({ compact = false }: { compact?: boolean }) {
  return (
    <p className="text-[10px] text-[var(--text-secondary)] leading-relaxed">
      {FAIR_CAM_ATTRIBUTION}{' '}
      <a href={FAIR_CAM_SOURCE.licenceUrl} target="_blank" rel="noopener noreferrer" className="hover:underline">Licence</a>
      {' · '}
      <a href={FAIR_CAM_SOURCE.referenceUrl} target="_blank" rel="noopener noreferrer" className="hover:underline">fairinstitute.org/FAIR-CAM</a>
      {'. '}
      {!compact && 'Which control serves which function is this site’s classification, not the FAIR Institute’s; availability of candidate controls only, never efficacy. '}
      <Link href="/frameworks/fair-cam" className="text-[var(--accent-teal)] hover:underline">How this works →</Link>
    </p>
  );
}
