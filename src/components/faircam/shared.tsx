'use client';

import Link from 'next/link';
import { useMemo } from 'react';
import { Badge } from '../shared/Badge';
import { FAIR_CAM_FUNCTIONS, FAIR_CAM_SOURCE, FAIR_CAM_ATTRIBUTION } from '../../lib/fair-cam.mjs';
import { domainSources, type DomainSources, type SideState } from '../../lib/fair-cam-state.mjs';
import type { FairCamCoverage } from '../../lib/types';

/** FAIR-CAM's own function names (quoted), keyed by our ids. */
export const FN_NAME: Record<string, string> = Object.fromEntries(FAIR_CAM_FUNCTIONS.map((f) => [f.id, f.name]));
export const FN_UNIT: Record<string, string> = Object.fromEntries(FAIR_CAM_FUNCTIONS.map((f) => [f.id, f.unit]));

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
