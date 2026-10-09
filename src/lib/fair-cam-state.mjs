// src/lib/fair-cam-state.mjs — pure, small, browser-safe. Tested by
// scripts/lib/fair-cam-state.test.mjs.
//
// Turns one coverage row (GET /api/v1/frameworks/fair-cam/coverage) into what
// the FAIR-CAM card and coverage panels show, WITHOUT overclaiming:
//
//   * A side (prevention, visibility, recognition, response) with candidates
//     is "found". With none, it is "none-found" only if every source that could
//     supply that side is LOADED for the technique's domain — otherwise it is
//     "not-covered": the gap is in this site's data, not in anyone's defences.
//     Which sources are loaded is read from the response itself (a domain with
//     zero detection strategies across all its techniques has none loaded), so
//     it stays right as data loads change. Measured 2026-10-09: ATT&CK detection
//     strategies and Sigma exist for Enterprise only, D3FEND for Enterprise and
//     ICS, data components for all but ATLAS.
//   * Monitoring (time between reviews), and Deterrence and Loss Reduction
//     (three mitigations in all of ATT&CK serve them), are "not modelled" by
//     these sources and never counted as gaps.
//   * Availability only: never efficacy, coverage or reliability.

export const PREVENTION = Object.freeze(['avoidance', 'deterrence', 'resistance']);
export const RESPONSE = Object.freeze(['eventTermination', 'resilience', 'lossReduction']);
export const NOT_MODELLED = Object.freeze(['deterrence', 'monitoring', 'lossReduction']);

/**
 * @typedef {{ attackId?: string, functions: Record<string, string[]>, counts: { dataComponents: number, detectionStrategies: number, sigmaRules: number }, unmapped: string[], domain: string }} Row
 * @typedef {{ mitigations: boolean, d3fend: boolean, dataComponents: boolean, detectionStrategies: boolean, sigmaRules: boolean }} DomainSources
 * @typedef {'found' | 'none-found' | 'not-covered'} SideState
 */

/**
 * Which sources have any data per domain, derived from the rows themselves.
 * @param {readonly Row[]} rows
 * @param {(id: string) => 'mitigation' | 'd3fend'} kindOf
 * @returns {Record<string, DomainSources>}
 */
export function domainSources(rows, kindOf) {
  /** @type {Record<string, DomainSources>} */
  const out = {};
  for (const r of rows) {
    const d = (out[r.domain] ??= { mitigations: false, d3fend: false, dataComponents: false, detectionStrategies: false, sigmaRules: false });
    const ids = Object.values(r.functions).flat();
    if (ids.some((id) => kindOf(id) === 'mitigation')) d.mitigations = true;
    if (ids.some((id) => kindOf(id) === 'd3fend')) d.d3fend = true;
    if (r.counts.dataComponents > 0) d.dataComponents = true;
    if (r.counts.detectionStrategies > 0) d.detectionStrategies = true;
    if (r.counts.sigmaRules > 0) d.sigmaRules = true;
  }
  return out;
}

const has = (row, fns) => fns.some((fn) => (row.functions[fn]?.length ?? 0) > 0);

/**
 * @param {Row} row
 * @param {DomainSources | undefined} src
 * @returns {{ prevention: SideState, visibility: SideState, recognition: SideState, response: SideState }}
 */
export function techniqueState(row, src) {
  const s = src ?? { mitigations: false, d3fend: false, dataComponents: false, detectionStrategies: false, sigmaRules: false };
  // Unclassified mitigations on this technique mean a source we could not read.
  const allMitigationsClassified = row.unmapped.length === 0;
  const side = (found, allLoaded) => (found ? 'found' : allLoaded ? 'none-found' : 'not-covered');
  return {
    prevention: side(has(row, PREVENTION), s.mitigations && s.d3fend && allMitigationsClassified),
    visibility: side(row.counts.dataComponents > 0 || has(row, ['visibility']), s.dataComponents && s.d3fend),
    recognition: side(
      row.counts.detectionStrategies > 0 || row.counts.sigmaRules > 0 || has(row, ['recognition']),
      s.detectionStrategies && s.sigmaRules && s.d3fend,
    ),
    response: side(has(row, RESPONSE), s.d3fend && s.mitigations && allMitigationsClassified),
  };
}

/**
 * Scenario summary over a set of techniques: per side, how many are found,
 * none-found (a real candidate gap) and not-covered (our data gap). Counted per
 * technique — never by summing controls, since a parent and its sub-techniques
 * share controls under the roll-up rule.
 *
 * @param {readonly Row[]} rows
 * @param {Record<string, DomainSources>} sources
 */
export function scenarioSummary(rows, sources) {
  const sides = /** @type {const} */ (['prevention', 'visibility', 'recognition', 'response']);
  const summary = Object.fromEntries(sides.map((k) => [k, { found: 0, 'none-found': 0, 'not-covered': 0 }]));
  /** @type {Array<{ attackId: string, missing: string[] }>} */
  const gaps = [];
  for (const r of rows) {
    const st = techniqueState(r, sources[r.domain]);
    for (const k of sides) summary[k][st[k]] += 1;
    const missing = sides.filter((k) => st[k] === 'none-found');
    if (missing.length) gaps.push({ attackId: r.attackId ?? '', missing });
  }
  return { techniques: rows.length, summary, gaps };
}

/**
 * One state for the detection side as a whole. FAIR-CAM's Loss Event Detection
 * is an AND (§3.2): it is "found" only when BOTH visible halves (Visibility,
 * Recognition) have candidates — Monitoring is never knowable here. A real gap
 * on either half is a gap for the side; otherwise, if a half is merely not
 * covered by our data, so is the side. One half found and the other unknown is
 * therefore "not-covered", never "found".
 *
 * @param {{ visibility: SideState, recognition: SideState }} st
 * @returns {SideState}
 */
export function detectionState(st) {
  if (st.visibility === 'found' && st.recognition === 'found') return 'found';
  if (st.visibility === 'none-found' || st.recognition === 'none-found') return 'none-found';
  return 'not-covered';
}

/**
 * Which loaded-source names a side is missing for a domain — so the UI can say
 * WHY a side is not covered instead of a fixed sentence.
 *
 * @param {'prevention' | 'visibility' | 'recognition' | 'response'} side
 * @param {DomainSources | undefined} src
 * @param {boolean} hasUnmapped
 * @returns {string[]}
 */
export function missingSources(side, src, hasUnmapped) {
  const s = src ?? { mitigations: false, d3fend: false, dataComponents: false, detectionStrategies: false, sigmaRules: false };
  const out = [];
  const need = {
    prevention: ['mitigations', 'd3fend'],
    visibility: ['dataComponents', 'd3fend'],
    recognition: ['detectionStrategies', 'sigmaRules', 'd3fend'],
    response: ['mitigations', 'd3fend'],
  }[side];
  const LABEL = { mitigations: 'ATT&CK mitigations', d3fend: 'D3FEND', dataComponents: 'ATT&CK data components', detectionStrategies: 'ATT&CK detection strategies', sigmaRules: 'Sigma rules' };
  for (const k of need) if (!s[k]) out.push(LABEL[k]);
  if (hasUnmapped && (side === 'prevention' || side === 'response')) out.push('classification of this domain’s mitigations');
  return out;
}
