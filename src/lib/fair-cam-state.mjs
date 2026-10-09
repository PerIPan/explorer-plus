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
 * @typedef {{ functions: Record<string, string[]>, counts: { dataComponents: number, detectionStrategies: number, sigmaRules: number }, unmapped: string[], domain: string }} Row
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
  /** @type {Array<{ attackId?: string, missing: string[] }>} */
  const gaps = [];
  for (const r of rows) {
    const st = techniqueState(r, sources[r.domain]);
    for (const k of sides) summary[k][st[k]] += 1;
    const missing = sides.filter((k) => st[k] === 'none-found');
    if (missing.length) gaps.push({ attackId: /** @type {any} */ (r).attackId, missing });
  }
  return { techniques: rows.length, summary, gaps };
}
