// src/lib/canonical-redirects.mjs
//
// Permanent redirects that middleware.ts issues BEFORE a page renders.
//
// Why middleware and not redirect() in the page: app/providers.tsx wraps the
// app in a root <Suspense>, so the shell (HTTP 200) is flushed before an
// async page can call redirect() or notFound(). In-page redirects therefore
// arrive as a 200 with a meta refresh. Here, with no DB, they are real 308s.

/**
 * Compliance framework keys SCF retired in favour of a newer edition of the
 * SAME document (verified by name against scf_frameworks, 2026-10-09). The old
 * keys still exist with no references, so their pages rendered empty. Keys
 * with no clear successor are not here; /compliance/[key] answers not-found.
 */
export const RENAMED_FRAMEWORK_KEYS = Object.freeze({
  // SCF 2026.3 re-keys
  'aus-ism-2026-march': 'aus-ism-2026-june',
  'deu-c5-2020': 'deu-c5-2026',
  'sparta': 'sparta-4-0',
  'law-ftc-act': 'law-ftc-act-1938',
  'sro-finra': 'sro-finra-2007',
  // Earlier editions of the same document
  'aus-ism-2024-june': 'aus-ism-2026-june',
  'esp-ccn-stic-825-2023': 'esp-ccn-stic-825-2026',
  'isr-cmo-1-0': 'isr-cmo-2-0',
  'isr-ppl-5741-1981': 'isr-ppl-5741-2025',
  'jpn-ppi-2020': 'jpn-appi-2020',
  'nist-800-172': 'nist-800-172-r3',
  'scf-dpmp-2025': 'scf-dpmp-2026',
  'gbr-dpa-1998': 'gbr-dpa-2018',
  'irl-dpa-2003': 'irl-dpa-2018',
  'ita-pdpc-2003': 'ita-pdpc-2018',
  // The 2022 CRA proposal columns; the regulation is the curated eu-cra.
  'eu-cyber-resilience-act-2022': 'eu-cra',
  'eu-cyber-resilience-act-annexes-2022': 'eu-cra',
});

/**
 * Where a page path should permanently redirect, or null.
 *   /frameworks/d3fend/d3-am  -> /frameworks/d3fend/D3-AM  (one URL per countermeasure)
 *   /compliance/<retired key> -> /compliance/<successor>
 *
 * @param {string} pathname
 * @returns {string | null}
 */
export function canonicalRedirect(pathname) {
  const d3 = /^\/frameworks\/d3fend\/(d3-[a-z0-9-]{1,40})\/?$/i.exec(pathname);
  if (d3 && d3[1] !== d3[1].toUpperCase()) return `/frameworks/d3fend/${d3[1].toUpperCase()}`;
  const fw = /^\/compliance\/([^/]+)\/?$/.exec(pathname);
  if (fw && Object.hasOwn(RENAMED_FRAMEWORK_KEYS, fw[1])) return `/compliance/${RENAMED_FRAMEWORK_KEYS[fw[1]]}`;
  return null;
}
