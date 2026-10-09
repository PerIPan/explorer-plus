// src/lib/framework-section.mjs
//
// How /api/v1/compliance/frameworks/[key] groups an SCF ref_id into a
// section. Plain .mjs so scripts/lib/framework-section.test.mjs can pin every
// rule with real reference shapes from the SCF workbook.

/**
 * Extract a stable "section" / "article" prefix from an SCF ref_id.
 *
 * Two frameworks number their refs in a way the generic rules below get wrong,
 * so they are handled first rather than by widening a shared regex (widening
 * the CFR rule to two digits would have re-cut PCI DSS "12.10.1" from section
 * 12 into section 12.10).
  *
 * @param {string} refId
 * @param {string} [frameworkKey]
 * @returns {string}
 */
export function extractSection(refId, frameworkKey) {
  if (!refId) return '(unspecified)';

  // HIPAA: "\u00a7 164.306(a)(1)". The section mark is a separate token, so the
  // generic rules missed it and the final split() collapsed all 576 refs into
  // one section literally named "\u00a7".
  if (frameworkKey === 'hipaa-security-rule') {
    const cfr = refId.match(/^\s*\u00a7?\s*(\d{2,3}\.\d+)/);
    if (cfr) return `\u00a7 ${cfr[1]}`;
  }

  // SP 800-171: "03.01.01.a" belongs to family "03.01", not "03".
  if (frameworkKey === 'nist-800-171-r3') {
    const fam = refId.match(/^(\d{2}\.\d{2})\./);
    if (fam) return fam[1];
  }

  // EU CRA: SCF writes Annex I points as "Annex I, Part I(2)(e)". Before
  // splitRefs kept that path whole, ingests stored a bare "Annex I" plus an
  // orphan "Part I(2)(e)", which the generic fallback filed in a section named
  // "Part". Those rows stay until the next sync, so bare Part refs still go
  // under Annex I, and annex refs keep their numeral ("Annex II", not "Annex").
  if (frameworkKey === 'eu-cra') {
    if (/^Part\s+I{1,2}\b/i.test(refId)) return 'Annex I';
    const annex = refId.match(/^Annex\s+([IVX]+)\b/i);
    if (annex) return `Annex ${annex[1].toUpperCase()}`;
  }

  // A hierarchical path the ingest keeps whole ("Title 2, Chapter II, Art.
  // 29(5)", "Appendix A, 1.1", "Annex I, Part II" — see splitRefs) groups
  // under its first container.
  const chain = refId.match(/^((?:title|chapter|annex|appendix|part|schedule)\s+[\w.]+),\s/i);
  if (chain) return chain[1];

  // A bare container ref groups under the container and its first number or
  // letter: "Schedule 1 - 1(1)(a)" -> "Schedule 1" (Hong Kong PDO),
  // "Annex 1.1.7" -> "Annex 1" (India RBI PA), "Appendix C" -> "Appendix C"
  // (Israel CDMO), "Title II - Chapter IV" -> "Title II" (DORA RTS). The
  // generic fallback below kept only the keyword, so each of those frameworks
  // collapsed into one section named "Schedule" / "Annex" / "Appendix".
  const bare = refId.match(/^((?:title|chapter|annex|appendix|part|schedule)\s+(?:\d+|[A-Za-z]+))\b/i);
  if (bare) return bare[1];

  // "Article N[.something]" -> "Article N"
  const art = refId.match(/^(Article\s+\d+)/i);
  if (art) return art[1];
  // CFR-style "164.NNN(a)..." -> "164.NNN"
  const cfr = refId.match(/^(\d{3}\.\d+)/);
  if (cfr) return cfr[1];
  // Family-prefix "XX-NN.YY" -> "XX"
  const family = refId.match(/^([A-Z]{2,4})-/);
  if (family) return family[1];
  // Numeric "1.2.3" -> "1"
  const num = refId.match(/^(\d+)\./);
  if (num) return num[1];
  // Roman chapter + first sub-part, like "Article 13": "III.9.a" -> "III.9"
  // (India RBI PA), "IV.1.49" -> "IV.1" (Serbia), "II.A.3.a" -> "II.A"
  // (FFIEC). The fallback below only split at a space or "(", so a
  // dotted ref without parentheses became a section of one — Brazil LGPD
  // had 139 of them. I/V/X only: "C.11" (Greece) and "L.1" (SIG) are
  // letter sections, not roman chapters.
  const roman = refId.match(/^([IVX]+)\.([A-Za-z0-9]+)(?=[.(-]|$)/);
  if (roman) return `${roman[1]}.${roman[2]}`;
  return refId.split(/[\s(]/)[0];
}
