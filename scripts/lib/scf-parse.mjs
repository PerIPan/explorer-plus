// scripts/lib/scf-parse.mjs
//
// Pure parsing helpers for the SCF workbook. No DB calls — keeps sync-scf.mjs
// testable and lets us unit-test column classification later if needed.

import { Buffer } from 'node:buffer';

/** Collapse \r\n and runs of whitespace, lowercase. */
export function normHeader(s) {
  return String(s ?? '').replace(/\r?\n/g, ' ').replace(/\s+/g, ' ').trim().toLowerCase();
}

/** Split a cell value into individual ref IDs.
 *  SCF inconsistently uses \n, \r\n, ', ', or '; '.
 *  Comma is conditional: only split on ", " (comma + space) — a bare comma
 *  inside ref IDs like "164.308(a)(1)" or "Art. 9.3(a)" must NOT be split. */
export function splitRefs(cellValue) {
  if (cellValue == null) return [];
  const s = String(cellValue).trim();
  if (!s) return [];
  return s
    .split(/[\r\n;]+|,\s+/)
    .map((x) => x.trim())
    .filter((x) => x && x.toLowerCase() !== 'n/a');
}

/** Extract T-codes (T1059, T1059.001) from an ATT&CK cell value. */
export function extractAttackIds(cellValue) {
  if (cellValue == null) return [];
  const s = String(cellValue);
  // Single regex pass — matches Txxxx[.yyy] tokens.
  return [...new Set(s.match(/T\d{4}(?:\.\d{3})?/g) ?? [])];
}

/** Classify a main-sheet column header.
 *  Returns one of:
 *    { kind: 'metadata' }
 *    { kind: 'risk', code: 'R-AC-1' }
 *    { kind: 'threat', code: 'MT-1' }
 *    { kind: 'attack' }
 *    { kind: 'framework', framework_key, source_header }
 */
export function classifyColumn({ header, colIndex, headerToFdi, aliasLookup, attackColIndex }) {
  const trimmed = String(header ?? '').trim();
  if (!trimmed) return { kind: 'metadata' };

  if (colIndex === attackColIndex) return { kind: 'attack' };

  // Risk codes: header like "Risk R-AC-1"
  const riskMatch = trimmed.match(/^Risk\s+(R-[A-Z]+-\d+)\s*$/i);
  if (riskMatch) return { kind: 'risk', code: riskMatch[1].toUpperCase() };

  // Threat codes: "Threat MT-1", "Threat NT-7"
  const threatMatch = trimmed.match(/^Threat\s+([MN]T-\d+)\s*$/i);
  if (threatMatch) return { kind: 'threat', code: threatMatch[1].toUpperCase() };

  // Curated registry alias match — substring search on normalized form.
  const norm = normHeader(trimmed);
  for (const entry of aliasLookup) {
    if (norm.includes(entry.alias)) {
      return { kind: 'framework', framework_key: entry.framework_key, source_header: trimmed };
    }
  }

  // Auth Sources fallback — exact header (with \r\n preserved) lookups against the FDI map.
  const fdi = headerToFdi.get(trimmed);
  if (fdi) {
    return { kind: 'framework', framework_key: fdi, source_header: trimmed };
  }

  return { kind: 'metadata' };
}

/** Parse Authoritative Sources sheet into framework rows.
 *  Filters out 'Deleted' / blank rows. */
export function parseAuthSources(rows) {
  if (!rows || rows.length < 2) return [];
  const out = [];
  for (let i = 1; i < rows.length; i++) {
    const geography = String(rows[i][0] ?? '').trim();
    const colHeader = String(rows[i][1] ?? '').trim();
    const fdi = String(rows[i][2] ?? '').trim();
    const source = String(rows[i][3] ?? '').trim();
    const docName = String(rows[i][4] ?? '').trim();
    const docTitle = String(rows[i][5] ?? '').trim();
    const docUrl = String(rows[i][6] ?? '').trim();

    if (!fdi || !colHeader) continue;
    if (geography === 'Deleted' || geography === 'Not Complete') continue;

    out.push({
      fdi,
      column_header: colHeader,
      geography,
      source_org: source || 'Unknown',
      doc_name: docName,
      doc_title: docTitle,
      doc_url: docUrl || 'https://www.securecontrolsframework.com/',
    });
  }
  return out;
}

/** Map SCF geography → our region enum. */
export function mapRegion(geography) {
  switch ((geography || '').trim().toUpperCase()) {
    case 'US': return 'us';
    case 'EMEA': return 'eu';
    case 'APAC': return 'apac';
    case 'AMERICAS': return 'americas';
    case 'GENERAL': return 'global';
    case 'COMPLETE': return 'global';
    default: return 'global';
  }
}

/** Slug the FDI → framework_key when no curated registry entry exists.
 *  FDI is already a slug ('general-nist-csf-2-0'), but we strip leading
 *  geography prefix when present for cleaner URLs. */
export function fdiToKey(fdi) {
  return String(fdi).toLowerCase().replace(/^(general|usa-federal|emea|apac|americas)-/, '');
}
