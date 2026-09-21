// scripts/lib/scf-parse.mjs
//
// Pure parsing helpers for the SCF workbook. No DB calls — keeps sync-scf.mjs
// testable. Unit tests: `node --test scripts/lib/`.

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

// ----- Authoritative-source sheet ('Focal Documents' since SCF 2026.2) --------

export const SCF_FALLBACK_URL = 'https://www.securecontrolsframework.com/';

/**
 * Column matchers for the auth-source sheet, applied to normHeader() of the
 * header row so line breaks and case do not matter.
 *
 * Columns are located by NAME, never by position. SCF 2026.2 removed the
 * 'Focal Document Title (FDT)' column; a positional reader (rows[i][5],
 * rows[i][6]) then silently took the source URL as the title and the STRM
 * PDF link as the upstream URL for every non-curated framework.
 *
 *   2026.1: Geography | SCF Column Header | FDI | Source | FDN | FDT | FDS | STRM
 *   2026.2: Geography | SCF Column Header | FDI | Source | FDN |       FDS | STRM URL
 */
export const AUTH_COLUMN_MATCHERS = Object.freeze({
  geography:     { re: /^geography$/,                        required: true },
  column_header: { re: /^scf column header$/,                required: true },
  fdi:           { re: /focal document identifier|\(fdi\)/,  required: true },
  source:        { re: /^source$/,                           required: false },
  doc_name:      { re: /focal document name|\(fdn\)/,        required: false },
  doc_title:     { re: /focal document title|\(fdt\)/,       required: false }, // gone since 2026.2
  doc_url:       { re: /focal document source|\(fds\)/,      required: false },
});

/**
 * Resolve the header row to { field: columnIndex }.
 * Throws when a required column is missing or any matcher hits more than one
 * header — both mean the sheet changed shape and positional assumptions are
 * exactly what must not fill the gap.
 */
export function locateAuthColumns(headerRow) {
  const raw = Array.isArray(headerRow) ? headerRow : [];
  const headers = raw.map((h) => normHeader(h));
  const out = {};
  const problems = [];
  for (const [field, { re, required }] of Object.entries(AUTH_COLUMN_MATCHERS)) {
    const hits = [];
    headers.forEach((h, i) => { if (re.test(h)) hits.push(i); });
    if (hits.length === 1) out[field] = hits[0];
    else if (hits.length > 1) problems.push(`${field}: ${hits.length} headers match (${hits.map((i) => JSON.stringify(String(raw[i]))).join(', ')})`);
    else if (required) problems.push(`${field}: no header matches ${re}`);
  }
  if (problems.length > 0) {
    throw new Error(
      `auth-source sheet header mismatch — ${problems.join('; ')}. ` +
      `Headers present: ${raw.map((h) => JSON.stringify(String(h))).join(', ')}`,
    );
  }
  return out;
}

/** Parse the auth-source sheet (header row + data rows) into framework rows.
 *  Filters out 'Deleted' / 'Not Complete' / blank rows. */
export function parseAuthSources(rows) {
  if (!rows || rows.length === 0) return [];
  const col = locateAuthColumns(rows[0]);
  const cell = (row, field) => (col[field] == null ? '' : String(row[col[field]] ?? '').trim());

  const out = [];
  for (let i = 1; i < rows.length; i++) {
    const row = rows[i] ?? [];
    const geography = cell(row, 'geography');
    const colHeader = cell(row, 'column_header');
    const fdi = cell(row, 'fdi');

    if (!fdi || !colHeader) continue;
    if (geography === 'Deleted' || geography === 'Not Complete') continue;

    const docUrl = cell(row, 'doc_url');
    out.push({
      fdi,
      column_header: colHeader,
      geography,
      source_org: cell(row, 'source') || 'Unknown',
      doc_name: cell(row, 'doc_name'),
      doc_title: cell(row, 'doc_title'),
      // Only ever store something a browser can open; anything else falls back
      // to the SCF site rather than becoming a dead "Source" link.
      doc_url: /^https?:\/\//i.test(docUrl) ? docUrl : SCF_FALLBACK_URL,
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
