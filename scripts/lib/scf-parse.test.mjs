// scripts/lib/scf-parse.test.mjs — run with `npm test` (node --test scripts/lib/)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { locateAuthColumns, parseAuthSources, SCF_FALLBACK_URL, resolveCuratedKey, buildCuratedFdiMap, splitRefs, findAuthSheetName } from './scf-parse.mjs';
import { stripShadowSuffix, shrinkViolations, parseArgs } from '../sync-scf.mjs';

// Header rows exactly as the two workbook generations ship them.
const HEADER_2026_1 = ['Geography', 'SCF Column Header', 'Focal Document Identifier (FDI)', 'Source',
  'Focal Document Name (FDN)', 'Focal Document Title (FDT)', 'Focal Document Source (FDS)', 'Set Theory Relationship Mapping (STRM)'];
const HEADER_2026_2 = ['Geography', 'SCF Column Header', 'Focal Document Identifier (FDI)', 'Source',
  'Focal Document Name (FDN)', 'Focal Document Source (FDS)', 'Set Theory Relationship Mapping (STRM) URL'];

const ROW_2026_1 = ['General', 'AICPA\r\nPrivacy Management Framework (PMF)', 'general-aicpa-pmf-2020', 'AICPA',
  'AICPA PMF (2020)', 'American Institute of CPAs PMF (2020)', 'https://www.aicpa-cima.com/pmf', 'https://content.securecontrolsframework.com/strm/x.pdf'];
const ROW_2026_2 = ['General', 'AICPA\r\nPrivacy Management Framework (PMF)', 'general-aicpa-pmf-2020', 'AICPA',
  'American Institute of CPAs PMF (2020)', 'https://www.aicpa-cima.com/pmf', 'https://content.securecontrolsframework.com/strm/x.pdf'];

test('locateAuthColumns: 2026.1 shape (8 columns, with FDT)', () => {
  assert.deepEqual(locateAuthColumns(HEADER_2026_1), {
    geography: 0, column_header: 1, fdi: 2, source: 3, doc_name: 4, doc_title: 5, doc_url: 6,
  });
});

test('locateAuthColumns: 2026.2 shape (7 columns, FDT removed) shifts doc_url, drops doc_title', () => {
  assert.deepEqual(locateAuthColumns(HEADER_2026_2), {
    geography: 0, column_header: 1, fdi: 2, source: 3, doc_name: 4, doc_url: 5,
  });
});

test('locateAuthColumns: header case/line breaks do not matter', () => {
  const messy = HEADER_2026_2.map((h) => h.toUpperCase().replace(' ', '\r\n'));
  assert.equal(locateAuthColumns(messy).doc_url, 5);
});

test('locateAuthColumns: missing required column throws and names it', () => {
  const noFdi = HEADER_2026_2.filter((h) => !h.includes('FDI'));
  assert.throws(() => locateAuthColumns(noFdi), /fdi: no header matches/);
});

test('locateAuthColumns: ambiguous column throws rather than picking the first', () => {
  assert.throws(() => locateAuthColumns([...HEADER_2026_2, 'Source']), /source: 2 headers match/);
});

test('locateAuthColumns: "Source" does not match "Focal Document Source (FDS)"', () => {
  const cols = locateAuthColumns(HEADER_2026_2);
  assert.equal(cols.source, 3);
  assert.equal(cols.doc_url, 5);
});

test('parseAuthSources: 2026.1 row maps title and URL from their own columns', () => {
  const [fw] = parseAuthSources([HEADER_2026_1, ROW_2026_1]);
  assert.equal(fw.fdi, 'general-aicpa-pmf-2020');
  assert.equal(fw.doc_name, 'AICPA PMF (2020)');
  assert.equal(fw.doc_title, 'American Institute of CPAs PMF (2020)');
  assert.equal(fw.doc_url, 'https://www.aicpa-cima.com/pmf');
});

test('parseAuthSources: 2026.2 row — URL is the source document, never the STRM PDF; title empty', () => {
  const [fw] = parseAuthSources([HEADER_2026_2, ROW_2026_2]);
  assert.equal(fw.doc_url, 'https://www.aicpa-cima.com/pmf');
  assert.equal(fw.doc_title, '');
  assert.equal(fw.doc_name, 'American Institute of CPAs PMF (2020)');
});

test('parseAuthSources: non-URL source falls back to the SCF site', () => {
  const row = [...ROW_2026_2]; row[5] = 'N/A';
  const [fw] = parseAuthSources([HEADER_2026_2, row]);
  assert.equal(fw.doc_url, SCF_FALLBACK_URL);
});

test('parseAuthSources: skips Deleted / Not Complete / blank-FDI rows', () => {
  const del = [...ROW_2026_2]; del[0] = 'Deleted';
  const inc = [...ROW_2026_2]; inc[0] = 'Not Complete';
  const noFdi = [...ROW_2026_2]; noFdi[2] = '';
  assert.equal(parseAuthSources([HEADER_2026_2, del, inc, noFdi, ROW_2026_2]).length, 1);
});

test('parseAuthSources: header-only sheet with a bad header still throws', () => {
  assert.throws(() => parseAuthSources([['Geography', 'Something else']]), /header mismatch/);
  assert.deepEqual(parseAuthSources([]), []);
});

test('stripShadowSuffix: promotes explicit and PG18 auto-generated names', () => {
  assert.equal(stripShadowSuffix('scf_framework_refs_pkey_new'), 'scf_framework_refs_pkey');
  assert.equal(stripShadowSuffix('idx_scf_attack_mappings_unresolved_new'), 'idx_scf_attack_mappings_unresolved');
  assert.equal(stripShadowSuffix('scf_framework_refs_new_scf_id_not_null'), 'scf_framework_refs_scf_id_not_null');
  assert.throws(() => stripShadowSuffix('scf_framework_refs_pkey1'), /does not carry/);
  assert.throws(() => stripShadowSuffix('idx_renewal'), /does not carry/);
});

test('shrinkViolations: flags >30% drops, ignores empty-before and growth', () => {
  assert.deepEqual(shrinkViolations([['refs', 55398, 11465]]), ['refs: 55398 → 11465 (79% fewer)']);
  assert.deepEqual(shrinkViolations([['refs', 55398, 58631]]), []);
  assert.deepEqual(shrinkViolations([['refs', 100, 70]]), []);
  assert.deepEqual(shrinkViolations([['refs', 100, 69]]), ['refs: 100 → 69 (31% fewer)']);
  assert.deepEqual(shrinkViolations([['refs', 0, 0]]), []);
});

test('parseArgs: accepts documented flags, rejects typos', () => {
  assert.deepEqual(parseArgs(['--dry-run', '--allow-shrink', '--version=2026.1.1']),
    { version: '2026.1.1', dryRun: true, force: false, allowShrink: true, xlsx: null });
  assert.throws(() => parseArgs(['--allow-shrnk']), /unknown argument/);
});

// Curated matching. aliasLookup is longest-first, as buildAliasLookup() sorts it.
const ALIASES = [
  { alias: 'nist ai rmf 1.0', framework_key: 'nist-ai-rmf' },
  { alias: 'nist ai rmf', framework_key: 'nist-ai-rmf' },
  { alias: 'ai rmf', framework_key: 'nist-ai-rmf' },
];
const KEYS = new Set(['nist-ai-rmf', 'nist-600-1-gen-ai-profile']);

test('resolveCuratedKey: alias match wins, as it always has', () => {
  const r = resolveCuratedKey({ columnHeader: 'NIST\r\nAI RMF\r\n1.0', fdi: 'general-nist-ai-rmf-1-0', aliasLookup: ALIASES, registryKeys: KEYS });
  assert.deepEqual(r, { key: 'nist-ai-rmf', via: 'alias', conflict: null });
});

test('resolveCuratedKey: a promoted Tier-3 entry is matched by its FDI-derived key', () => {
  const r = resolveCuratedKey({ columnHeader: 'NIST\r\nAI 600-1', fdi: 'USA-Federal-NIST-600-1-Gen-AI-Profile', aliasLookup: ALIASES, registryKeys: KEYS });
  assert.deepEqual(r, { key: 'nist-600-1-gen-ai-profile', via: 'fdi', conflict: null });
});

test('resolveCuratedKey: neither path → uncurated (Tier 3)', () => {
  const r = resolveCuratedKey({ columnHeader: 'ISO 27018', fdi: 'general-iso-27018-2025', aliasLookup: ALIASES, registryKeys: KEYS });
  assert.deepEqual(r, { key: null, via: null, conflict: null });
});

test('resolveCuratedKey: alias and FDI key disagree → alias kept, conflict reported', () => {
  const r = resolveCuratedKey({ columnHeader: 'NIST AI RMF GenAI', fdi: 'general-nist-600-1-gen-ai-profile', aliasLookup: ALIASES, registryKeys: KEYS });
  assert.equal(r.key, 'nist-ai-rmf');
  assert.deepEqual(r.conflict, { aliasKey: 'nist-ai-rmf', fdiKey: 'nist-600-1-gen-ai-profile' });
});

test('buildCuratedFdiMap: maps curated rows only and collects conflicts', () => {
  const rows = [
    { fdi: 'general-nist-ai-rmf-1-0', column_header: 'NIST AI RMF 1.0' },
    { fdi: 'general-nist-600-1-gen-ai-profile', column_header: 'NIST AI 600-1' },
    { fdi: 'general-iso-27018-2025', column_header: 'ISO 27018' },
  ];
  const { map, conflicts } = buildCuratedFdiMap(rows, ALIASES, KEYS);
  assert.deepEqual([...map.entries()], [
    ['general-nist-ai-rmf-1-0', 'nist-ai-rmf'],
    ['general-nist-600-1-gen-ai-profile', 'nist-600-1-gen-ai-profile'],
  ]);
  assert.deepEqual(conflicts, []);
});

test('splitRefs: newline, semicolon and ", " lists still split; bare commas do not', () => {
  assert.deepEqual(splitRefs('164.308(a)(1)\r\n164.312(b); Art. 9.3(a), Art. 10'), ['164.308(a)(1)', '164.312(b)', 'Art. 9.3(a)', 'Art. 10']);
  assert.deepEqual(splitRefs('N/A'), []);
  assert.deepEqual(splitRefs(''), []);
});

test('splitRefs: a container is glued to the point it qualifies (2026.3 CRA, Belgium, Israel)', () => {
  assert.deepEqual(splitRefs('Article 24(1)\nAnnex I, Part I(2)(e)\nAnnex I, Part I(2)(f)'), ['Article 24(1)', 'Annex I, Part I(2)(e)', 'Annex I, Part I(2)(f)']);
  assert.deepEqual(splitRefs('Title 2, Chapter II, Art. 29(5)'), ['Title 2, Chapter II, Art. 29(5)']);
  assert.deepEqual(splitRefs('Appendix A, 1.1\nAppendix A, 1.2'), ['Appendix A, 1.1', 'Appendix A, 1.2']);
});

test('splitRefs: siblings of the same kind stay a list; no glue across lines', () => {
  assert.deepEqual(splitRefs('Annex I, Annex II'), ['Annex I', 'Annex II']);
  assert.deepEqual(splitRefs('Part I(1), Part II(3)'), ['Part I(1)', 'Part II(3)']);
  assert.deepEqual(splitRefs('Annex I\nPart II'), ['Annex I', 'Part II']);
});

test('findAuthSheetName: every name SCF has shipped, plus a future suffix', () => {
  assert.equal(findAuthSheetName(['SCF 2026.1', 'Authoritative Sources']), 'Authoritative Sources');
  assert.equal(findAuthSheetName(['SCF 2026.2', 'Focal Documents']), 'Focal Documents');
  assert.equal(findAuthSheetName(['READ THIS', 'Focal Documents (FD)', 'SCF 2026.3']), 'Focal Documents (FD)');
  assert.equal(findAuthSheetName(['SCF 2027.1', 'Focal Documents v2']), 'Focal Documents v2');
  assert.equal(findAuthSheetName(['SCF 2026.3', 'Risk Catalog']), null);
});

