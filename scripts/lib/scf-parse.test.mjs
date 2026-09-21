// scripts/lib/scf-parse.test.mjs — run with `npm test` (node --test scripts/lib/)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { locateAuthColumns, parseAuthSources, SCF_FALLBACK_URL } from './scf-parse.mjs';
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
