/**
 * The CLI's terminal renderer.
 *
 * Only the TERMINAL path goes through this module, which is why the sanitising
 * tests matter: the API serves third-party text (IOC values, advisory prose,
 * Atomic Red Team command strings) and writing raw control bytes to a TTY is an
 * injection surface. Piped output bypasses all of this by design.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  sanitize,
  defang,
  renderDetail,
  renderList,
  isIocRow,
  escapeForTerminal,
} from '../../cli/lib/format.mjs';

test('sanitize removes everything a terminal would obey', () => {
  // ESC is the one that matters: without it no CSI/OSC sequence can start.
  assert.equal(sanitize('a\u001b[2Jb'), 'a[2Jb');
  assert.equal(sanitize('t\u001b]0;title\u0007x'), 't]0;titlex');
  assert.equal(sanitize('bell\u0007'), 'bell');
  assert.equal(sanitize('del\u007f'), 'del');
  assert.equal(sanitize('c1\u009b'), 'c1');
  assert.ok(!sanitize('\u001b[31mred\u001b[0m').includes('\u001b'));
  // Tabs and newlines are text, not instructions.
  assert.equal(sanitize('a\tb\nc'), 'a\tb\nc');
});

test('defang neuters a URL without mangling the scheme', () => {
  // The bug this pins: a capture-group slip produced `hxxtp://`.
  assert.equal(defang('http://evil.example.com/a.exe'), 'hxxp://evil[.]example[.]com/a[.]exe');
  assert.equal(defang('https://evil.example.com'), 'hxxps://evil[.]example[.]com');
  assert.equal(defang('evil.example.com'), 'evil[.]example[.]com');
});

test('a zero or negative width never corrupts the text', () => {
  /* The regression: `process.stdout.columns` is 0 — not undefined — in a pty
     with no window size (script, CI, many containers), so `?? 100` kept the 0
     and every budget went negative. `slice(0, -n)` counts from the END, so
     short fields rendered as a lone ellipsis while a long value printed almost
     in full: the opposite of truncation. */
  const obj = { attackId: 'T1059', description: 'x'.repeat(200) };
  for (const width of [0, -50, 1, 20]) {
    const lines = renderDetail(obj, { width, color: false }).split('\n');
    assert.match(lines[0], /T1059/, `width ${width} lost a short value`);
    // Long values now wrap under their column rather than being cut to one
    // line, so the contract is "every line is bounded", not "line 2 is short".
    for (const line of lines) {
      assert.ok(line.length <= 60, `width ${width} produced a ${line.length}-char line`);
    }
    /* The value survives across those lines. Whitespace is stripped first
       because a long unbreakable token is hard-broken and each continuation is
       indented to the value column, so the raw join interleaves padding. */
    const joined = lines.join('').replace(/\s+/g, '');
    assert.ok(joined.includes('x'.repeat(40)), `width ${width} dropped the value`);
  }
});

test('a long value wraps under its own column and says where the rest is', () => {
  /* `description` IS the content of a detail view. Clipping it to one line
     meant Log4Shell's text ended at ~80 characters with no hint that --json
     held the remainder. */
  const out = renderDetail({ description: 'word '.repeat(400) }, { width: 80, color: false });
  const lines = out.split('\n');
  assert.ok(lines.length > 3, 'did not wrap');
  assert.ok(lines.every((l) => l.length <= 80), 'a wrapped line exceeded the width');
  assert.match(out, /--json for the rest/);
  // Continuation lines are indented to the value column, not to column zero.
  assert.match(lines[1], /^ {2,}\S/);
});

test('nested object scalars are reachable as dotted rows', () => {
  /* Seven endpoints rendered as field names and no values, because a nested
     object printed as `{attackVersion, domain, seededAt}`. */
  const out = renderDetail({ stats: { techniqueCount: 1073, groupCount: 180 } }, { width: 80, color: false });
  assert.match(out, /stats\.techniqueCount\s+1073/);
  assert.match(out, /stats\.groupCount\s+180/);
});

test('an all-arrays response previews its buckets instead of listing counts', () => {
  // /search returned `techniques [20] groups [20]` — seeing one hit cost
  // another call per bucket.
  const body = {
    query: 'lazarus',
    techniques: [{ attackId: 'T1', name: 'one' }],
    groups: [{ attackId: 'G1', name: 'two' }],
    software: [{ attackId: 'S1', name: 'three' }],
  };
  const out = renderDetail(body, { width: 100, color: false });
  assert.match(out, /techniques · 1/);
  assert.match(out, /one/);
  assert.match(out, /two/);
  // ...but an ordinary detail response with a couple of arrays is untouched.
  const detail = renderDetail({ name: 'T1', groups: [1, 2, 3], tactics: [] }, { width: 100, color: false });
  assert.match(detail, /--expand <field>/);
  assert.doesNotMatch(detail, /groups · 3/);
});

test('table columns lead with identity and label, not boilerplate', () => {
  const rows = [
    { id: 'uuid-1', stixId: 'x--1', url: 'https://a', description: 'long prose here', attackId: 'G0001', name: 'APT1' },
    { id: 'uuid-2', stixId: 'x--2', url: 'https://b', description: 'more prose here', attackId: 'G0002', name: 'APT2' },
  ];
  const header = renderList(rows, null, { width: 120 }).split('\n')[0];
  assert.match(header, /^attackId\s+name/, header);
});

test('a column with the same value in every row is ranked last', () => {
  const rows = [
    { attackId: 'G1', name: 'A', isRevoked: false, platform: 'windows' },
    { attackId: 'G2', name: 'B', isRevoked: false, platform: 'linux' },
  ];
  const header = renderList(rows, null, { width: 120 }).split('\n')[0];
  assert.ok(header.indexOf('platform') < header.indexOf('isRevoked'), header);
});

test('the list footer states the page, the total and how to get the rest', () => {
  const rows = [{ attackId: 'G1', name: 'A', extra1: 1, extra2: 2, extra3: 3, extra4: 4, extra5: 5 }];
  const out = renderList(rows, { page: 1, limit: 1, total: 40, totalPages: 40 }, { width: 120 });
  assert.match(out, /page 1\/40/);
  assert.match(out, /1 of 40 rows/);
  assert.match(out, /next: --page 2/);
  assert.match(out, /more fields per row/);
});

test('an empty list says so rather than printing nothing', () => {
  assert.match(renderList([], null, {}), /No rows matched/);
});

test('detail reduces arrays to counts and offers --expand', () => {
  const out = renderDetail({ name: 'T1', groups: [1, 2, 3], tactics: [] }, { width: 100 });
  assert.match(out, /groups\s+\[3\]/);
  assert.match(out, /tactics\s+\[0\]/);
  assert.match(out, /--expand <field>/);
});

test('--expand tables an array, and names the real fields when asked for a bad one', () => {
  const obj = { name: 'T1', groups: [{ attackId: 'G1', name: 'APT1' }] };
  assert.match(renderDetail(obj, { expand: 'groups', width: 100 }), /attackId\s+name/);
  const bad = renderDetail(obj, { expand: 'nope', width: 100 });
  assert.match(bad, /No array field "nope"/);
  assert.match(bad, /Available: groups/);
});

test('an IOC locator is defanged for the terminal whatever the caller asked for', () => {
  /* This test previously asserted that `defanged: false` left the URL intact,
     which encoded the bug: the caller decided by endpoint path, and
     /feed/intelligence was not on the list, so live C2 URLs printed clickable.
     An IOC-shaped row now defangs its locator regardless of the flag. Byte
     fidelity is not this module's job — the piped path never calls it. */
  const rows = [{ value: 'http://bad.example.com', type: 'url' }];
  for (const defanged of [true, false]) {
    assert.match(renderList(rows, null, { width: 120, defanged }), /hxxp:\/\/bad\[\.\]example/);
  }
  // A row that is not IOC-shaped keeps its URL: an ATT&CK entity's own `url`
  // is ours, not an adversary's, and mangling it would be noise.
  const entity = [{ attackId: 'T1059', url: 'https://attack.mitre.org/techniques/T1059' }];
  assert.match(renderList(entity, null, { width: 120 }), /https:\/\/attack\.mitre\.org/);
});

/* ── the security review's findings, pinned ─────────────────────────────── */

test('defang only rewrites things that look like a locator', () => {
  // The shape guard exists because defanging moved from a path allowlist to a
  // value test: without it, a CVSS score of 9.8 became 9[.]8.
  assert.equal(defang('9.8'), '9.8');
  assert.equal(defang('2026-10-01T10:00:00Z'), '2026-10-01T10:00:00Z');
  assert.equal(defang('CVSS:3.1/AV:N/AC:L'), 'CVSS:3.1/AV:N/AC:L');
  assert.equal(defang('144a0a499e007f2c'), '144a0a499e007f2c');
  // ...and still does its job on the real thing.
  assert.equal(defang('evil.example.com'), 'evil[.]example[.]com');
  assert.equal(defang('46.30.191.214'), '46[.]30[.]191[.]214');
  assert.equal(defang('http://elxxvvx.xyz/f'), 'hxxp://elxxvvx[.]xyz/f');
});

test('IOC rows are detected by shape, not by endpoint path', () => {
  /* The gate was `path.startsWith('/feed/iocs')`, and
     /feed/intelligence/{attackId} returns rows from the same ioc_entries
     table — so live C2 URLs rendered undefanged while the README promised
     otherwise. Shape covers any future endpoint serving the same rows. */
  assert.ok(isIocRow({ type: 'url', value: 'http://x.example' }));
  assert.ok(isIocRow({ type: 'DOMAIN', value: 'x.example' }));
  assert.ok(isIocRow({ type: 'ip', value: '1.2.3.4' }));
  assert.ok(!isIocRow({ type: 'hash', value: 'abc' }));
  assert.ok(!isIocRow({ attackId: 'T1059', name: 'x' }));
  assert.ok(!isIocRow(null));

  // End to end: an IOC-shaped row defangs its locator without being told to.
  const rows = [{ type: 'url', value: 'http://evil.example.com', confidence: 'inferred' }];
  assert.match(renderList(rows, null, { width: 120, defanged: false }), /hxxp:\/\/evil\[\.\]example/);
  // A non-IOC row with a dotted number is left alone.
  const scores = [{ cveId: 'CVE-1', cvssScore: 9.8 }];
  assert.match(renderList(scores, null, { width: 120 }), /9\.8/);
});

test('response field NAMES cannot carry control bytes or forge a line', () => {
  /* Keys never went through cell(), so they were the one place on the human
     path where an ESC could still reach the terminal — and the only place a
     newline could forge an output line, because cell() collapses whitespace in
     values but nothing collapsed it in keys. */
  const hostile = { name: 'ok', ['k\u001b]52;c;aGk=\u0007']: 'v', ['forged\nline']: 'v2' };
  const detail = renderDetail(hostile, { width: 100 });
  assert.ok(!detail.includes('\u001b'), 'ESC survived in a key');
  assert.ok(!detail.includes('\u0007'), 'BEL survived in a key');
  // 3 fields + the blank line and hint are absent (no arrays), so no extra line.
  assert.equal(detail.split('\n').length, 3, detail);

  const table = renderList([hostile], null, { width: 120 });
  assert.ok(!table.includes('\u001b'), 'ESC survived in a table header');

  // The array-expand hint and the bad-field error echo keys and argv too.
  const withArray = { arr: [1], ['bad\u001b[2J']: 'x' };
  assert.ok(!renderDetail(withArray, { width: 100 }).includes('\u001b'));
  const badExpand = renderDetail({ arr: [1] }, { expand: 'nope\u001b]52;c;aGk=\u0007', width: 100 });
  assert.ok(!badExpand.includes('\u001b'), 'ESC survived an --expand echo');
});

test('escapeForTerminal closes the C1 hole JSON.stringify leaves open', () => {
  /* JSON.stringify escapes C0 (ESC -> \\u001b) but passes U+007F-U+009F
     through raw. U+009B is CSI and U+009D is OSC to a UTF-8 terminal, so a
     payload needs no ESC byte at all. */
  const raw = JSON.stringify({ d: 'x\u009b2J\u009d52;c;aGk=\u009c' });
  assert.match(raw, /[\u007f-\u009f]/, 'premise changed: stringify now escapes C1');

  const safe = escapeForTerminal(raw);
  assert.doesNotMatch(safe, /[\u007f-\u009f]/);
  assert.match(safe, /\\u009b/);
  // Still the same JSON value, so piping it to a parser is unaffected.
  assert.deepEqual(JSON.parse(safe), JSON.parse(raw));
});
