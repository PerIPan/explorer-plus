/**
 * The CLI's argv → URL path decisions.
 *
 * Lives under scripts/ because that is the only tree `npm test` walks
 * (`node --test "scripts/**\/*.test.mjs"`), and imports the shipped modules
 * from cli/ directly — the code under test is the code that publishes.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  TREE,
  resolve,
  commandUsage,
  optionsFor,
  validate,
  buildPath,
  commandTokens,
  canonicaliseValues,
  UNION_OPTIONS,
  whoAccepts,
  searchSibling,
  exampleCommand,
} from '../../cli/lib/dispatch.mjs';
import { appSlug } from '../../cli/lib/app-slug.mjs';

test('every catalogue GET endpoint became a command', () => {
  assert.equal(TREE.length, 85);
  assert.ok(TREE.every((c) => c.path.startsWith('/')));
});

test('path mirroring resolves at every depth', () => {
  const cases = [
    [['techniques'], '/techniques', {}],
    [['techniques', 'T1059'], '/techniques/{attackId}', { attackId: 'T1059' }],
    [['techniques', 'T1059', 'packages'], '/techniques/{attackId}/packages', { attackId: 'T1059' }],
    [['feed', 'reports', 'R1', 'techniques'], '/feed/reports/{reportId}/techniques', { reportId: 'R1' }],
    [['frameworks', 'csf'], '/frameworks/csf', {}],
  ];
  for (const [tokens, path, values] of cases) {
    const r = resolve(tokens);
    assert.equal(r.cmd?.path, path, tokens.join(' '));
    assert.deepEqual(r.pathValues, values);
  }
});

test('a static sub-path wins over a dynamic sibling', () => {
  // /frameworks/csf is a route and /frameworks/{x} is not, but the inverse
  // ordering would silently send 'csf' as an id. TREE sorts most-static-first.
  assert.equal(resolve(['frameworks', 'csf']).cmd.path, '/frameworks/csf');
  assert.equal(resolve(['frameworks', 'technique', 'T1059']).cmd.path, '/frameworks/technique/{attackId}');
});

test('an unmatched command reports the closest real commands first', () => {
  // /feed/reports/{reportId} is not a route, though its child is.
  const r = resolve(['feed', 'reports', 'R1']);
  assert.equal(r.cmd, null);
  assert.equal(r.near[0], 'feed reports <reportId> techniques');
});

test('commandTokens separates positionals from flag values, wherever they sit', () => {
  /* Three regressions live in this one test, all of which produced a DIFFERENT
     command rather than an error — the worst failure mode this CLI has:
       - untyped `strict:false` read `cves --severity CRITICAL --limit 3` as the
         positionals ['cves','CRITICAL','3']
       - "stop at the first '-'" dropped `T1059` from `techniques --json T1059`,
         silently returning the 50-row list with exit 0
       - the same rule swallowed `--`, discarding the positional it protects */
  const t = (argv) => commandTokens(argv);
  assert.deepEqual(t(['cves', '--severity', 'CRITICAL', '--limit', '3']), ['cves']);
  assert.deepEqual(t(['groups', '-q', 'lazarus']), ['groups']);
  assert.deepEqual(t(['techniques', '--json', 'T1059']), ['techniques', 'T1059']);
  assert.deepEqual(t(['--json', 'techniques', 'T1059']), ['techniques', 'T1059']);
  assert.deepEqual(t(['cves', '--severity', 'HIGH', 'CVE-2021-44228']), ['cves', 'CVE-2021-44228']);
  assert.deepEqual(t(['techniques', '--', 'T1059']), ['techniques', 'T1059']);
  assert.deepEqual(t(['external-actors', '--', '-8220 Gang']), ['external-actors', '-8220 Gang']);
  assert.deepEqual(t(['techniques', 'T1059', 'packages']), ['techniques', 'T1059', 'packages']);
  assert.deepEqual(t([]), []);

  // ...and each of those resolves to the command the user plainly meant.
  assert.equal(resolve(t(['techniques', '--json', 'T1059'])).cmd.path, '/techniques/{attackId}');
  assert.equal(resolve(t(['cves', '--severity', 'HIGH', 'CVE-2021-44228'])).cmd.path, '/cves/{cveId}');
  assert.equal(resolve(t(['external-actors', '--', '-8220 Gang'])).cmd.path, '/external-actors/{name}');
});

test('the union options table cannot mis-type a flag', () => {
  // It is only safe because no two commands disagree about a param's type.
  const byName = new Map();
  for (const cmd of TREE) {
    for (const p of cmd.params) {
      const type = p.type === 'boolean' ? 'boolean' : 'string';
      if (byName.has(p.name)) assert.equal(byName.get(p.name), type, `${p.name} type conflict`);
      byName.set(p.name, type);
    }
  }
  for (const [name, type] of byName) assert.equal(UNION_OPTIONS[name]?.type, type, name);
});

test('a closed vocabulary is matched case-insensitively against its OWN command', () => {
  /* `--severity high` was rejected, and the error then pointed at capec,
     advisories and ghsa — three other commands — because the cross-command
     lookup ran before anyone checked this command's values in another case. */
  const cves = resolve(['cves']).cmd;
  assert.deepEqual(canonicaliseValues(cves, { severity: 'high' }), { severity: 'HIGH' });
  assert.deepEqual(validate(cves, canonicaliseValues(cves, { severity: 'high' }), {}), []);
  // An unknown value still errors, and still says where it IS valid.
  const errs = validate(cves, canonicaliseValues(cves, { severity: 'Very High' }), {});
  assert.equal(errs.length, 1);
  assert.match(errs[0], /valid for: capec/);
});

test('an empty value is rejected rather than silently dropped', () => {
  /* composePath drops an empty query value and the server normalises an empty
     path segment, so both used to return the unfiltered LIST with exit 0. */
  const techniques = resolve(['techniques']).cmd;
  assert.deepEqual(validate(techniques, { query: '' }, {}), ['--query was given no value']);
  const detail = resolve(['techniques', 'T1059']).cmd;
  assert.deepEqual(validate(detail, {}, { attackId: '' }), ['<attackId> cannot be empty']);
  assert.deepEqual(validate(detail, {}, { attackId: 'T1059' }), []);
});

test('-q maps to whichever name the endpoint declares', () => {
  // The catalogue calls full text `search` on 14 endpoints and `q` on 13.
  const groups = resolve(['groups']).cmd;
  const cves = resolve(['cves']).cmd;
  assert.equal(groups.fulltext, 'search');
  assert.equal(cves.fulltext, 'q');
  assert.equal(buildPath(groups, {}, { query: 'lazarus' }), '/groups?search=lazarus');
  assert.equal(buildPath(cves, {}, { query: 'log4j' }), '/cves?q=log4j');
});

test('-q is offered on exactly the endpoints that accept full text', () => {
  const withFulltext = TREE.filter((c) => c.fulltext);
  assert.equal(withFulltext.length, 27);
  for (const cmd of withFulltext) assert.ok(optionsFor(cmd).query, commandUsage(cmd));
  for (const cmd of TREE.filter((c) => !c.fulltext)) {
    assert.equal(optionsFor(cmd).query, undefined, commandUsage(cmd));
  }
});

test('application positionals are normalized the way the ingest normalized them', () => {
  // applications.normalized is [a-z0-9] per part; sending a real vendor name
  // 400s. Mirrors normalizeAppPart() in src/lib/tools/execute.ts.
  assert.equal(appSlug('Red Hat'), 'redhat');
  assert.equal(appSlug('log4j-core'), 'log4jcore');
  assert.equal(appSlug('iphone_os'), 'iphoneos');
  assert.equal(appSlug('Comelit Group S.p.A.'), 'comelitgroupspa');
  const cmd = resolve(['applications', 'Red Hat', 'OpenShift 4']).cmd;
  assert.equal(
    buildPath(cmd, { vendor: 'Red Hat', product: 'OpenShift 4' }, {}),
    '/applications/redhat/openshift4',
  );
});

test('closed vocabularies are enforced per command', () => {
  const cves = resolve(['cves']).cmd;
  assert.deepEqual(validate(cves, { severity: 'CRITICAL' }, {}), []);
  const errs = validate(cves, { severity: 'Very High' }, {});
  assert.equal(errs.length, 1);
  assert.match(errs[0], /must be one of: CRITICAL, HIGH, MEDIUM, LOW/);
  // The same flag name carries a different vocabulary on /capec, so the error
  // says where the typed value IS valid.
  assert.match(errs[0], /valid for: capec/);
});

test('whoAccepts finds the command whose vocabulary takes a value', () => {
  assert.deepEqual(whoAccepts('severity', 'Very High'), ['capec']);
  assert.ok(whoAccepts('severity', 'CRITICAL').includes('cves'));
});

test('a missing required flag is reported under a spelling that works', () => {
  // /search declares its full-text param as `q`, but `--q` is not accepted by
  // the parser — only -q/--query is. "--q is required" sent readers to a flag
  // that then errored.
  const search = resolve(['search']).cmd;
  assert.deepEqual(validate(search, { query: 'lazarus' }, {}), []);
  assert.deepEqual(validate(search, {}, {}), ['-q (--query) is required']);
  // A required flag that is NOT the full-text one keeps its own name.
  const byTechniques = resolve(['frameworks', 'by-techniques']).cmd;
  assert.deepEqual(validate(byTechniques, {}, {}), ['--ids is required']);
});

test('empty and false flags are dropped rather than sent', () => {
  const cmd = resolve(['techniques']).cmd;
  assert.equal(buildPath(cmd, {}, {}), '/techniques');
  assert.equal(buildPath(cmd, {}, { include_deprecated: false }), '/techniques');
  assert.equal(buildPath(cmd, {}, { include_deprecated: true }), '/techniques?include_deprecated=1');
});

test('path values are URL-encoded', () => {
  const cmd = resolve(['external-actors', 'x']).cmd;
  assert.equal(buildPath(cmd, { name: '8220 Gang' }, {}), '/external-actors/8220%20Gang');
});

test('canonically upper-case ids are upper-cased; mixed-case ids are not', () => {
  // `techniques t1059` and `cves cve-2021-44228` both returned 400 from the
  // route's own format regex.
  const tech = resolve(['techniques', 'x']).cmd;
  assert.equal(buildPath(tech, { attackId: 't1059' }, {}), '/techniques/T1059');
  assert.equal(buildPath(tech, { attackId: 't1059.001' }, {}), '/techniques/T1059.001');
  const cve = resolve(['cves', 'x']).cmd;
  assert.equal(buildPath(cve, { cveId: 'cve-2021-44228' }, {}), '/cves/CVE-2021-44228');
  // GHSA and D3FEND ids are mixed-case; upper-casing them would break ids that
  // work today.
  const ghsa = resolve(['ghsa', 'x']).cmd;
  assert.equal(
    buildPath(ghsa, { ghsaId: 'GHSA-jfh8-c2jp-5v3q' }, {}),
    '/ghsa/GHSA-jfh8-c2jp-5v3q',
  );
});

test('searchSibling finds the full-text list command for a root', () => {
  // This is what redirects `mitrex groups APT29` (a name where an id goes).
  assert.equal(commandUsage(searchSibling('groups')), 'groups');
  assert.equal(searchSibling('nav-counts'), null);
});

test('every worked example round-trips into a runnable command', () => {
  /* 83 of 85 entries carry an example that returns 200. Help now prints it, so
     a malformed one would be a copy-paste trap rather than a dead comment. */
  const withExample = TREE.filter((c) => c.example);
  assert.equal(withExample.length, 83);
  for (const cmd of withExample) {
    const line = exampleCommand(cmd);
    assert.ok(line.startsWith('mitrex '), cmd.path);
    // The example must name the command it belongs to...
    const argv = line.split(' ').slice(1);
    const resolved = resolve(commandTokens(argv));
    assert.equal(resolved.cmd?.path, cmd.path, line);
    // ...and must not advertise a flag that command rejects.
    const opts = optionsFor(cmd);
    for (const token of argv.filter((t) => t.startsWith('--'))) {
      assert.ok(opts[token.slice(2)], `${line} uses ${token}, which ${cmd.path} rejects`);
    }
  }
});
