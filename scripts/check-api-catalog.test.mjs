// Tests for the open-API catalogue guard.
//
// Two jobs. The first four suites feed the pure comparators synthetic input and
// assert they FAIL — a guard nobody has watched fail is a guard nobody knows
// works. The last suite runs the real check against the real tree, so `npm test`
// is itself the drift gate: catalogue an endpoint that does not exist, or add a
// route and document it nowhere, and this goes red before CI does.

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  EXCLUDED,
  routeFileToPath,
  shape,
  diffCatalogue,
  diffMethods,
  checkTools,
  checkLlmsTxt,
  collectRoutes,
  run,
} from './check-api-catalog.mjs';

test('routeFileToPath maps the route tree to catalogue paths', () => {
  assert.equal(routeFileToPath('app/api/v1/cves/route.ts'), '/cves');
  assert.equal(routeFileToPath('app/api/v1/cves/[cveId]/packages/route.ts'), '/cves/{cveId}/packages');
  assert.equal(routeFileToPath('app/api/v1/feed/[source]/sync/route.ts'), '/feed/{source}/sync');
  assert.equal(routeFileToPath('app/api/v1/applications/[...slug]/route.ts'), '/applications/{...slug}');
});

test('shape compares by placeholder position, not parameter name', () => {
  assert.equal(shape('/cves/{cveId}'), shape('/cves/{id}'));
  assert.equal(shape('/packages/{ecosystem}/{nameEncoded}'), shape('/packages/{ecosystem}/{name}'));
  // The catch-all must NOT collapse to the same shape as one fixed segment,
  // or a variable-width route would silently match a single-segment entry.
  assert.notEqual(shape('/applications/{...slug}'), shape('/applications/{vendor}'));
  assert.equal(shape('/applications/{...slug}'), '/applications/{...}');
});

test('diffCatalogue fails on a route that is neither documented nor excluded', () => {
  const failures = diffCatalogue({
    routePaths: ['/cves', '/brand-new-thing'],
    entries: [{ path: '/cves', method: 'GET' }],
    excluded: {},
  });
  assert.equal(failures.length, 1);
  assert.match(failures[0], /brand-new-thing/);
  assert.match(failures[0], /NEITHER the catalogue nor EXCLUDED/);
});

test('diffCatalogue accepts a route that is excluded with a reason', () => {
  const failures = diffCatalogue({
    routePaths: ['/cves', '/site-health'],
    entries: [{ path: '/cves', method: 'GET' }],
    excluded: { '/site-health': 'site furniture' },
  });
  assert.deepEqual(failures, []);
});

test('diffCatalogue fails on a catalogued endpoint that does not exist', () => {
  const failures = diffCatalogue({
    routePaths: ['/cves'],
    entries: [{ path: '/cves', method: 'GET' }, { path: '/imaginary', method: 'GET' }],
    excluded: {},
  });
  assert.equal(failures.length, 1);
  assert.match(failures[0], /GET \/imaginary has no route/);
});

test('diffCatalogue fails when an endpoint is both catalogued and excluded', () => {
  const failures = diffCatalogue({
    routePaths: ['/site-health'],
    entries: [{ path: '/site-health', method: 'GET' }],
    excluded: { '/site-health': 'site furniture' },
  });
  assert.equal(failures.length, 1);
  assert.match(failures[0], /BOTH catalogued and EXCLUDED/);
});

test('diffCatalogue resolves the catch-all alias', () => {
  const failures = diffCatalogue({
    routePaths: ['/applications/{...slug}'],
    entries: [{ path: '/applications/{vendor}/{product}', method: 'GET' }],
    excluded: {},
  });
  assert.deepEqual(failures, []);
});

test('diffMethods fails when the documented verb is not exported', () => {
  const failures = diffMethods({
    entries: [{ path: '/cves', method: 'POST' }],
    routeMethods: { '/cves': ['GET'] },
  });
  assert.equal(failures.length, 1);
  assert.match(failures[0], /says POST \/cves but the route exports only GET/);
});

test('checkTools catches every shape of tool-count drift', () => {
  // The exact failure this guard exists for: site.ts said 43, llms.txt 42.
  const countDrift = checkTools({
    declared: ['a', 'b'],
    agentToolCount: 3,
    grouped: ['a', 'b'],
    endpointKeys: ['a', 'b'],
  });
  assert.equal(countDrift.length, 1);
  assert.match(countDrift[0], /AGENT_TOOL_COUNT.*is 3 but TOOL_DECLARATIONS has 2/);

  const ungrouped = checkTools({
    declared: ['a', 'b'],
    agentToolCount: 2,
    grouped: ['a'],
    endpointKeys: ['a', 'b'],
  });
  assert.match(ungrouped.join('\n'), /'b' is declared but ungrouped/);

  const duplicated = checkTools({
    declared: ['a'],
    agentToolCount: 1,
    grouped: ['a', 'a'],
    endpointKeys: ['a'],
  });
  assert.match(duplicated.join('\n'), /lists 'a' 2 times/);

  const phantom = checkTools({
    declared: ['a'],
    agentToolCount: 1,
    grouped: ['a', 'ghost'],
    endpointKeys: ['a'],
  });
  assert.match(phantom.join('\n'), /'ghost', which is not a declared tool/);

  const noEndpoint = checkTools({
    declared: ['a'],
    agentToolCount: 1,
    grouped: ['a'],
    endpointKeys: [],
  });
  assert.match(noEndpoint.join('\n'), /no TOOL_ENDPOINTS mapping/);

  assert.deepEqual(
    checkTools({ declared: ['a', 'b'], agentToolCount: 2, grouped: ['b', 'a'], endpointKeys: ['a', 'b'] }),
    [],
  );
});

test('checkLlmsTxt catches a stale count, a missing endpoint and a resurrected rate-limit claim', () => {
  const origin = 'https://example.test';
  const good = [
    `- REST: ${origin}/api/v1`,
    `- MCP: ${origin}/api/mcp exposes the same 43-tool catalogue.`,
    `- A2A: ${origin}/api/a2a`,
  ].join('\n');
  assert.deepEqual(checkLlmsTxt(good, { toolCount: 43, origin }), []);

  assert.match(
    checkLlmsTxt(good, { toolCount: 44, origin }).join('\n'),
    /says "43-tool" but the catalogue has 44/,
  );
  assert.match(
    checkLlmsTxt(good.replace(`${origin}/api/mcp`, '/api/mcp'), { toolCount: 43, origin }).join('\n'),
    /does not mention https:\/\/example\.test\/api\/mcp/,
  );
  assert.match(
    checkLlmsTxt(`${good}\n- heavy traffic is rate-limited per IP at the edge`, { toolCount: 43, origin }).join('\n'),
    /claims a per-IP rate limit/,
  );
  assert.match(
    checkLlmsTxt(good.replace('43-tool', 'big'), { toolCount: 43, origin }).join('\n'),
    /no "<n>-tool" phrase/,
  );
});

test('the real catalogue covers the real route tree', () => {
  const { failures, counts } = run();
  assert.deepEqual(failures, [], `catalogue drift:\n${failures.join('\n')}`);
  // Catalogued + excluded must account for every route, with nothing left over.
  assert.equal(counts.catalogued + counts.excluded, counts.routes);
  assert.equal(counts.excluded, Object.keys(EXCLUDED).length);
  assert.ok(counts.routes >= 86, `expected at least 86 routes, found ${counts.routes}`);
  assert.equal(counts.tools, 43);
});

test('every route file is discovered and reports its exported verbs', () => {
  const { paths, methods } = collectRoutes();
  assert.equal(paths.length, Object.keys(methods).length, 'a route path collided');
  const verbless = paths.filter((p) => methods[p].length === 0);
  assert.deepEqual(verbless, [], `route files exporting no HTTP verb: ${verbless.join(', ')}`);
});
