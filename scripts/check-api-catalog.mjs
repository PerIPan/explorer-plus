#!/usr/bin/env node
// Guard: the open-API catalogue (src/lib/api-catalog.ts) is the single
// description of the public surface, read by the header modal, /open-apis and
// /open-mcp. Before it existed, each surface carried its own hand-written list —
// and the one in AppShell.tsx had drifted to 55 documented paths against 86 real
// routes, while the agent tool count read 43 in two places, 42 in llms.txt and
// 47 in a task brief. Nothing failed. This is what fails.
//
// It enforces five things:
//   1. every route under app/api/v1 is either CATALOGUED or in EXCLUDED below;
//   2. every catalogue entry resolves to a real route, with a matching method;
//   3. AGENT_TOOL_COUNT === TOOL_DECLARATIONS.length, and every declared tool is
//      grouped exactly once and has an endpoint mapping;
//   4. public/llms.txt quotes the same tool count and the same origin;
//   5. API_ENDPOINT_COUNT === API_CATALOG.length (the sidebar quotes it).
//
// It parses TEXT rather than importing, because `npm test` runs
// `node --test "scripts/**/*.test.mjs"` and node cannot import a .ts module.
// The catalogue therefore stays .ts (it is a client import) and this file reads
// it as source. The regexes are strict and self-checking: if the catalogue is
// reformatted so an entry's fields no longer sit on one line, the entry-count
// cross-check below fails loudly rather than silently skipping entries.

import { readFileSync } from 'node:fs';
import { readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const read = (rel) => readFileSync(join(ROOT, rel), 'utf8');

/* ─────────────────────────────────────────────────────────────────────────
 * Routes deliberately ABSENT from the catalogue.
 *
 * The catalogue is a consumer-facing list — endpoints an outside caller could
 * use to get information for their own project — not an inventory of the route
 * tree. These four exist to run this site, so they are not advertised. The
 * reasons are the record of a decision, for whoever next asks "why isn't export
 * in here?"; they are never rendered to a visitor.
 *
 * Adding a route to /api/v1 and forgetting both lists fails this guard, which
 * is the point: the exclusion has to be argued for in review.
 * ───────────────────────────────────────────────────────────────────────── */
export const EXCLUDED = {
  '/feed/vt-lookup': 'Spends the owner\'s VirusTotal API quota on every call, and 400s without a hash.',
  '/feed/{source}/sync': 'Operational: POST triggers a feed ingest and is cron-authenticated.',
  '/profile/submit': 'Internal telemetry write — records one profile answer set.',
  '/export/{entityType}': 'Bulk CSV export stays a reason to visit the site, not an advertised scrape endpoint (product call, 2026-09-26).',
  '/site-health': 'Site furniture: this site\'s own VirusTotal verdict, read by the header badge. Says nothing about threat data.',
};

/* ───────────────────────────── pure helpers ───────────────────────────── */

/**
 * `app/api/v1/cves/[cveId]/packages/route.ts` -> `/cves/{cveId}/packages`.
 * A catch-all `[...slug]` keeps its spread so `shape()` can count it as one
 * variable-width segment.
 */
export function routeFileToPath(relPath) {
  return (
    '/' +
    relPath
      .replace(/\\/g, '/')
      .replace(/^app\/api\/v1\/?/, '')
      .replace(/\/?route\.ts$/, '')
  )
    .replace(/\/+$/, '')
    .replace(/\[\.\.\.([^\]]+)\]/g, '{...$1}')
    .replace(/\[([^\]]+)\]/g, '{$1}')
    || '/';
}

/**
 * Compare paths by SHAPE, so renaming a path parameter in either the route tree
 * or the catalogue is not a failure — `/cves/{cveId}` and `/cves/{id}` describe
 * the same endpoint. Placeholder segments collapse to `{}`.
 */
export function shape(path) {
  // A sentinel for the catch-all, because `{...}` would itself be swallowed by
  // the ordinary-placeholder replace that follows it.
  const SENTINEL = '\u0000';
  return path
    .replace(/\{\.\.\.[^}]*\}/g, SENTINEL)
    .replace(/\{[^}]*\}/g, '{}')
    .split(SENTINEL)
    .join('{...}');
}

/**
 * Catch-all routes whose catalogue path spells the segments out. One entry:
 * `/applications/[...slug]` is documented as `/applications/{vendor}/{product}`
 * because that is what a caller types. Keyed by route shape.
 */
export const CATCHALL_ALIASES = {
  '/applications/{...}': '/applications/{}/{}',
};

/** Which routes are undocumented, and which entries point at nothing. */
export function diffCatalogue({ routePaths, entries, excluded }) {
  const failures = [];
  const excludedShapes = new Map(Object.keys(excluded).map((p) => [shape(p), p]));
  const entryShapes = new Map();
  for (const e of entries) entryShapes.set(shape(e.path), e);

  const seenRouteShapes = new Set();
  for (const route of routePaths) {
    let s = shape(route);
    if (CATCHALL_ALIASES[s]) s = CATCHALL_ALIASES[s];
    seenRouteShapes.add(s);
    if (entryShapes.has(s)) continue;
    if (excludedShapes.has(s)) continue;
    failures.push(
      `route /api/v1${route} is in NEITHER the catalogue nor EXCLUDED — document it in src/lib/api-catalog.ts, or add it to EXCLUDED in this script with the reason it is internal`,
    );
  }
  for (const [s, e] of entryShapes) {
    if (!seenRouteShapes.has(s)) {
      failures.push(`catalogue entry ${e.method} ${e.path} has no route under app/api/v1`);
    }
    if (excludedShapes.has(s)) {
      failures.push(`${e.path} is BOTH catalogued and EXCLUDED — pick one`);
    }
  }
  return failures;
}

/** An entry claiming POST against a GET-only route would mislead every caller. */
export function diffMethods({ entries, routeMethods }) {
  const failures = [];
  const byShape = new Map();
  for (const [route, methods] of Object.entries(routeMethods)) {
    let s = shape(route);
    if (CATCHALL_ALIASES[s]) s = CATCHALL_ALIASES[s];
    byShape.set(s, methods);
  }
  for (const e of entries) {
    const methods = byShape.get(shape(e.path));
    if (!methods) continue; // already reported by diffCatalogue
    if (!methods.includes(e.method)) {
      failures.push(
        `catalogue says ${e.method} ${e.path} but the route exports only ${methods.join(', ') || '(nothing)'}`,
      );
    }
  }
  return failures;
}

/**
 * The sidebar quotes the endpoint count as a constant, because importing the
 * catalogue into the shell would ship all 81 descriptions on every page. That
 * constant is exactly the kind of hand-maintained number this guard exists for.
 */
export function checkEndpointCount({ apiEndpointCount, entries }) {
  if (apiEndpointCount === entries.length) return [];
  return [
    `API_ENDPOINT_COUNT in src/lib/site.ts is ${apiEndpointCount} but API_CATALOG has ${entries.length} entries`,
  ];
}

/** The drift this guard was written for: four surfaces, three numbers. */
export function checkTools({ declared, agentToolCount, grouped, endpointKeys }) {
  const failures = [];
  if (agentToolCount !== declared.length) {
    failures.push(
      `AGENT_TOOL_COUNT in src/lib/site.ts is ${agentToolCount} but TOOL_DECLARATIONS has ${declared.length} tools`,
    );
  }
  const declaredSet = new Set(declared);
  const seen = new Map();
  for (const name of grouped) seen.set(name, (seen.get(name) ?? 0) + 1);
  for (const [name, n] of seen) {
    if (!declaredSet.has(name)) failures.push(`TOOL_GROUPS lists '${name}', which is not a declared tool`);
    if (n > 1) failures.push(`TOOL_GROUPS lists '${name}' ${n} times — a tool belongs to one group`);
  }
  for (const name of declared) {
    if (!seen.has(name)) failures.push(`tool '${name}' is declared but ungrouped in TOOL_GROUPS — /open-mcp would not show it`);
    if (!endpointKeys.includes(name)) failures.push(`tool '${name}' has no TOOL_ENDPOINTS mapping`);
  }
  for (const name of endpointKeys) {
    if (!declaredSet.has(name)) failures.push(`TOOL_ENDPOINTS maps '${name}', which is not a declared tool`);
  }
  return failures;
}

/** llms.txt is the only machine-readable copy of these facts. It drifted first. */
export function checkLlmsTxt(text, { toolCount, origin }) {
  const failures = [];
  const m = text.match(/(\d+)-tool/);
  if (!m) {
    failures.push('public/llms.txt: no "<n>-tool" phrase found — it is the machine-readable statement of the catalogue size');
  } else if (Number(m[1]) !== toolCount) {
    failures.push(`public/llms.txt says "${m[1]}-tool" but the catalogue has ${toolCount} tools`);
  }
  for (const needed of [`${origin}/api/v1`, `${origin}/api/mcp`, `${origin}/api/a2a`]) {
    if (!text.includes(needed)) failures.push(`public/llms.txt does not mention ${needed}`);
  }
  if (/rate[- ]limit(ed)? per IP/i.test(text)) {
    failures.push('public/llms.txt claims a per-IP rate limit on the REST API. There is none — only /api/a2a and /api/v1/profile/submit are metered');
  }
  return failures;
}

/* ─────────────────────────── source parsing ─────────────────────────── */

function walkRoutes(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) walkRoutes(full, out);
    else if (name === 'route.ts') out.push(full);
  }
  return out;
}

export function collectRoutes() {
  const base = join(ROOT, 'app/api/v1');
  const paths = [];
  const methods = {};
  for (const file of walkRoutes(base).sort()) {
    const rel = relative(ROOT, file);
    const p = routeFileToPath(rel);
    paths.push(p);
    const src = readFileSync(file, 'utf8');
    methods[p] = [...src.matchAll(/export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)/g)].map((m) => m[1]);
  }
  return { paths, methods };
}

/** Text between `export const NAME` and the next line that is exactly `];` / `};`. */
function slice(src, name) {
  const start = src.indexOf(`export const ${name}`);
  if (start === -1) throw new Error(`check-api-catalog: ${name} not found — was it renamed?`);
  const end = src.indexOf('\n];', start) !== -1 ? src.indexOf('\n];', start) : src.indexOf('\n};', start);
  if (end === -1) throw new Error(`check-api-catalog: could not find the end of ${name}`);
  return src.slice(start, end);
}

export function parseCatalog(src) {
  const body = slice(src, 'API_CATALOG');
  const lines = [...body.matchAll(/^\s*path: '([^']+)',\s*method: '(GET|POST)',\s*group: '([a-z]+)',(.*)$/gm)];
  const entries = lines.map(([, path, method, group, rest]) => ({
    path,
    method,
    group,
    executable: /executable:\s*true/.test(rest),
  }));
  // Self-check: every `path: '...'` in the array must have produced an entry.
  // Guards against a reformat quietly shrinking what this script sees.
  const rawPaths = [...body.matchAll(/^\s*path: '/gm)].length;
  if (rawPaths !== entries.length) {
    throw new Error(
      `check-api-catalog: parsed ${entries.length} entries but found ${rawPaths} 'path:' lines in API_CATALOG. ` +
        'Each entry must keep path/method/group on its first line, or this guard stops seeing them.',
    );
  }
  const groupBody = slice(src, 'TOOL_GROUPS');
  const grouped = [...groupBody.matchAll(/tools: \[([^\]]*)\]/g)]
    .flatMap(([, list]) => [...list.matchAll(/'([a-z0-9_]+)'/g)].map((m) => m[1]));
  const endpointBody = slice(src, 'TOOL_ENDPOINTS');
  const endpointKeys = [...endpointBody.matchAll(/^\s{2}([a-z0-9_]+):/gm)].map((m) => m[1]);
  return { entries, grouped, endpointKeys };
}

/* ───────────────────────────────── main ───────────────────────────────── */

export function run() {
  const catalogSrc = read('src/lib/api-catalog.ts');
  const { entries, grouped, endpointKeys } = parseCatalog(catalogSrc);
  const { paths, methods } = collectRoutes();

  const declared = [...read('src/lib/tools/declarations.ts').matchAll(/^\s{4}name: '([a-z0-9_]+)',$/gm)].map((m) => m[1]);
  const siteSrc = read('src/lib/site.ts');
  const countMatch = siteSrc.match(/AGENT_TOOL_COUNT\s*=\s*(\d+)/);
  const endpointCountMatch = siteSrc.match(/API_ENDPOINT_COUNT\s*=\s*(\d+)/);
  const originMatch = siteSrc.match(/NEXT_PUBLIC_SITE_URL\s*\|\|\s*'([^']+)'/);
  if (!countMatch) throw new Error('check-api-catalog: AGENT_TOOL_COUNT not found in src/lib/site.ts');
  if (!endpointCountMatch) throw new Error('check-api-catalog: API_ENDPOINT_COUNT not found in src/lib/site.ts');
  if (!originMatch) throw new Error('check-api-catalog: SITE_URL default not found in src/lib/site.ts');

  const failures = [
    ...diffCatalogue({ routePaths: paths, entries, excluded: EXCLUDED }),
    ...diffMethods({ entries, routeMethods: methods }),
    ...checkEndpointCount({ apiEndpointCount: Number(endpointCountMatch[1]), entries }),
    ...checkTools({ declared, agentToolCount: Number(countMatch[1]), grouped, endpointKeys }),
    ...checkLlmsTxt(read('public/llms.txt'), { toolCount: declared.length, origin: originMatch[1] }),
  ];

  const excludedFound = paths.filter((p) => {
    const s = shape(p);
    return Object.keys(EXCLUDED).some((e) => shape(e) === s);
  });
  for (const key of Object.keys(EXCLUDED)) {
    if (!excludedFound.some((p) => shape(p) === shape(key))) {
      failures.push(`EXCLUDED lists ${key}, which is no longer a route — drop the exclusion`);
    }
  }

  return {
    failures,
    counts: {
      routes: paths.length,
      catalogued: entries.length,
      excluded: excludedFound.length,
      executable: entries.filter((e) => e.executable).length,
      tools: declared.length,
    },
  };
}

function main() {
  let result;
  try {
    result = run();
  } catch (err) {
    console.error(`FAIL: ${err.message}`);
    process.exit(1);
  }
  const { failures, counts } = result;
  if (failures.length) {
    console.error('\nOpen-API catalogue drift:');
    for (const f of failures) console.error(`  - ${f}`);
    console.error('\nSource of truth: src/lib/api-catalog.ts (paths) + src/lib/tools/declarations.ts (tools).');
    process.exit(1);
  }
  console.log(
    `OK: ${counts.catalogued} catalogued + ${counts.excluded} excluded = ${counts.routes} routes under /api/v1 ` +
      `(${counts.executable} with a live example); ${counts.tools} agent tools, all grouped, counted and quoted consistently.`,
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
