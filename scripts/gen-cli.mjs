/**
 * Generate the CLI's command table from API_CATALOG.
 *
 * WHY THIS EXISTS: the CLI's whole promise is that its commands are the REST
 * surface, so the two cannot be allowed to drift. `src/lib/api-catalog.ts` is
 * the single description of that surface; this script turns it into a plain
 * `.mjs` table the published package carries, and `check-api-catalog.mjs`
 * fails the build when the committed table no longer matches the catalogue.
 *
 * WHY IT IMPORTS THE .ts RATHER THAN PARSING IT: `check-api-catalog.mjs` reads
 * the catalogue as TEXT and so sees only path/method/group/executable — it can
 * never reach `params` or their closed `values`, which is precisely what flag
 * validation needs. Node 24 strips types on import; the only thing that fails
 * is resolving the extensionless './site' specifier, which the resolve hook
 * below repairs in ten lines. So the generator works from the REAL objects.
 */
import { registerHooks } from 'node:module';
import { existsSync, readFileSync, writeFileSync, copyFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { collisions } from './lib/cli-mirror.mjs';
// The path -> command rule, shared with src/views/Cli.tsx so the /cli page
// cannot document commands the generated table does not contain.
import { commandFor } from '../src/lib/cli-command.mjs';
import { TRANSFORM_NAMES, RESERVED_FLAGS } from '../cli/lib/contract.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/** Lets a `.ts` module import `./site` the way TypeScript resolves it. */
registerHooks({
  resolve(spec, ctx, next) {
    try {
      return next(spec, ctx);
    } catch (err) {
      if (spec.startsWith('.') && ctx.parentURL?.endsWith('.ts')) {
        const url = new URL(`${spec}.ts`, ctx.parentURL);
        if (existsSync(url)) return next(`${spec}.ts`, ctx);
      }
      throw err;
    }
  },
});

/* pathToFileURL, because a bare absolute path is not a valid ESM specifier on
   Windows — `C:\...` parses as a URL scheme. */
const { API_CATALOG, PAGINATION_PARAMS, API_FACTS } = await import(
  pathToFileURL(join(ROOT, 'src/lib/api-catalog.ts')).href
);

/**
 * The full-text parameter is called `search` on 14 entries and `q` on 13, split
 * along no line a reader could learn. Every command therefore accepts
 * `-q`/`--query` and forwards it under whichever name that endpoint declares.
 * The declared name stays accepted too, so a copied curl line still works.
 */
const FULLTEXT = new Set(['search', 'q']);

/**
 * Commands whose positionals are NOT what the catalogue path calls them.
 *
 * `/applications/{vendor}/{product}` reads as typeable but the route matches
 * `applications.normalized`, a lowercase-alphanumerics-only slug. Sending a
 * real vendor name 400s. src/lib/tools/execute.ts solved this for the MCP
 * surface with normalizeAppPart(), noting it had 400'd 2,430 of 7,206
 * entries; the CLI applies the same transform rather than inventing one.
 */
const POSITIONAL_TRANSFORMS = { '/applications/{vendor}/{product}': 'appSlug' };


const commands = API_CATALOG.filter((e) => e.method === 'GET').map((entry) => {
  const { words, positionals } = commandFor(entry);
  // PAGINATION_PARAMS is additive and lives apart from each entry's own params,
  // exactly as the /open-apis request builder merges it. Lifted, not re-derived.
  const params = [...(entry.params ?? []), ...(entry.paginated ? PAGINATION_PARAMS : [])];
  const fulltext = params.find((p) => FULLTEXT.has(p.name))?.name ?? null;
  return {
    path: entry.path,
    words,
    positionals,
    summary: entry.summary,
    group: entry.group,
    paginated: Boolean(entry.paginated),
    example: entry.example ?? null,
    fulltext,
    transform: POSITIONAL_TRANSFORMS[entry.path] ?? null,
    params: params.map((p) => ({
      name: p.name,
      type: p.type,
      required: Boolean(p.required),
      values: p.values ? [...p.values] : null,
      note: p.note ?? null,
    })),
  };
});

/* Help groups by PATH ROOT, not by `group`. The catalogue's nine groups are a
   website taxonomy and two entries' group contradicts their own command name;
   a CLI reader scans for the word they are about to type. */
const roots = [...new Set(commands.map((c) => c.words[0]))].sort();

/* ───────────────────── invariants the CLI relies on ───────────────────── */

/**
 * A transform the generator names but dispatch.mjs does not implement.
 *
 * The table carries a transform NAME and dispatch resolves it from a map at
 * call time, so an unknown name passed every check, passed every test, and
 * then threw `TRANSFORMS[cmd.transform] is not a function` the first time a
 * user ran that one command.
 */
function unknownTransforms() {
  return Object.entries(POSITIONAL_TRANSFORMS)
    .filter(([, name]) => !TRANSFORM_NAMES.includes(name))
    .map(([path, name]) => `${path} names transform '${name}', which cli/lib/dispatch.mjs does not implement`);
}

/** A catalogue param that would shadow one of the CLI's own flags. */
function shadowedFlags(entries) {
  const out = [];
  for (const e of entries) {
    for (const p of e.params ?? []) {
      if (RESERVED_FLAGS.includes(p.name)) {
        out.push(`${e.path} declares a param named '${p.name}', which is one of the CLI's own flags`);
      }
    }
  }
  return out;
}

const getEntries = API_CATALOG.filter((e) => e.method === 'GET');
const problems = [
  ...collisions(getEntries),
  ...unknownTransforms(),
  ...shadowedFlags(getEntries),
];
if (problems.length) {
  console.error('gen-cli: the generated CLI would not be correct:');
  for (const p of problems) console.error(`  ${p}`);
  console.error('Resolve these before regenerating.');
  process.exit(1);
}

const banner = `/**
 * GENERATED by scripts/gen-cli.mjs from src/lib/api-catalog.ts. Do not edit.
 *
 * Regenerate with \`npm run gen:cli\`. \`npm run check:cli\` (scripts/gen-cli.mjs
 * --check) fails the build if this file and the catalogue disagree, so it
 * cannot drift silently.
 */`;

const generated = `${banner}
export const BASE_URL = ${JSON.stringify(API_FACTS.baseUrl)};
export const ROOTS = ${JSON.stringify(roots)};
export const COMMANDS = ${JSON.stringify(commands, null, 2)};
`;

const withFulltext = commands.filter((c) => c.fulltext).length;
const GENERATED_PATH = join(ROOT, 'cli/lib/commands.generated.mjs');
/* A byte-for-byte copy, so the published package is self-contained while the
   single source of truth stays in src/lib. --check asserts they are identical. */
const SHARED = [
  ['src/lib/api-request.mjs', 'cli/lib/api-request.mjs'],
  // The slug rule the ingest WRITES and the API and CLI must reproduce. It used
  // to be three separate copies compared by string-matching a regex literal,
  // which missed real drift and fired on reformatting. One module instead.
  ['src/lib/app-slug.mjs', 'cli/lib/app-slug.mjs'],
];

if (process.argv.includes('--check')) {
  const failures = [];
  const read = (p) => (existsSync(p) ? readFileSync(p, 'utf8') : null);

  if (read(GENERATED_PATH) !== generated) {
    failures.push('cli/lib/commands.generated.mjs is stale — run `npm run gen:cli` and commit the result');
  }
  for (const [src, copy] of SHARED) {
    const a = read(join(ROOT, src));
    const b = read(join(ROOT, copy));
    /* Existence asserted separately: `read()` returns null for a missing file,
       so a bare `a !== b` was `null !== null` — false — and the guard stayed
       silent when BOTH files had been renamed away. */
    if (a === null) failures.push(`${src} is missing — the CLI's copy is orphaned`);
    else if (b === null) failures.push(`${copy} is missing — run \`npm run gen:cli\``);
    else if (a !== b) failures.push(`${copy} differs from ${src} — run \`npm run gen:cli\``);
  }

  /* The README is the copy a user reads, and the only one that goes stale
     without anything breaking. Same principle as API_ENDPOINT_COUNT. */
  const readme = read(join(ROOT, 'cli/README.md')) ?? '';
  const searchCount = commands.filter((c) => c.fulltext === 'search').length;
  const qCount = commands.filter((c) => c.fulltext === 'q').length;
  const quoted = [
    [`all ${commands.length} commands`, 'the command count'],
    [`\`search\` on ${searchCount} endpoints and \`q\` on ${qCount}`, 'the search/q split'],
    [`works on all ${withFulltext}`, 'the full-text endpoint count'],
  ];
  for (const [text, label] of quoted) {
    if (!readme.includes(text)) failures.push(`cli/README.md no longer states ${label} ("${text}")`);
  }

  if (failures.length) {
    console.error('gen-cli --check failed:');
    for (const f of failures) console.error(`  ${f}`);
    process.exit(1);
  }
  console.log(`gen-cli --check: ok (${commands.length} commands, mirror unambiguous, shared module identical)`);
  process.exit(0);
}

writeFileSync(GENERATED_PATH, generated);
for (const [src, copy] of SHARED) copyFileSync(join(ROOT, src), join(ROOT, copy));

console.log(`gen-cli: ${commands.length} commands across ${roots.length} roots`);
console.log(`gen-cli: ${commands.filter((c) => c.positionals.length).length} take positionals, ${withFulltext} accept -q`);
console.log(`gen-cli: ${commands.reduce((n, c) => n + c.params.filter((p) => p.values).length, 0)} params carry a closed vocabulary`);
