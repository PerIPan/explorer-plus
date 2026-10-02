/**
 * Turning argv into a request — the whole of the CLI's decision-making, kept
 * pure so it tests without a network or a terminal.
 *
 * The command tree mirrors the REST paths. That is only unambiguous because no
 * parent path in the catalogue has both a static and a dynamic child, which
 * `scripts/gen-cli.mjs` asserts via `collisions()` in scripts/lib/cli-mirror.mjs
 * and refuses to generate when violated — so this file never has to guess.
 */
import { parseArgs } from 'node:util';
import { COMMANDS } from './commands.generated.mjs';
import { composePath, seedValues } from './api-request.mjs';
import { appSlug } from './app-slug.mjs';
import { RESERVED_FLAGS } from './contract.mjs';

/** `{id}` is one segment, `{...slug}` swallows the rest. */
const PLACEHOLDER = /^\{(\.\.\.)?([^}]+)\}$/;

/** Ordered segments of a command's path: either a literal word or a variable. */
function segmentsOf(path) {
  return path
    .split('/')
    .filter(Boolean)
    .map((seg) => {
      const m = PLACEHOLDER.exec(seg);
      return m ? { var: m[2], catchAll: Boolean(m[1]) } : { word: seg };
    });
}

/** Commands with their segments pre-parsed, most-specific first. */
export const TREE = COMMANDS.map((c) => ({ ...c, segs: segmentsOf(c.path) })).sort(
  (a, b) => b.segs.filter((s) => s.word).length - a.segs.filter((s) => s.word).length,
);

/** Positional transforms, keyed by the name the generated table references. */
export const TRANSFORMS = { appSlug };

/**
 * Path variables whose values are canonically upper-case.
 *
 * `mitrex techniques t1059` and `mitrex cves cve-2021-44228` both returned 400
 * from the route's own format regex. Deliberately NOT ghsaId, osvId or
 * d3fendId: `GHSA-vcvr-r3j9-…` and `D3-NTA` are mixed-case, so upper-casing
 * them would break ids that work today.
 */
const UPPERCASE_IDS = new Set(['attackId', 'cveId']);

/**
 * Align a token sequence against one command's segments.
 * @returns {Record<string,string>|null} path values, or null if it does not fit
 */
function tryMatch(cmd, tokens) {
  const values = {};
  let t = 0;
  for (const seg of cmd.segs) {
    if (seg.word !== undefined) {
      if (tokens[t] !== seg.word) return null;
      t += 1;
    } else if (seg.catchAll) {
      const rest = tokens.slice(t);
      if (rest.length === 0) return null;
      values[seg.var] = rest.join('/');
      t = tokens.length;
    } else {
      if (t >= tokens.length) return null;
      values[seg.var] = tokens[t];
      t += 1;
    }
  }
  return t === tokens.length ? values : null;
}

/**
 * How many leading tokens of `tokens` a command's segments account for.
 * Ranks near-misses so the suggestion is the command the reader half-typed,
 * rather than every command sharing a first word.
 */
function align(cmd, tokens) {
  let n = 0;
  for (const seg of cmd.segs) {
    if (n >= tokens.length) break;
    if (seg.word !== undefined) {
      if (tokens[n] !== seg.word) break;
    }
    n += 1;
  }
  return n;
}

/**
 * Every flag any command accepts, with its type — the union across all 83.
 *
 * This exists to break a circle: the command must be known before its own flags
 * can be declared, yet the command is named by the positionals, and you cannot
 * tell a positional from a flag's VALUE without knowing that flag's type.
 * Verified safe: 46 distinct parameter names across the catalogue and not one
 * type conflict between commands, so a single table cannot mis-type anything.
 */
export const UNION_OPTIONS = (() => {
  const options = {
    json: { type: 'boolean' },
    'no-color': { type: 'boolean' },
    help: { type: 'boolean', short: 'h' },
    table: { type: 'boolean' },
    url: { type: 'boolean' },
    expand: { type: 'string' },
    timeout: { type: 'string' },
    base: { type: 'string' },
    query: { type: 'string', short: 'q' },
  };
  for (const cmd of COMMANDS) {
    for (const p of cmd.params) {
      options[p.name] ??= { type: p.type === 'boolean' ? 'boolean' : 'string' };
    }
  }
  return options;
})();

/**
 * The tokens that name a command.
 *
 * Two earlier attempts were both wrong in the same direction — they produced a
 * DIFFERENT command rather than an error:
 *   - `parseArgs({ strict: false })` with no table cannot know which flags take
 *     a value, so `cves --severity CRITICAL --limit 3` yielded the positionals
 *     ['cves','CRITICAL','3'].
 *   - "stop at the first '-'" dropped every positional written after a flag, so
 *     `techniques --json T1059` silently returned the 50-row LIST with exit 0,
 *     and `--` discarded the very positional it exists to protect.
 * Typing the union fixes both, and lets flags appear before, after or around
 * the command words the way people actually type them.
 */
export function commandTokens(argv) {
  const { positionals } = parseArgs({
    args: argv,
    options: UNION_OPTIONS,
    allowPositionals: true,
    strict: false,
  });
  return positionals;
}

/**
 * Find the command a token sequence names.
 *
 * `holes` is why this reports near-misses rather than just failing: 11 commands
 * have a parent or detail node that is not itself a route, so
 * `mitrex feed reports R123` is a reasonable guess at a URL that does not
 * exist. Listing the commands that DO start with those tokens explains the gap
 * instead of denying it.
 */
export function resolve(tokens) {
  for (const cmd of TREE) {
    const pathValues = tryMatch(cmd, tokens);
    if (pathValues) return { cmd, pathValues };
  }
  const near = TREE.map((c) => ({ usage: commandUsage(c), score: align(c, tokens) }))
    .filter((c) => c.score > 0)
    .sort((a, b) => b.score - a.score)
    .map((c) => c.usage);
  return { cmd: null, near };
}

/**
 * The catalogue's worked example, rewritten as the command that produces it.
 *
 * 81 of the 83 entries carry an example that already returns 200, and none of
 * them were ever shown — so help described flags in the abstract while the one
 * line a reader could paste sat unused in the table.
 */
export function exampleCommand(cmd) {
  if (!cmd.example) return null;
  const { path: pathValues, query } = seedValues(cmd.path, cmd.example);
  const words = [];
  for (const seg of cmd.path.split('/').filter(Boolean)) {
    const m = PLACEHOLDER.exec(seg);
    if (!m) words.push(seg);
    else words.push(...String(pathValues[m[2]] ?? '').split('/'));
  }
  const flags = [];
  for (const [key, value] of Object.entries(query)) {
    const param = cmd.params.find((pp) => pp.name === key);
    if (!param) continue;
    // Shown under the spelling that works everywhere, not the declared name.
    const flag = key === cmd.fulltext ? '-q' : `--${key}`;
    if (param.type === 'boolean') flags.push(flag);
    else flags.push(flag, /\s/.test(value) ? JSON.stringify(value) : value);
  }
  return ['mitrex', ...words, ...flags].join(' ');
}

/**
 * The full-text list command under a root, if there is one.
 *
 * `mitrex groups APT29` and `mitrex software mimikatz` both return
 * `400 Invalid attack_id format`, because the positional is an id and the user
 * typed a name. The answer is always the sibling list command with `-q`.
 */
export function searchSibling(root) {
  return TREE.find((c) => c.words[0] === root && c.positionals.length === 0 && c.fulltext) ?? null;
}

/** The human form of a command: `techniques <attackId> packages`. */
export function commandUsage(cmd) {
  return cmd.segs
    .map((s) => (s.word !== undefined ? s.word : `<${s.catchAll ? `...${s.var}` : s.var}>`))
    .join(' ');
}

/**
 * The parseArgs option table for one command.
 *
 * Built per command and never shared, because an unknown query parameter is
 * SILENTLY IGNORED by the routes: `--search` on an endpoint that calls it `q`
 * would return a cheerful unfiltered first page rather than an error. parseArgs
 * is strict by default, so declaring exactly this endpoint's parameters is what
 * turns that silent wrong answer into a usage error.
 */
export function optionsFor(cmd) {
  /* Built from RESERVED_FLAGS so the list the generator checks against IS the
     list declared here — two hand-kept copies would drift. `query` is added
     below, only for commands that accept full text. */
  const SHAPES = {
    json: { type: 'boolean' },
    expand: { type: 'string' },
    timeout: { type: 'string' },
    base: { type: 'string' },
    'no-color': { type: 'boolean' },
    help: { type: 'boolean', short: 'h' },
    table: { type: 'boolean' },
    url: { type: 'boolean' },
  };
  const options = {};
  for (const name of RESERVED_FLAGS) if (SHAPES[name]) options[name] = SHAPES[name];
  for (const p of cmd.params) {
    options[p.name] = { type: p.type === 'boolean' ? 'boolean' : 'string' };
  }
  // One spelling for full text, whatever this endpoint calls it underneath.
  if (cmd.fulltext) options.query = { type: 'string', short: 'q' };
  return options;
}

/** Every command whose closed vocabulary for `flag` accepts `value`. */
export function whoAccepts(flag, value) {
  const wanted = String(value).toLowerCase();
  return TREE.filter((c) =>
    c.params.some((p) => p.name === flag && p.values?.some((v) => v.toLowerCase() === wanted)),
  ).map((c) => commandUsage(c));
}

/**
 * Match a closed-vocabulary value case-insensitively and return the canonical
 * spelling.
 *
 * `--severity high` used to be rejected outright, and then the error helpfully
 * pointed at `capec, advisories, ghsa` — three other commands — because the
 * cross-command lookup ran before anyone checked whether THIS command's own
 * vocabulary had it in a different case. Nobody types CRITICAL.
 */
export function canonicaliseValues(cmd, flags) {
  const out = { ...flags };
  for (const p of cmd.params) {
    if (!p.values || out[p.name] === undefined) continue;
    const wanted = String(out[p.name]).toLowerCase();
    const hit = p.values.find((v) => v.toLowerCase() === wanted);
    if (hit !== undefined) out[p.name] = hit;
  }
  return out;
}

/**
 * Validate parsed flags against the command's catalogue entry.
 * @returns {string[]} human-readable errors, empty when the call is good
 */
export function validate(cmd, flags, pathValues) {
  const errors = [];
  for (const [name, value] of Object.entries(pathValues ?? {})) {
    if (String(value).trim() === '') errors.push(`<${name}> cannot be empty`);
  }
  for (const p of cmd.params) {
    const raw = p.name === cmd.fulltext && flags.query !== undefined ? flags.query : flags[p.name];
    if (raw === undefined) continue;
    if (typeof raw === 'string' && raw.trim() === '') {
      errors.push(`--${p.name === cmd.fulltext ? 'query' : p.name} was given no value`);
      continue;
    }
    if (p.values && !p.values.includes(String(raw))) {
      const elsewhere = whoAccepts(p.name, raw).filter((u) => u !== commandUsage(cmd));
      let msg = `--${p.name} must be one of: ${p.values.join(', ')} (got "${raw}")`;
      // The same flag name carries incompatible vocabularies across commands —
      // --severity is CRITICAL|HIGH|… on cves but 'Very High' on capec. Saying
      // where the typed value IS valid turns a dead end into a redirection.
      if (elsewhere.length) msg += `\n  "${raw}" is valid for: ${elsewhere.slice(0, 3).join(', ')}`;
      errors.push(msg);
    }
    if (p.type === 'number' && raw !== undefined && !Number.isFinite(Number(raw))) {
      errors.push(`--${p.name} must be a number (got "${raw}")`);
    }
  }
  for (const p of cmd.params) {
    if (p.required && flags[p.name] === undefined && !(p.name === cmd.fulltext && flags.query)) {
      /* Name the spelling that WORKS. The full-text parameter is `q` on some
         endpoints and `search` on others; `-q`/`--query` is the only spelling
         accepted on all of them, so "--q is required" would send a reader to a
         flag the parser rejects. */
      errors.push(p.name === cmd.fulltext ? '-q (--query) is required' : `--${p.name} is required`);
    }
  }
  return errors;
}

/**
 * Build the relative request path for a resolved command and its flags.
 * Reuses composePath() from src/lib/api-request.mjs — the same encoder the
 * /open-apis Run button has used since the endpoint modal shipped.
 */
export function buildPath(cmd, pathValues, flags) {
  const values = { ...pathValues };
  if (cmd.transform) {
    for (const key of Object.keys(values)) values[key] = TRANSFORMS[cmd.transform](values[key]);
  }
  for (const key of Object.keys(values)) {
    if (UPPERCASE_IDS.has(key)) values[key] = String(values[key]).toUpperCase();
  }
  const pairs = [];
  for (const p of cmd.params) {
    const v = p.name === cmd.fulltext && flags.query !== undefined ? flags.query : flags[p.name];
    if (v === undefined || v === false) continue;
    pairs.push([p.name, v === true ? '1' : String(v)]);
  }
  return composePath(cmd.path, values, pairs);
}
