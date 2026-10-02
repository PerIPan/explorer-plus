#!/usr/bin/env node
/**
 * mitrex — the mitre-explorer.org REST API as a command line.
 *
 * Every command here is generated from the same catalogue that draws
 * /open-apis, so the CLI cannot describe an endpoint the site does not have.
 * Read-only by construction: the catalogue's GET entries are the whole surface.
 *
 * It holds no credentials, because the API needs none.
 */
import { parseArgs } from 'node:util';
import { readFileSync } from 'node:fs';
import { styleText } from 'node:util';
import { BASE_URL, ROOTS } from './lib/commands.generated.mjs';
import {
  TREE,
  resolve,
  commandUsage,
  optionsFor,
  validate,
  buildPath,
  commandTokens,
  canonicaliseValues,
  searchSibling,
  exampleCommand,
} from './lib/dispatch.mjs';
import { renderDetail, renderList, sanitize, escapeForTerminal } from './lib/format.mjs';
import { request } from './lib/http.mjs';
import { completionScript, SHELLS } from './lib/completion.mjs';

const { version } = JSON.parse(
  readFileSync(new URL('./package.json', import.meta.url), 'utf8'),
);

/* `mitrex techniques T1059 | head -3` closes stdout while we are still writing.
   Without this the process dies on an unhandled EPIPE and prints a stack trace
   over the output the reader asked for. A closed pipe is a normal exit. */
process.stdout.on('error', (e) => {
  /* A closed pipe is a normal exit. Any other stdout error cannot be reported
     ON stdout, and throwing from inside an 'error' listener just becomes an
     uncaught exception, so say it on stderr and leave with a failure code. */
  if (e?.code === 'EPIPE') process.exit(0);
  process.stderr.write(`stdout: ${e?.code ?? e?.message ?? e}\n`);
  process.exit(1);
});

const argv = process.argv.slice(2);
/* Colour is off unless stdout is a terminal; styleText already honours that,
   and NO_COLOR is the convention for turning it off when it is. */
const COLOR = !(process.env.NO_COLOR || argv.includes('--no-color'));

/**
 * Sanitise, THEN style. Order is the whole point.
 *
 * stderr is where HTTP error bodies and the user's own argv get echoed, and
 * stdout had a sanitiser while stderr had none — so a response body or a pasted
 * argument could carry OSC 52 (a clipboard write) or a screen clear straight to
 * the terminal. But sanitising AFTER styling strips the ESC out of our own
 * colour codes and leaves `[31m` as literal text, which is exactly what
 * happened: every error printed `[31mNo command "x".[39m`. The text is cleaned
 * first and the escapes added last, where nothing can remove them.
 *
 * `{ stream }` matters too: styleText defaults to deciding by process.stdout,
 * so without it `mitrex … 2>log` wrote colour codes into the log file whenever
 * stdout happened to be a terminal.
 */
const safe = (s) => sanitize(String(s));
const paint = (style, s, stream = process.stdout) =>
  COLOR ? styleText(style, safe(s), { stream }) : safe(s);
const err = (s) => process.stderr.write(`${s}\n`);
const out = (s) => process.stdout.write(`${s}\n`);

function die(message, code = 2, hint = null) {
  err(paint('red', message, process.stderr));
  if (hint) err(paint('gray', hint, process.stderr));
  process.exit(code);
}

/**
 * A closed vocabulary, abbreviated when listing it all would be noise.
 *
 * `--sector` has twelve values and ran the help line to 150 characters. Three
 * plus a count tells a reader the shape; `--help` on the command, or a rejected
 * value, prints the full list.
 */
function vocab(values) {
  return values.length <= 5 ? values.join('|') : `${values.slice(0, 3).join('|')}|…+${values.length - 3}`;
}

/** Known flag spellings for a command, with the full-text one named once. */
function flagList(cmd) {
  const out = cmd.fulltext ? ['-q, --query <text>'] : [];
  for (const p of cmd.params) {
    // `--search`/`--q` are reached through -q/--query, which is the only
    // spelling that works on all 27 endpoints declaring one or the other.
    if (p.name === cmd.fulltext) continue;
    out.push(p.values ? `--${p.name} <${vocab(p.values)}>` : `--${p.name}`);
  }
  return out;
}

/** Levenshtein, bounded — only ever run over 30 roots or a dozen flag names. */
function distance(a, b) {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 0; j <= b.length; j += 1) d[0][j] = j;
  for (let i = 1; i <= a.length; i += 1) {
    for (let j = 1; j <= b.length; j += 1) {
      d[i][j] = Math.min(
        d[i - 1][j] + 1,
        d[i][j - 1] + 1,
        d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
    }
  }
  return d[a.length][b.length];
}

/** The closest few candidates to `word`, or none if nothing is close. */
function closest(word, candidates, limit = 3) {
  // distance() allocates O(word x candidate); no real command name is long.
  if (word.length > 64) return [];
  const max = word.length <= 4 ? 1 : word.length <= 7 ? 2 : 3;
  return candidates
    .map((c) => ({ c, d: distance(word.toLowerCase(), c.toLowerCase()) }))
    .filter((x) => x.d <= max)
    .sort((a, b) => a.d - b.d)
    .slice(0, limit)
    .map((x) => x.c);
}

/**
 * Words a reader could reasonably type that are not the command's name.
 *
 * `malware` is the one that matters: the sidebar labels this resource Malware
 * while the URL, the MCP tools and therefore the CLI all say `software`. That
 * is the house convention — labels say Malware, identifiers say software — so
 * the command keeps the identifier and the error does the translating.
 */
const ALIASES = { malware: 'software', tool: 'software', tools: 'software', cve: 'cves', technique: 'techniques', group: 'groups', actor: 'external-actors', actors: 'external-actors', advisory: 'advisories', ioc: 'feed iocs', iocs: 'feed iocs', sigma: 'feed sigma', atomic: 'feed atomic', report: 'feed reports', reports: 'feed reports' };

function overview() {
  out(`${paint('bold', 'mitrex')} ${paint('gray', `v${version}`)} — mitre-explorer.org from the command line`);
  out('');
  out(`  ${paint('cyan', 'mitrex <command> [args] [--flags]')}`);
  out('');
  out(`${TREE.length} commands over ${ROOTS.length} resources. No key, no account, read-only.`);
  out('');
  out(paint('bold', 'Resources'));
  /* Grouped by the first word of the command, because that is what a reader is
     about to type. The catalogue's own nine groups are a website taxonomy. */
  const cols = 4;
  for (let i = 0; i < ROOTS.length; i += cols) {
    out(`  ${ROOTS.slice(i, i + cols).map((r) => r.padEnd(18)).join('')}`.trimEnd());
  }
  out('');
  out(paint('bold', 'Examples'));
  out(paint('gray', '  mitrex techniques T1059'));
  out(paint('gray', '  mitrex groups --search lazarus'));
  out(paint('gray', '  mitrex cves --severity CRITICAL --limit 5 | jq \'.data[].cveId\''));
  out('');
  out(`${paint('cyan', 'mitrex help <resource>')}  commands for one resource`);
  out(`${paint('cyan', 'mitrex ls')}               every command, one per line`);
}

function helpFor(root) {
  const cmds = TREE.filter((c) => c.words[0] === root).sort((a, b) =>
    commandUsage(a).localeCompare(commandUsage(b)),
  );
  if (cmds.length === 0) {
    const guess = closest(root, ROOTS);
    die(`No resource "${root}".`, 2, guess.length ? `Did you mean: ${guess.join(', ')}?` : `Try: mitrex ls`);
  }
  const width = Math.max(40, process.stdout.columns || 100);
  for (const c of cmds) {
    out(paint('cyan', commandUsage(c)));
    out(`  ${c.summary}`);
    const example = exampleCommand(c);
    if (example) out(`  ${paint('gray', 'e.g.')} ${example}`);
    /* One flag per line, with the note the catalogue already carries. 134 of
       the 219 parameters have a note — the `--since` format, the "3-character
       minimum" that produces an otherwise unexplained 400 — and a single
       joined line ran to 343 characters and soft-wrapped unindented. */
    const spellings = flagList(c);
    const names = c.fulltext ? [c.fulltext, ...c.params.filter((pp) => pp.name !== c.fulltext).map((pp) => pp.name)] : c.params.map((pp) => pp.name);
    const pad = Math.min(34, Math.max(...spellings.map((f) => f.length), 4));
    spellings.forEach((spelling, i) => {
      const note = c.params.find((pp) => pp.name === names[i])?.note;
      if (!note) return out(paint('gray', `  ${spelling}`));
      const head = `  ${spelling.padEnd(pad)}  `;
      const wrapped = note.length + head.length <= width ? note : note.slice(0, width - head.length - 1) + '…';
      out(paint('gray', `${head}${wrapped}`));
    });
    out('');
  }
}

async function main() {
  /* POSITION, not membership. `version` is a documented query parameter on 7
     commands (/cves, /applications, /ghsa/{id}, /packages, …), so
     `argv.includes('--version')` made `mitrex applications "Red Hat" "OpenShift 4"
     --version 4.12` print the CLI's own version and exit 0 without ever making
     the request — a silent wrong answer, which is the failure class the strict
     flag parsing exists to prevent. */
  /* Length-limited as well as position-limited. `version` is a documented query
     parameter on 7 commands (/cves, /applications, /ghsa/{id}, /packages, …), so
     an argv-wide membership test made `mitrex cves --app log4j --version 2.14`
     print the CLI's own version and exit 0 without making the request — a
     silent wrong answer, the failure class the strict parsing exists to stop. */
  if (argv.length === 1 && ['--version', '-V', 'version'].includes(argv[0])) return out(version);
  if (argv.length === 0) return overview();
  if (argv[0] === 'ls') {
    /* usage<TAB>summary: tab-separated so `mitrex ls | column -t -s$'\t'` and
       `grep` both work, and so the summary the catalogue already has is not
       thrown away. */
    const rows = TREE.map((c) => [commandUsage(c), c.summary]).sort((a, b) => a[0].localeCompare(b[0]));
    return rows.forEach(([usage, summary]) => out(`${usage}\t${summary}`));
  }
  if (argv[0] === 'completion') {
    const shell = argv[1];
    if (!SHELLS.includes(shell)) {
      return die(`mitrex completion <${SHELLS.join('|')}>`, 2, 'e.g. eval "$(mitrex completion zsh)"');
    }
    return out(completionScript(shell));
  }
  if (argv[0] === 'help') return argv[1] ? helpFor(ALIASES[argv[1]]?.split(' ')[0] ?? argv[1]) : overview();

  /* -h/--help anywhere, because that is where people put it. A bare resource
     word is also a help request: typing `frameworks` used to exit 2 with "Did
     you mean: frameworks?" — the fuzzy matcher firing on an exact root. */
  const tokens = commandTokens(argv);
  const wantsHelp = argv.includes('--help') || argv.includes('-h');
  if (wantsHelp && tokens.length === 0) return overview();
  if (wantsHelp && ROOTS.includes(tokens[0])) return helpFor(tokens[0]);
  if (argv.length === 1 && ROOTS.includes(argv[0]) && !resolve([argv[0]]).cmd) return helpFor(argv[0]);

  if (tokens.length === 0) {
    return die(`No command given.`, 2, 'Try "mitrex" for the resources, or "mitrex ls" for every command.');
  }
  const { cmd, pathValues, near } = resolve(tokens);
  if (!cmd) {
    const typed = tokens.join(' ').slice(0, 120);
    const alias = ALIASES[tokens[0]?.toLowerCase()];
    // Never fuzzy-match a word that IS a root; it only ever suggested itself.
    const fuzzy = alias || ROOTS.includes(tokens[0]) ? [] : closest(tokens[0] ?? '', ROOTS);
    const lines = [];
    const [root, ...rest] = tokens;

    /* `mitrex search lazarus` — the root is right, the term just needs a flag.
       Only offered when the root has NO command that takes a positional at all:
       that is what separates `search` (query-only, so a bare word can only be a
       search term) from `techniques` (where a bare word is an id, and the real
       answer is the --expand hint below). */
    const rootTakesPositional = TREE.some((c) => c.words[0] === root && c.positionals.length > 0);
    if (searchSibling(root) && rest.length && !rootTakesPositional) {
      lines.push(`Search terms go in a flag: mitrex ${root} -q ${rest.join(' ')}`);
    }

    /* `mitrex techniques T1059 groups` — `groups` is a FIELD of the detail
       response, not a sub-resource, so --expand is the answer. */
    if (rest.length >= 2 && resolve(tokens.slice(0, -1)).cmd) {
      const field = tokens[tokens.length - 1];
      lines.push(`If "${field}" is a field, try: mitrex ${tokens.slice(0, -1).join(' ')} --expand ${field}`);
    }

    if (alias) lines.push(`This site calls it "${alias}" — try: mitrex ${[alias, ...tokens.slice(1)].join(' ')}`);
    if (fuzzy.length) lines.push(`Did you mean: ${fuzzy.join(', ')}?`);
    if (near?.length) lines.push(`Closest:\n${near.slice(0, 4).map((u) => `  mitrex ${u}`).join('\n')}`);
    if (!lines.length) lines.push('Try "mitrex ls" for every command.');
    return die(`No command "${typed}".`, 2, lines.join('\n'));
  }

  let parsed;
  try {
    parsed = parseArgs({ args: argv, options: optionsFor(cmd), allowPositionals: true });
  } catch (e) {
    /* parseArgs is strict, which is what stops a mistyped flag becoming a
       silent unfiltered result: the ROUTES ignore unknown query params, so
       `--search` on an endpoint that calls it `q` would otherwise return a
       cheerful first page rather than an error.
       Only an UNKNOWN option gets rewritten. Relabelling every failure as
       "Unknown flag" produced self-contradictory output — typing
       `--include_deprecated=false` said the flag was unknown, suggested the
       same flag, and then listed it as accepted. parseArgs' own message for
       "does not take an argument" and "argument missing" is the accurate one. */
    const names = flagList(cmd).map((f) => /--[a-z0-9_-]+/.exec(f)?.[0] ?? f);
    const accepts = `${commandUsage(cmd)} accepts: ${names.join(' ') || '(no flags)'}`;
    if (e?.code !== 'ERR_PARSE_ARGS_UNKNOWN_OPTION') return die(e.message, 2, accepts);
    const bad = /'(-{1,2}[^'\s]+)/.exec(e.message)?.[1] ?? '';
    const guess = closest(bad.replace(/^-+/, ''), names.map((n) => n.replace(/^--/, '')));
    const hint = [guess.length ? `Did you mean --${guess[0]}?` : null, accepts]
      .filter(Boolean)
      .join('\n');
    return die(bad ? `Unknown flag ${bad}` : e.message, 2, hint);
  }

  const flags = parsed.values;
  if (flags.help) return helpFor(cmd.words[0]);

  const flags2 = canonicaliseValues(cmd, flags);
  const errors = validate(cmd, flags2, pathValues);
  if (errors.length) return die(errors.join('\n'), 2, `mitrex ${commandUsage(cmd)} --help`);

  const relPath = buildPath(cmd, pathValues, flags2);
  const baseUrl = flags.base ?? BASE_URL;
  if (flags.base) {
    /* Validated once, up front. Unvalidated, a malformed base threw a SECOND
       time inside http.mjs's own error handler and surfaced as a bare
       "Invalid URL" with no mention of the flag that caused it. */
    let parsed;
    try {
      parsed = new URL(baseUrl);
    } catch {
      return die(`--base is not a URL: ${baseUrl}`);
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return die(`--base must be http or https (got ${parsed.protocol})`);
    }
  }
  const timeoutMs = flags.timeout ? Number(flags.timeout) : 30000;
  /* Above 2^31-1 Node prints TimeoutOverflowWarning and aborts after 1ms, so a
     huge --timeout behaved as the shortest possible one. */
  const MAX_TIMEOUT = 2147483647;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) return die(`--timeout must be a positive number of milliseconds.`);
  if (timeoutMs > MAX_TIMEOUT) return die(`--timeout must be at most ${MAX_TIMEOUT} ms.`);

  if (flags.url) return out(`${baseUrl}${relPath}`);

  let res;
  try {
    res = await request(baseUrl, relPath, { timeoutMs, version });
  } catch (e) {
    return die(e.message, e.exitCode ?? 3, e.hint);
  }

  if (!res.ok) {
    const code = res.json?.code ? ` [${res.json.code}]` : '';
    /* `error` is not guaranteed to be a string — an object printed as
       "[object Object]", which tells the reader nothing. */
    const raw = res.json?.error ?? res.text.slice(0, 300);
    const detail = typeof raw === 'string' ? raw : JSON.stringify(raw);
    err(paint('red', `HTTP ${res.status}${code} ${detail}`, process.stderr));
    if (res.retryAfter) err(paint('gray', `Retry-After: ${res.retryAfter}`, process.stderr));
    /* A name typed where an id goes is the single most common way to get a 400
       here — `groups APT29`, `software mimikatz`. The sibling list command with
       -q is what the reader wanted. */
    if (res.status === 400 || res.status === 404) {
      const idPositional = cmd.positionals.find((pp) => /^(attackId|cveId)$/.test(pp.name));
      const sibling = idPositional ? searchSibling(cmd.words[0]) : null;
      if (sibling) {
        const typed = Object.values(pathValues)[0];
        err(paint('gray', `Looking for a name rather than an id? mitrex ${cmd.words[0]} -q ${typed}`, process.stderr));
      }
    }
    err(paint('gray', res.url, process.stderr));
    /* 4 means "try again later", distinct from 1 ("your request was wrong") and
       from an internal failure. A script retrying every non-zero exit would
       otherwise hammer a 404 and give up on a 503. */
    process.exit(res.status === 429 || res.status >= 500 ? 4 : 1);
  }

  /* A captive portal, a proxy error page or a 204 all arrive as a 200 whose body
     is not JSON. `res.json` is then null and the piped path printed the literal
     string `null` with exit 0 — indistinguishable from a real JSON null. */
  if (res.json === null && res.text.trim() !== 'null') {
    return die(
      `Expected JSON but the endpoint returned ${res.text.trim() === '' ? 'an empty body' : 'something else'}.`,
      1,
      res.url,
    );
  }

  const body = res.json;
  /* Piped output is the API's bytes, unaltered, so jq and scripts see exactly
     what curl would. The terminal renderer is the only thing that rewrites. */
  const color = !(process.env.NO_COLOR || flags['no-color']);
  /* `--expand` is a projection the caller explicitly asked for, so honour it on
     the piped path too by narrowing the JSON to that field. It used to be
     silently dropped, and `--expand groups | head` printed the whole document. */
  const projected =
    flags.expand && body && typeof body === 'object' && Array.isArray(body[flags.expand])
      ? body[flags.expand]
      : body;
  const reIndented = JSON.stringify(projected, null, 2);
  /* Piped output is the API's bytes, unaltered, so jq and scripts see exactly
     what curl would. `--json` ON A TERMINAL is the one case that still needs
     escaping: JSON.stringify escapes C0 but leaves U+007F-U+009F raw, and
     U+009B/U+009D are CSI/OSC to a UTF-8 terminal — a sequence with no ESC. */
  if (!process.stdout.isTTY && !flags.table) {
    /* The API's own bytes, not a re-serialisation. The README promises byte-for
       byte and `JSON.stringify(body, null, 2)` is not that — it re-indents, and
       on /techniques/T1059 turned 65,588 bytes into 72,136. A projection has no
       original bytes to preserve, so that one is serialised. */
    if (projected !== body) return out(reIndented);
    process.stdout.write(res.text.endsWith('\n') ? res.text : `${res.text}\n`);
    return undefined;
  }
  if (flags.json) return out(escapeForTerminal(reIndented));

  /* `??` would keep a 0 here: a pty with no window size — `script`, CI, many
     containers — reports columns as 0, not undefined. A 0 width made every
     cell budget negative, and `slice(0, negative)` counts from the END, so
     short fields rendered as a lone ellipsis while a long description printed
     almost in full. Hence `||`, and a floor narrower than any real terminal. */
  const width = Math.max(40, process.stdout.columns || 100);
  /* IOC values are attacker-controlled by definition, so they are defanged for
     the terminal — and only there. --json keeps them exact. */
  const defanged = cmd.path.startsWith('/feed/iocs');
  if (body && Array.isArray(body.data)) return out(renderList(body.data, body.pagination, { width, defanged, color }));
  if (Array.isArray(body)) return out(renderList(body, null, { width, defanged, color }));
  if (body && typeof body === 'object') {
    /* Some routes wrap a single object in the same `data` envelope the lists
       use. The list branch unwraps its array; this one did not, so the whole
       response rendered as one nested object — i.e. field names and no values. */
    const subject =
      body.data && typeof body.data === 'object' && !Array.isArray(body.data) ? body.data : body;
    return out(renderDetail(subject, { expand: flags.expand, width, defanged, color }));
  }
  /* A valid-JSON body that is neither object nor array — or a 200 that was not
     JSON at all, where `body` is null. Sanitised because no route shape
     guarantees what lands here, and said plainly rather than printing "null". */
  return out(safe(String(body)));
}

main().catch((e) => die(`Unexpected: ${e?.message ?? e}`, 1));
