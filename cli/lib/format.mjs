/**
 * Rendering a response for a human — and ONLY for a human.
 *
 * Everything in here runs when stdout is a terminal. Piped output never reaches
 * this module: it is `JSON.stringify` of exactly what the API returned, so a
 * script sees the data unaltered and `jq` behaves.
 *
 * That split is the point. The API serves third-party text — IOC values from
 * OTX and ThreatFox, advisory prose, Atomic Red Team command strings — none of
 * which this project authored. Writing such bytes straight to a TTY is an
 * injection surface: an ESC in a description repaints the screen, rewrites the
 * prompt, or in some terminals asks the emulator to send text back. So the
 * TERMINAL renderer sanitises, and the machine-readable path stays faithful.
 */
import { styleText } from 'node:util';

/**
 * Strip everything a terminal would treat as an instruction rather than text:
 * C0 controls (keeping tab), DEL, and the C1 range. ESC is the one that matters
 * — no ESC, no CSI/OSC/DCS sequence can begin.
 */
export function sanitize(value) {
  return (
    String(value)
      // eslint-disable-next-line no-control-regex
      .replace(/[\u0000-\u0008\u000B-\u001F\u007F-\u009F]/g, '')
      /* Bidi overrides and isolates. Not cosmetic here: this tool exists to
         display adversary-chosen strings that an analyst then pastes into a
         blocklist, and these reorder what is rendered relative to what is
         stored — so what they read need not be what they copy. Replaced with
         U+FFFD rather than deleted, so tampering is visible instead of silent. */
      .replace(/[\u202A-\u202E\u2066-\u2069\u061C\u200E\u200F]/g, '\uFFFD')
  );
}

/**
 * Printed width, not code-unit count.
 *
 * CJK, fullwidth forms and emoji occupy two terminal cells, so `.length`
 * under-measures them and every column after a CJK cell drifted left. Combining
 * marks occupy none.
 */
export function displayWidth(text) {
  let n = 0;
  for (const ch of String(text)) {
    const cp = ch.codePointAt(0);
    if (cp >= 0x0300 && cp <= 0x036f) continue; // combining diacritics
    const wide =
      (cp >= 0x1100 && cp <= 0x115f) ||
      (cp >= 0x2e80 && cp <= 0xa4cf) ||
      (cp >= 0xac00 && cp <= 0xd7a3) ||
      (cp >= 0xf900 && cp <= 0xfaff) ||
      (cp >= 0xfe30 && cp <= 0xfe6f) ||
      (cp >= 0xff00 && cp <= 0xff60) ||
      (cp >= 0xffe0 && cp <= 0xffe6) ||
      (cp >= 0x1f300 && cp <= 0x1faff);
    n += wide ? 2 : 1;
  }
  return n;
}

/** Pad to a printed width, so a CJK or emoji cell does not shift its neighbours. */
function padTo(text, width) {
  return text + ' '.repeat(Math.max(0, width - displayWidth(text)));
}

/**
 * Neuter a URL or bare host so pasting the terminal's output somewhere cannot
 * navigate to it. Applied only to IOC endpoints, whose values ARE the hostile
 * input, and only in terminal output — the JSON path keeps them exact because a
 * detection pipeline needs the real string.
 */
export function defang(value) {
  const s = String(value);
  /* Only ever rewrite something that looks like a locator. Without this guard a
     key-or-shape-driven caller would turn a CVSS score of 9.8 into 9[.]8. */
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s) && !/[a-z]\.[a-z]{2}/i.test(s) && !/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) {
    return s;
  }
  return s.replace(/^http(s?):\/\//i, 'hxxp$1://').replace(/\./g, '[.]');
}

/** IOC `type` values whose `value` field is an attacker-chosen locator. */
const IOC_TYPES = new Set(['url', 'uri', 'domain', 'hostname', 'host', 'ip', 'ipv4', 'ipv6', 'email']);
/** Keys that only ever hold third-party locators, on any endpoint. */
const IOC_KEYS = new Set(['value', 'indicator', 'ioc', 'source_ref']);

/**
 * Does this row carry an indicator?
 *
 * Shape, not path. The original gate was `path.startsWith('/feed/iocs')`, and
 * `/feed/intelligence/{attackId}` returns rows from the same `ioc_entries`
 * table — so live C2 URLs rendered clickable while the README promised they
 * would not. Any future endpoint that surfaces the same rows is covered by
 * this and would not have been by a longer allowlist.
 */
export function isIocRow(row) {
  return Boolean(
    row && typeof row === 'object' && IOC_TYPES.has(String(row.type).toLowerCase()),
  );
}

/**
 * Escape the control codepoints `JSON.stringify` leaves alone.
 *
 * `JSON.stringify` escapes C0 (so ESC becomes `\u001b`) but passes U+007F and
 * the whole C1 block U+0080–U+009F through as raw bytes. In a UTF-8
 * xterm-class terminal those codepoints ARE controls: U+009B is CSI and
 * U+009D is OSC, so a payload needs no ESC byte at all to open a sequence.
 * Terminal-dependent — VTE and iTerm2 largely ignore 8-bit C1 in UTF-8 mode,
 * xterm and others do not — which makes it worth closing rather than arguing
 * about.
 *
 * The result is still the same JSON VALUE, so this is only ever applied when
 * the destination is a terminal. The piped path stays byte-for-byte, which is
 * the promise the README actually makes.
 */
export function escapeForTerminal(json) {
  return json.replace(/[\u007F-\u009F]/g, (c) => `\\u${c.codePointAt(0).toString(16).padStart(4, '0')}`);
}

/** Soft-wrap a footer to the terminal width; footers used to wrap mid-word. */
function wrap(text, width) {
  const limit = Math.max(20, Math.floor(width));
  const lines = [];
  let line = '';
  const push = () => {
    if (line) lines.push(line);
    line = '';
  };
  for (const word of String(text).split(' ')) {
    /* A token with no spaces in it cannot be wrapped between words, so it is
       hard-broken. Without this a 64-character hash, a base64 blob or a long
       URL stayed on one line and overflowed the terminal however narrow it
       was — wrapping by spaces alone silently does nothing to them. */
    if (word.length > limit) {
      push();
      for (const chunk of [...word].reduce((acc, ch) => {
        if (acc.length === 0 || acc[acc.length - 1].length >= limit) acc.push(ch);
        else acc[acc.length - 1] += ch;
        return acc;
      }, [])) {
        lines.push(chunk);
      }
      continue;
    }
    if (line && `${line} ${word}`.length > limit) push();
    line = line ? `${line} ${word}` : word;
  }
  push();
  return lines.join('\n');
}

const SCALAR = new Set(['string', 'number', 'boolean']);
const isScalar = (v) => v === null || SCALAR.has(typeof v);

/**
 * A response's own field name, made safe to print.
 *
 * Keys never went through `cell()`, so they were the one place a control byte
 * could still reach the terminal on the human path — and the only place a
 * newline could forge a whole output line, because `cell()` collapses
 * whitespace in values but nothing collapsed it in keys. No endpoint returns
 * attacker-chosen keys today; the first one that returns a map keyed by
 * upstream data (a parsed Sigma rule, an OSV `database_specific` blob) would.
 */
const label = (k) => sanitize(k).replace(/\s+/g, ' ');

function cell(value, { width, defanged }) {
  if (value === null || value === undefined) return '—';
  let s = sanitize(value);
  if (defanged) s = defang(s);
  s = s.replace(/\s+/g, ' ').trim();
  /* A width of 0 or less would make `slice(0, width - 1)` count from the end of
     the string and return the wrong text entirely, so the budget is clamped
     here as well as at the call site. */
  if (s === '') return '—';
  const budget = Math.max(4, Math.floor(width));
  if (displayWidth(s) <= budget) return s;
  /* By code point and by PRINTED width: slicing by code unit splits a surrogate
     pair into a lone half that encodes to U+FFFD, and counting by code unit
     lets a CJK cell overflow its column by its own length again. */
  let acc = '';
  let used = 0;
  for (const ch of s) {
    const w = displayWidth(ch);
    if (used + w > budget - 1) break;
    acc += ch;
    used += w;
  }
  return `${acc}…`;
}

/**
 * Styling is a parameter, not a module-level decision.
 *
 * `--no-color` was honoured by the help and error text but not here — and this
 * module is only ever reached when stdout IS a terminal, so the flag failed on
 * every case it exists for. Threading it also decouples the tests from
 * FORCE_COLOR, which otherwise made them pass only because `node --test` pipes
 * the child's stdout.
 */
function styler(color) {
  const paint = (style) => (s) => (color ? styleText(style, s) : s);
  return { dim: paint('gray'), bold: paint('bold'), accent: paint('cyan'), red: paint('red') };
}

/**
 * Which columns a table shows, in priority order.
 *
 * The API returns rows of thirty fields and a terminal fits about six, so the
 * naive "first six keys" lands on `id`, `stixId`, `url` and two booleans while
 * truncating the name — the one column a reader scans. Identity and label come
 * first, boilerplate goes last, and `--json` is always there for everything.
 */
const ID_KEYS = ['attackId', 'cveId', 'ghsaId', 'osvId', 'scfId', 'd3fendId', 'capecId', 'controlId', 'subcategoryId', 'engageId', 'key', 'slug', 'ecosystem', 'vendor'];
const LABEL_KEYS = ['name', 'title', 'product', 'package', 'label', 'domain'];
/** Long prose, opaque identifiers and audit stamps: real data, poor columns. */
const DEMOTED = ['description', 'summary', 'detection', 'url', 'stixId', 'id', 'stixCreated', 'stixModified', 'created_at', 'updated_at', 'createdAt', 'updatedAt'];

function pickColumns(rows, limit = 6) {
  const row = rows[0];
  const scalars = Object.keys(row).filter((k) => isScalar(row[k]));
  void 0;
  /* A column holding the same value in every row carries no information — on a
     list of live ATT&CK groups, `isRevoked` is false all the way down. It still
     beats nothing, so it is ranked last rather than dropped. */
  /* Only consulted when there are more fields than slots. Demoting a column
     whose value never varies is a real improvement — `isRevoked` is false all
     the way down a list of live groups — but it makes the column SET depend on
     the page, so `--limit 4` and `--limit 40` could disagree. Restricting it to
     the case where something has to be dropped keeps the order stable whenever
     everything fits. */
  const mustChoose = scalars.length > limit;
  const constant = (k) => mustChoose && rows.length > 1 && rows.every((r) => r[k] === row[k]);
  const rank = (k) => {
    if (ID_KEYS.includes(k)) return 0;
    if (LABEL_KEYS.includes(k)) return 1;
    if (constant(k)) return 5;
    if (DEMOTED.includes(k)) return 4;
    // A lone boolean rarely earns a column against a named field.
    if (typeof row[k] === 'boolean') return 3;
    return 2;
  };
  return scalars
    .map((k, i) => ({ k, r: rank(k), i }))
    .sort((a, b) => a.r - b.r || a.i - b.i)
    .slice(0, limit)
    .map((x) => x.k);
}

/**
 * A list response as a table.
 *
 * Columns are the first row's scalar fields, capped at six: a terminal is 80-ish
 * columns and the API returns rows with thirty fields. `--json` is the way to
 * see all of them, and the footer says so rather than leaving it a mystery.
 */
export function renderList(rows, pagination, { width = 100, defanged = false, color = true } = {}) {
  const { dim, accent } = styler(color);
  if (rows.length === 0) return dim('No rows matched.');
  /* A list endpoint is expected to return objects, but `mitrex.mjs` routes any
     bare array here and nothing promises its shape. An array of strings used to
     render as a table with columns 0..5, one character per cell; an array
     containing null threw and surfaced as "Unexpected:". */
  if (!rows.every((r) => r && typeof r === 'object' && !Array.isArray(r))) {
    return escapeForTerminal(JSON.stringify(rows, null, 2));
  }
  const keys = pickColumns(rows);
  if (keys.length === 0) return escapeForTerminal(JSON.stringify(rows, null, 2));

  /* Natural width first, then take the shortfall off the right-hand columns and
     drop trailing columns rather than starve every column equally. An equal
     split cut `name` to `AI Agent Clic…` while handing 14 characters each to
     `description` and `url`, and gave a 40-character hash the same room as a
     4-character `type` — so the one column a reader came for was the one they
     could not read. */
  const natural = keys.map((k) =>
    Math.min(
      60,
      Math.max(
        displayWidth(k),
        ...rows.map((r) =>
          displayWidth(
            String(r[k] ?? '—')
              .replace(/\s+/g, ' ')
              .trim() || '—',
          ),
        ),
      ),
    ),
  );

  const shown = [...keys];
  const widths = [...natural];
  const GAP = 2;
  const total = () => widths.reduce((a, b) => a + b, 0) + GAP * (widths.length - 1);
  while (total() > width && widths.length > 1) {
    const last = widths.length - 1;
    const over = total() - width;
    if (widths[last] - over >= 8) {
      widths[last] -= over;
      break;
    }
    // Starving it below 8 would make it unreadable, so drop it instead.
    widths.pop();
    shown.pop();
  }
  if (widths.length === 1) widths[0] = Math.max(8, Math.min(widths[0], width));
  const dropped = keys.length - shown.length;
  keys.length = 0;
  keys.push(...shown);

  const line = (cells) => cells.map((c, i) => padTo(c, widths[i])).join('  ').trimEnd();
  const out = [
    /* Truncated like any other cell. Left un-truncated, `malware_family` (14)
       in an 11-wide column pushed every following column off its rule. */
    accent(line(keys.map((k, i) => cell(label(k), { width: widths[i] })))),
    dim(widths.map((w) => '─'.repeat(w)).join('  ')),
    ...rows.map((r) =>
      line(
        keys.map((k, i) =>
          cell(r[k], { width: widths[i], defanged: defanged || (isIocRow(r) && IOC_KEYS.has(k)) }),
        ),
      ),
    ),
  ];

  const hidden = Object.keys(rows[0]).length - keys.length + dropped;
  const notes = [];
  if (pagination) {
    notes.push(
      `page ${pagination.page}/${pagination.totalPages} · ${rows.length} of ${pagination.total} rows`,
    );
    if (pagination.page < pagination.totalPages) notes.push(`next: --page ${pagination.page + 1}`);
  }
  if (hidden > 0) notes.push(`${hidden} more fields per row — use --json`);
  if (notes.length) out.push('', dim(wrap(notes.join('  ·  '), width)));
  return out.join('\n');
}

/**
 * A detail response as key/value, with arrays reduced to counts.
 *
 * A single technique carries `groups[125]` and `software[23]`. Printing those
 * inline buries the fields someone actually came for, so arrays are summarised
 * and `--expand <field>` promotes one of them to a table.
 */
/**
 * Walk a response into flat scalars and arrays, keeping the path as a dotted key.
 *
 * A nested object used to print as `{attackVersion, domain, seededAt}` — its
 * field NAMES and none of its values. Seven endpoints (dashboard, nav-counts,
 * profile, frameworks/status, frameworks/purdue, compliance/frameworks,
 * assets/{id}) showed nothing but key names, hiding 23 fields on one of them.
 * Depth is capped at 3 so a deeply nested document degrades to `--json` instead
 * of producing hundreds of rows.
 */
function walkFields(value, prefix = '', depth = 0, acc = { scalars: [], arrays: [], deep: [] }) {
  for (const [k, v] of Object.entries(value)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (Array.isArray(v)) acc.arrays.push([key, v]);
    else if (isScalar(v)) acc.scalars.push([key, v]);
    else if (v && typeof v === 'object') {
      if (depth < 3) walkFields(v, key, depth + 1, acc);
      else acc.deep.push([key, v]);
    }
  }
  return acc;
}

/** Lay a long value out under its own column instead of truncating to one line. */
function block(text, labelWidth, valueWidth, maxLines) {
  const lines = wrap(text, valueWidth).split('\n');
  const shown = lines.slice(0, maxLines);
  const pad = ' '.repeat(labelWidth + 2);
  const body = shown.map((l, i) => (i === 0 ? l : pad + l));
  return { body, truncated: lines.length > shown.length };
}

export function renderDetail(obj, { expand, width = 100, defanged = false, color = true } = {}) {
  const { dim, bold, accent, red } = styler(color);
  const { scalars, arrays, deep } = walkFields(obj);

  if (expand) {
    const found = arrays.find(([k]) => k === expand);
    if (!found) {
      const names = arrays.map(([k]) => label(k)).join(', ');
      const asked = sanitize(String(expand)).replace(/\s+/g, ' ').slice(0, 60);
      return `${red(`No array field "${asked}".`)}\n${dim(wrap(`Available: ${names || 'none'}`, width))}`;
    }
    const [, items] = found;
    // [].every() is true, so an empty array used to render as a blank line.
    if (items.length === 0) return dim(`${label(expand)} is empty.`);
    if (items.every(isScalar)) {
      const locators = defanged || IOC_KEYS.has(expand);
      return items.map((i) => cell(i, { width, defanged: locators })).join('\n');
    }
    return renderList(items, null, { width, defanged, color });
  }

  const names = [...scalars, ...arrays, ...deep].map(([k]) => k.length);
  const labelWidth = Math.min(26, Math.max(...names, 4));
  const valueWidth = Math.max(16, width - labelWidth - 2);
  const iocRow = isIocRow(obj);
  const out = [];

  for (const [k, v] of scalars) {
    const defangThis = defanged || (iocRow && IOC_KEYS.has(k.split('.').pop()));
    const raw = v === null || v === undefined ? '—' : sanitize(v).replace(/\s+/g, ' ').trim() || '—';
    const text = defangThis ? defang(raw) : raw;
    const head = accent(label(k).padEnd(labelWidth));
    if (text.length <= valueWidth) {
      out.push(`${head}  ${k === 'name' || k === 'attackId' ? bold(text) : text}`);
      continue;
    }
    /* Wrapped under its own column rather than cut at one line. `description`
       IS the content of a detail view, and Log4Shell's was clipped at ~80
       characters with no way to see the rest short of --json. */
    const { body, truncated } = block(text, labelWidth, valueWidth, 8);
    out.push(`${head}  ${body[0]}`, ...body.slice(1));
    if (truncated) out.push(`${' '.repeat(labelWidth + 2)}${dim('… --json for the rest')}`);
  }

  for (const [k, v] of deep) {
    out.push(`${accent(label(k).padEnd(labelWidth))}  ${dim(`{${Object.keys(v).map(label).join(', ')}} — --json`)}`);
  }
  for (const [k, v] of arrays) {
    out.push(`${accent(label(k).padEnd(labelWidth))}  ${dim(`[${v.length}]`)}`);
  }

  /* A response that is ALL arrays — /search, /relationships — showed only
     `techniques [20] groups [20]`, so seeing a single hit cost another call per
     bucket. Preview the first few of each instead. */
  /* A "buckets" response is almost entirely arrays — /search has one scalar and
     eight. Two arrays beside a name is an ordinary detail response, and
     previewing those would bury the fields someone came for. */
  if (arrays.length >= 3 && scalars.length <= 1 && deep.length === 0) {
    const preview = [];
    for (const [k, items] of arrays) {
      if (items.length === 0) continue;
      preview.push('', accent(`${label(k)} · ${items.length}`));
      const head = items.slice(0, 3);
      preview.push(
        head.every(isScalar)
          ? head.map((i) => `  ${cell(i, { width: width - 2, defanged })}`).join('\n')
          : renderList(head, null, { width: width - 2, defanged, color })
              .split('\n')
              .map((l) => `  ${l}`)
              .join('\n'),
      );
      if (items.length > 3) preview.push(dim(`  … ${items.length - 3} more — mitrex … --expand ${k}`));
    }
    if (preview.length) return [...out, ...preview].join('\n');
  }

  if (arrays.length) {
    out.push('', dim(wrap(`--expand <field> to table one of: ${arrays.map(([k]) => label(k)).join(', ')}`, width)));
  }
  return out.join('\n');
}
