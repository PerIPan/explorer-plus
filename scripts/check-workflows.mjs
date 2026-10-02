#!/usr/bin/env node
// scripts/check-workflows.mjs
//
// Two invariants about .github/workflows, both learned by breaking them.
//
// 1. NO EMPTY GITHUB EXPRESSION, anywhere in the file.
//
//    GitHub evaluates expressions inside a `run:` block before the shell ever
//    sees the script — including inside what looks like a shell comment. An
//    EMPTY expression is a parse error, and it does not fail the step: it fails
//    the whole workflow FILE. The run then shows up named by its path rather
//    than its `name:`, with "This run likely failed because of a workflow file
//    issue" and no log.
//
//    On 2026-10-02 this shipped in seven workflows at once, in a comment whose
//    subject was the danger of writing expressions inside `run:` blocks. Six
//    scheduled syncs were dead on main until it was fixed. `yaml.safe_load`
//    parses the file happily, so YAML validity proves nothing here.
//
// 2. NO GITHUB EXPRESSION INSIDE A `run:` BLOCK, at all.
//
//    This is the substantive one. A `${...}`-style GitHub expression in a
//    `run:` block is substituted textually before the shell parses the line,
//    so an input containing a shell metacharacter becomes a command — in jobs
//    that hold DATABASE_URL. Values must arrive through `env:` and be read as
//    shell variables.
//
//    The rule is absolute rather than "no UNSAFE expressions", because
//    judging safety per site is what let the pattern spread in the first
//    place, and because a comment mentioning one is how invariant 1 was
//    broken. `env:`, `with:`, `if:` and `name:` are unaffected.
//
// Dependency-free on purpose: this runs in the `consistency` CI job, which
// deliberately does no `npm ci`.

import { readdirSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const DIR = join(dirname(fileURLToPath(import.meta.url)), '../.github/workflows');

// Assembled at runtime so this file does not itself contain the literal token
// it forbids — otherwise the guard would flag its own source.
const OPEN = '$' + '{{';
const EMPTY = new RegExp('\\$\\{\\{\\s*\\}\\}');

const problems = [];

for (const file of readdirSync(DIR).filter((f) => f.endsWith('.yml') || f.endsWith('.yaml'))) {
  const lines = readFileSync(join(DIR, file), 'utf8').split('\n');

  // Track `run:` blocks by indentation: the key's indent, then every
  // more-indented line until the indentation returns to that level or less.
  let runIndent = null;

  lines.forEach((line, i) => {
    const n = i + 1;
    const indent = line.length - line.trimStart().length;

    if (runIndent !== null && line.trim() !== '' && indent <= runIndent) runIndent = null;

    const isRunKey = /^\s*-?\s*run:/.test(line);
    const inRun = runIndent !== null;

    if (EMPTY.test(line)) {
      problems.push(
        `${file}:${n}  EMPTY expression — a parse error that fails the whole workflow file\n    ${line.trim()}`,
      );
    } else if ((inRun || isRunKey) && line.includes(OPEN)) {
      problems.push(
        `${file}:${n}  expression inside a run: block — pass it through env: instead\n    ${line.trim()}`,
      );
    }

    if (isRunKey) runIndent = indent;
  });
}

if (problems.length > 0) {
  console.error(`check-workflows: ${problems.length} problem(s)\n`);
  for (const p of problems) console.error(`  ${p}\n`);
  process.exit(1);
}

const count = readdirSync(DIR).filter((f) => f.endsWith('.yml') || f.endsWith('.yaml')).length;
console.log(`check-workflows: ok (${count} workflows, no empty expressions, none inside a run: block)`);
