#!/usr/bin/env node
// scripts/check-scripts.mjs
//
// Two invariants about the scripts the scheduled workflows run, both learned
// on 2026-10-09 while ingesting SCF 2026.3.
//
// 1. A WORKFLOW INSTALLS EVERY PACKAGE ITS SCRIPTS IMPORT.
//
//    sync-scf.yml installed with `npm ci --omit=dev`, and `xlsx` had become a
//    devDependency in April. Every SCF run since died with ERR_MODULE_NOT_FOUND
//    before touching the database, so nothing in feed_sync_log or on /status
//    ever showed it; the July run failed and the data quietly went stale.
//    Most workflows install a hand-picked list (`npm install pg@… yaml@…`),
//    which breaks the same way the day a script gains an import. This follows
//    each workflow's `node scripts/…` and `npm run …` entry points through
//    their local imports and fails when a package is not in what the workflow
//    installs.
//
// 2. SESSION STATE GOES THROUGH scripts/lib/db-session.mjs.
//
//    DATABASE_URL is Neon's pooled endpoint (PgBouncer, transaction mode). A
//    session advisory lock or a session `SET` there lands on whichever server
//    connection the pooler picks: sync-scf's unlock missed its lock, which
//    then blocked the next run for an hour, and a timeout leaked by another
//    client cancelled its rebuild. A script that takes pg_advisory_lock /
//    pg_try_advisory_lock or runs a non-LOCAL `SET` must import db-session.mjs
//    (direct endpoint, one dedicated lock client).
//
// 3. EVERY SCHEDULED WORKFLOW IS WATCHED.
//
//    .github/workflows/alert-on-failure.yml opens an issue when a listed
//    workflow fails. A scheduled workflow missing from its list would fail as
//    silently as sync-scf did; a listed name that matches no workflow (a
//    rename) watches nothing.
//
// Dependency-free on purpose: this runs in the `consistency` CI job, which
// deliberately does no `npm ci`.

import { readdirSync, readFileSync, existsSync, statSync } from 'node:fs';
import { join, dirname, resolve, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { builtinModules } from 'node:module';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BUILTINS = new Set(builtinModules.flatMap((m) => [m, m.split('/')[0]]));

/**
 * What a workflow's install steps put in node_modules.
 * `npm ci` → every dependency; `npm ci --omit=dev` (even with an `|| npm ci`
 * fallback, which only runs if the first fails) → production + optional;
 * `npm install a@1 b@2` → exactly those names.
 *
 * @param {string} text  workflow YAML
 * @returns {{ all: boolean, prod: boolean, names: Set<string> }}
 */
export function parseInstall(text) {
  const out = { all: false, prod: false, names: new Set() };
  for (const raw of text.split('\n')) {
    const line = raw.replace(/^\s*-?\s*(run:\s*)?/, '');
    if (line.startsWith('#')) continue;
    const PROD = /--omit[= ]dev\b|--production\b|--only[= ]prod(?:uction)?\b/;
    const ci = line.match(/\bnpm ci\b([^|&;]*)/);
    if (ci) {
      if (PROD.test(ci[1])) out.prod = true;
      else out.all = true;
      continue;
    }
    const inst = line.match(/\bnpm (?:install|i)\b([^|&;#]*)/);
    if (inst) {
      const toks = inst[1].trim().split(/\s+/).map((t) => t.replace(/^['"]|['"]$/g, '')).filter(Boolean);
      const pkgs = toks.filter((t) => !t.startsWith('-'));
      // A bare `npm install` installs package.json's dependencies.
      if (pkgs.length === 0) { if (PROD.test(inst[1])) out.prod = true; else out.all = true; continue; }
      for (const tok of pkgs) out.names.add(tok.startsWith('@') ? tok.split('@').slice(0, 2).join('@') : tok.split('@')[0]);
    }
  }
  return out;
}

/**
 * `scripts/…` files a workflow (or an npm script it calls) runs with node.
 *
 * @param {string} text
 * @param {Record<string, string>} npmScripts  package.json "scripts"
 * @returns {string[]}  repo-relative paths
 */
export function scriptEntries(text, npmScripts, seen = new Set()) {
  const out = new Set();
  // Join shell line continuations ("node \\\n  scripts/x.mjs").
  for (const raw of text.replace(/\\\n\s*/g, ' ').split('\n')) {
    const line = raw.trim();
    if (line.startsWith('#')) continue;
    for (const m of line.matchAll(/\bnode\b[^\n]*?\b(scripts\/[\w./-]+\.(?:mjs|js|ts))\b/g)) out.add(m[1]);
    for (const m of line.matchAll(/\bnpm run\s+([\w:-]+)/g)) {
      const name = m[1];
      if (seen.has(name) || !npmScripts[name]) continue;
      seen.add(name);
      for (const s of scriptEntries(npmScripts[name], npmScripts, seen)) out.add(s);
    }
  }
  return [...out];
}

/**
 * Module specifiers a source file imports at runtime (static, side-effect,
 * re-export, dynamic and require). `import type` is skipped.
 *
 * @param {string} src
 * @returns {string[]}
 */
export function importsOf(src) {
  const out = new Set();
  const patterns = [
    /^\s*import\s+(?!type\s)[\s\S]*?\bfrom\s*['"]([^'"]+)['"]/gm,
    /^\s*import\s+['"]([^'"]+)['"]/gm,
    /^\s*export\s+(?!type\s)[^;'"]*?\bfrom\s*['"]([^'"]+)['"]/gm,
    // Dynamic import, but not a JSDoc type (`{import('pg').Pool}`) or a comment line.
    /^(?![ \t]*(?:\/\/|\*|\/\*))[^\n{]*?\bimport\(\s*['"]([^'"]+)['"]\s*\)/gm,
    /\brequire\(\s*['"]([^'"]+)['"]\s*\)/g,
  ];
  for (const re of patterns) for (const m of src.matchAll(re)) out.add(m[1]);
  return [...out];
}

/** "pg" for "pg", "@scope/name" for "@scope/name/sub"; null for builtins and relative paths. */
export function packageName(spec) {
  if (spec.startsWith('.') || spec.startsWith('/')) return null;
  if (spec.startsWith('node:') || BUILTINS.has(spec) || BUILTINS.has(spec.split('/')[0])) return null;
  const parts = spec.split('/');
  return spec.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0];
}

function resolveLocal(fromFile, spec) {
  const base = resolve(dirname(fromFile), spec);
  for (const cand of [base, `${base}.mjs`, `${base}.js`, `${base}.ts`, join(base, 'index.mjs'), join(base, 'index.js')]) {
    if (existsSync(cand) && statSync(cand).isFile()) return cand;
  }
  return null;
}

/**
 * Every package reachable from an entry script through local imports, with
 * the import chain that reaches it.
 *
 * @returns {Map<string, string[]>}  package -> chain of repo-relative files
 */
export function packagesReachable(entryAbs, unresolved = []) {
  const found = new Map();
  const walk = (file, chain, seen) => {
    if (seen.has(file)) return;
    seen.add(file);
    const here = [...chain, relative(ROOT, file)];
    for (const spec of importsOf(readFileSync(file, 'utf8'))) {
      const pkg = packageName(spec);
      if (pkg) { if (!found.has(pkg)) found.set(pkg, here); continue; }
      if (spec.startsWith('.')) {
        const next = resolveLocal(file, spec);
        if (!next) unresolved.push(`${relative(ROOT, file)} imports '${spec}', which does not resolve`);
        else if (next.startsWith(ROOT) && !next.includes('node_modules')) walk(next, here, seen);
      }
    }
  };
  walk(entryAbs, [], new Set());
  return found;
}

/** The `workflows:` list of a workflow_run trigger. */
export function watchedWorkflows(text) {
  const m = text.match(/workflow_run:\s*\n\s*workflows:\s*\n((?:\s*-\s*.+\n)+)/);
  if (!m) return [];
  return m[1].split('\n').map((l) => l.replace(/^\s*-\s*/, '').trim()).filter(Boolean);
}

/** A workflow's `name:` and whether it has a schedule trigger. */
export function workflowMeta(text) {
  const name = text.match(/^name:\s*(.+?)\s*$/m)?.[1]?.replace(/^['"]|['"]$/g, '') ?? null;
  return { name, scheduled: /^\s*schedule:\s*$/m.test(text) };
}

/** Session-state use that needs db-session.mjs: a session advisory lock or a non-LOCAL SET. */
export function usesSessionState(src) {
  return /\bpg_(?:try_)?advisory_lock\s*\(/.test(src)
    || /query\(\s*[`'"]\s*(?:SET\s+(?!LOCAL\b)\w|RESET\s+\w)/i.test(src)
    || /set_config\([^)]*,\s*false\s*\)/i.test(src);
}

function main() {
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  const deps = Object.keys(pkg.dependencies ?? {});
  const dev = Object.keys(pkg.devDependencies ?? {});
  const opt = Object.keys(pkg.optionalDependencies ?? {});
  const problems = [];

  // 1. Workflow installs cover their scripts' imports.
  const wfDir = join(ROOT, '.github/workflows');
  let checkedRuns = 0;
  for (const f of readdirSync(wfDir).filter((n) => /\.ya?ml$/.test(n)).sort()) {
    const text = readFileSync(join(wfDir, f), 'utf8');
    const entries = scriptEntries(text, pkg.scripts ?? {});
    if (entries.length === 0) continue;
    const inst = parseInstall(text);
    const have = new Set(inst.names);
    if (inst.all) for (const n of [...deps, ...dev, ...opt]) have.add(n);
    if (inst.prod) for (const n of [...deps, ...opt]) have.add(n);
    for (const entry of entries) {
      const abs = join(ROOT, entry);
      if (!existsSync(abs)) { problems.push(`${f}: runs ${entry}, which does not exist`); continue; }
      checkedRuns++;
      const unresolved = [];
      for (const [name, chain] of packagesReachable(abs, unresolved)) {
        if (have.has(name)) continue;
        const why = dev.includes(name) ? ' (a devDependency — the install step omits dev)' : '';
        problems.push(`${f}: ${chain.join(' → ')} imports '${name}', which the workflow does not install${why}`);
      }
      for (const u of unresolved) problems.push(`${f}: ${u}`);
    }
  }

  // 2. Session state goes through db-session.mjs.
  const scriptFiles = [
    ...readdirSync(join(ROOT, 'scripts')).filter((n) => n.endsWith('.mjs')).map((n) => join('scripts', n)),
    ...readdirSync(join(ROOT, 'scripts/lib')).filter((n) => n.endsWith('.mjs')).map((n) => join('scripts/lib', n)),
  ].filter((p) => !p.endsWith('.test.mjs') && !p.endsWith('db-session.mjs') && !p.endsWith('check-scripts.mjs'));
  let sessionUsers = 0;
  for (const p of scriptFiles) {
    const src = readFileSync(join(ROOT, p), 'utf8');
    if (!usesSessionState(src)) continue;
    sessionUsers++;
    const imports = /from\s+['"][./]*(?:lib\/)?db-session\.mjs['"]/.test(src);
    const calls = /\b(?:batchDatabaseUrl|takeSessionLock)\s*\(/.test(src);
    if (!imports || !calls) {
      problems.push(`${p}: takes a session advisory lock or sets session state but does not use scripts/lib/db-session.mjs (direct endpoint + dedicated lock client)`);
    }
  }

  // 3. Scheduled workflows are watched by alert-on-failure.yml.
  const alertFile = join(wfDir, 'alert-on-failure.yml');
  if (!existsSync(alertFile)) {
    problems.push('.github/workflows/alert-on-failure.yml is missing');
  } else {
    const watched = new Set(watchedWorkflows(readFileSync(alertFile, 'utf8')));
    const names = new Map();
    for (const f of readdirSync(wfDir).filter((n) => /\.ya?ml$/.test(n) && n !== 'alert-on-failure.yml')) {
      const meta = workflowMeta(readFileSync(join(wfDir, f), 'utf8'));
      if (meta.name) names.set(meta.name, { file: f, ...meta });
      else if (meta.scheduled) problems.push(`${f}: scheduled workflow has no name: — alert-on-failure.yml cannot watch it`);
    }
    for (const { file, name, scheduled } of names.values()) {
      if (scheduled && !watched.has(name)) problems.push(`${file}: scheduled workflow '${name}' is not in alert-on-failure.yml — its failures would go unnoticed`);
    }
    for (const w of watched) if (!names.has(w)) problems.push(`alert-on-failure.yml watches '${w}', which is no workflow's name: (renamed?)`);
  }

  if (problems.length) {
    console.error(`check-scripts: ${problems.length} problem(s)\n  - ${problems.join('\n  - ')}`);
    process.exit(1);
  }
  console.log(`check-scripts: ok (${checkedRuns} workflow script runs cover their imports; ${sessionUsers} session-state script(s) use db-session; scheduled workflows all watched)`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) main();
