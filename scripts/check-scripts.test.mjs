// scripts/check-scripts.test.mjs — run with `npm test`
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseInstall, scriptEntries, importsOf, packageName, usesSessionState, watchedWorkflows, workflowMeta } from './check-scripts.mjs';

test('parseInstall: npm ci, npm ci --omit=dev (with fallback), explicit npm install', () => {
  assert.deepEqual({ ...parseInstall('      - run: npm ci\n'), names: [] }, { all: true, prod: false, names: [] });
  // The sync-scf.yml line that hid the xlsx failure from April to October.
  const omit = parseInstall('        run: npm ci --omit=dev --include=optional || npm ci\n');
  assert.equal(omit.all, false);
  assert.equal(omit.prod, true);
  const list = parseInstall('        run: npm install pg@8.23.0 yaml@2.9.1 @scope/x@1.0.0 --ignore-scripts --no-audit\n');
  assert.deepEqual([...list.names].sort(), ['@scope/x', 'pg', 'yaml']);
  assert.equal(parseInstall('# npm ci in a comment\n').all, false);
});

test('scriptEntries: node invocations and npm run indirection, comments skipped', () => {
  const wf = [
    '        run: node --experimental-strip-types scripts/sync-scf.mjs $ARGS',
    '        # node scripts/ignored.mjs',
    '        run: npm run seed:thing',
  ].join('\n');
  assert.deepEqual(scriptEntries(wf, { 'seed:thing': 'node scripts/seed-thing.mjs && npm run inner', inner: 'node scripts/inner.mjs' }).sort(),
    ['scripts/inner.mjs', 'scripts/seed-thing.mjs', 'scripts/sync-scf.mjs']);
});

test('importsOf: static, multi-line, side-effect, re-export, dynamic, require; not import type', () => {
  const src = [
    "import pg from 'pg';",
    'import {',
    '  a,',
    "} from './lib/a.mjs';",
    "import 'dotenv/config';",
    "export { b } from './b.mjs';",
    "const m = await import('../src/lib/x.ts');",
    "const y = require('yaml');",
    "import type { T } from 'typeonly';",
  ].join('\n');
  assert.deepEqual(importsOf(src).sort(), ['../src/lib/x.ts', './b.mjs', './lib/a.mjs', 'dotenv/config', 'pg', 'yaml']);
});

test('packageName: builtins and relative paths are not packages', () => {
  assert.equal(packageName('node:fs'), null);
  assert.equal(packageName('fs'), null);
  assert.equal(packageName('child_process'), null);
  assert.equal(packageName('./x.mjs'), null);
  assert.equal(packageName('pg'), 'pg');
  assert.equal(packageName('@modelcontextprotocol/server/x'), '@modelcontextprotocol/server');
  assert.equal(packageName('dotenv/config'), 'dotenv');
});

test('usesSessionState: session lock or non-LOCAL SET; xact locks and SET LOCAL are fine', () => {
  assert.equal(usesSessionState("await client.query('SELECT pg_try_advisory_lock($1)', [k])"), true);
  assert.equal(usesSessionState('await pool.query(`SELECT pg_advisory_lock(42)`)'), true);
  assert.equal(usesSessionState("await client.query(`SET statement_timeout = '15min'`)"), true);
  assert.equal(usesSessionState("await client.query(`SET LOCAL lock_timeout = '30s'`)"), false);
  assert.equal(usesSessionState("await client.query('SELECT pg_advisory_xact_lock($1)', [k])"), false);
  assert.equal(usesSessionState('// a session lock is unreliable through the pooler'), false);
});

test('watchedWorkflows / workflowMeta: the alert list and a workflow\'s name + schedule', () => {
  const alert = 'on:\n  workflow_run:\n    workflows:\n      - sync-scf\n      - Sync CVE → Application Products (NVD)\n    types: [completed]\n';
  assert.deepEqual(watchedWorkflows(alert), ['sync-scf', 'Sync CVE → Application Products (NVD)']);
  assert.deepEqual(workflowMeta("name: sync-scf\non:\n  schedule:\n    - cron: '0 0 10 * *'\n"), { name: 'sync-scf', scheduled: true });
  assert.deepEqual(workflowMeta('name: Checks\non:\n  push:\n'), { name: 'Checks', scheduled: false });
});

test('parseInstall: production flags, bare npm install, quoted tokens', () => {
  assert.equal(parseInstall('run: npm ci --production\n').prod, true);
  assert.equal(parseInstall('run: npm ci --only=prod\n').prod, true);
  assert.equal(parseInstall('run: npm install\n').all, true);
  assert.deepEqual([...parseInstall('run: npm install "pg@8.23.0" --no-audit\n').names], ['pg']);
});

test('scriptEntries follows a backslash-continued node command', () => {
  assert.deepEqual(scriptEntries('        run: node --experimental-strip-types \\\n          scripts/x.mjs --flag\n', {}), ['scripts/x.mjs']);
});

test('importsOf ignores JSDoc types and comment lines', () => {
  assert.deepEqual(importsOf(" * @param {import('pg').Pool} pool\n// await import('nope')\nconst m = await import('./real.mjs');"), ['./real.mjs']);
});

test('usesSessionState: RESET and set_config(..., false) count; set_config(..., true) does not', () => {
  assert.equal(usesSessionState("await client.query('RESET statement_timeout')"), true);
  assert.equal(usesSessionState("await client.query(\"SELECT set_config('statement_timeout', '0', false)\")"), true);
  assert.equal(usesSessionState("await client.query(\"SELECT set_config('statement_timeout', $1, true)\", [ms])"), false);
});
