#!/usr/bin/env node
// Guard: the "catch-all CWE" threshold (a CWE mapping to >N distinct ATT&CK
// techniques is a fan-out CWE) is the single number that keeps CVE/GHSA/OWASP
// counts consistent across the runtime helper and the build-time matviews.
// It can't be shared as one import (SQL files + .mjs scripts can't read the TS
// constant), so it's copied. This fails CI if any copy drifts from
// CATCHALL_CWE_THRESHOLD in app/api/v1/lib/inference.ts.
import { readFileSync } from 'node:fs';

const read = (rel) => readFileSync(new URL(`../${rel}`, import.meta.url), 'utf8');

// Source of truth
const inf = read('app/api/v1/lib/inference.ts');
const srcMatch = inf.match(/CATCHALL_CWE_THRESHOLD\s*=\s*(\d+)/);
if (!srcMatch) {
  console.error('FAIL: CATCHALL_CWE_THRESHOLD not found in app/api/v1/lib/inference.ts');
  process.exit(1);
}
const threshold = Number(srcMatch[1]);

// Build-time copies that can't import the constant. Each must contain at least
// one threshold literal, and every literal must equal `threshold`.
const targets = [
  { file: 'scripts/migrate-applications.sql', re: /COUNT\(DISTINCT technique_id\)\s*>\s*(\d+)/g, note: 'catchall_cwes matview def' },
  { file: 'scripts/ingest-cvelistv5.mjs',     re: /COUNT\(DISTINCT technique_id\)\s*>\s*(\d+)/g, note: 'app_technique_groups matview' },
  { file: 'scripts/migrate-ghsa.sql',         re: /COUNT\(DISTINCT technique_id\)\s*>\s*(\d+)/g, note: 'package_summary matview' },
  { file: 'scripts/sync-frameworks.mjs',      re: /techs\.size\s*>\s*(\d+)/g,                    note: 'in-memory CWE->technique catch-all drop' },
];

const failures = [];
for (const t of targets) {
  let src;
  try { src = read(t.file); } catch { failures.push(`${t.file}: not found`); continue; }
  const nums = [...src.matchAll(t.re)].map((m) => Number(m[1]));
  if (nums.length === 0) { failures.push(`${t.file}: no threshold literal matched — pattern moved? (${t.note})`); continue; }
  for (const n of nums) {
    if (n !== threshold) failures.push(`${t.file}: found '> ${n}', expected '> ${threshold}' (${t.note})`);
  }
}

// The in-memory bridge should reference the constant, not a literal.
const bridge = read('app/api/cron/lib/capec-bridge.ts');
if (!/CATCHALL_CWE_THRESHOLD/.test(bridge)) {
  failures.push('app/api/cron/lib/capec-bridge.ts: expected to reference CATCHALL_CWE_THRESHOLD (not a literal)');
}

if (failures.length) {
  console.error(`\nCatch-all CWE threshold drift (source of truth = ${threshold}):`);
  for (const f of failures) console.error(`  - ${f}`);
  console.error('\nUpdate every copy to match CATCHALL_CWE_THRESHOLD in app/api/v1/lib/inference.ts.');
  process.exit(1);
}
console.log(`OK: catch-all CWE threshold = ${threshold} is consistent across all ${targets.length} build-time copies + the in-memory bridge.`);
