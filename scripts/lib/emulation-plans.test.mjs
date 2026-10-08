import test from 'node:test';
import assert from 'node:assert/strict';

import {
  EMULATION_PLANS,
  NOT_INGESTED,
  normalizePlan,
  upstreamUrl,
} from '../../src/lib/emulation-plans.mjs';

/* Fixtures are the shapes the real files have, as `yaml.parse` returns them —
 * taken from APT29.yaml (clean), turla_snake.yaml (`attack_id: x`, padded
 * tactics) and carbanak (step refs like "7.A.5" in attack_id), read
 * 2026-10-08. Objects rather than YAML text so the test needs no parser. */

const header = {
  emulation_plan_details: {
    id: '4975696e-1d41-11eb-adc1-0242ac120002',
    adversary_name: 'APT29',
    adversary_description: '…',
    attack_version: 8.1,
    format_version: 1.0,
  },
};

const step = (id, attackId, extra = {}) => ({
  id,
  name: `step ${id}`,
  description: 'd',
  tactic: 'execution',
  technique: { attack_id: attackId, name: 'n' },
  procedure_step: '1.A',
  platforms: { windows: { psh: { command: 'whoami' } } },
  ...extra,
});

test('registry: ten plans, unique keys, slug-safe, group ids well-formed', () => {
  assert.equal(EMULATION_PLANS.length, 10);
  const keys = EMULATION_PLANS.map((p) => p.planKey);
  assert.equal(new Set(keys).size, keys.length);
  for (const p of EMULATION_PLANS) {
    assert.match(p.planKey, /^[a-z0-9-]+$/);
    assert.match(p.attackGroupId, /^G\d{4}$/);
    assert.match(p.path, /\.ya?ml$/);
  }
  // Turla has two plans; every other group one.
  assert.equal(EMULATION_PLANS.filter((p) => p.attackGroupId === 'G0010').length, 2);
});

test('registry: nothing is both ingested and listed as not ingested', () => {
  const ingestedGroups = new Set(EMULATION_PLANS.map((p) => p.attackGroupId));
  for (const n of NOT_INGESTED) if (n.attackGroupId) assert.ok(!ingestedGroups.has(n.attackGroupId), n.label);
});

test('normalizePlan: header fields, file order, platforms', () => {
  const out = normalizePlan([header, step('a', 'T1059.001'), step('b', 'T1036.002', { platforms: { linux: {}, Windows: {} } })]);
  assert.equal(out.plan.name, 'APT29');
  assert.equal(out.plan.attackVersion, '8.1');
  assert.equal(out.plan.upstreamPlanId, '4975696e-1d41-11eb-adc1-0242ac120002');
  assert.deepEqual(out.steps.map((s) => [s.stepUid, s.ordinal]), [['a', 1], ['b', 2]]);
  assert.deepEqual(out.steps[0].platforms, ['windows']);
  assert.deepEqual(out.steps[1].platforms, ['linux', 'windows']);
  assert.equal(out.steps[0].validTechniqueId, 'T1059.001');
  assert.deepEqual(out.warnings, []);
});

test('normalizePlan: junk technique ids are kept as steps but not as techniques', () => {
  const out = normalizePlan([header, step('a', 'x'), step('b', '7.A.5'), step('c', ' T1105 '), step('d', undefined)]);
  assert.equal(out.steps.length, 4);
  assert.deepEqual(out.steps.map((s) => s.validTechniqueId), [null, null, 'T1105', null]);
  assert.deepEqual(out.steps.map((s) => s.attackTechniqueId), ['x', '7.A.5', 'T1105', null]);
});

test('normalizePlan: messy tactic strings are trimmed, not rewritten', () => {
  const out = normalizePlan([header, step('a', 'T1105', { tactic: ' Commmand and Control ' })]);
  assert.equal(out.steps[0].tacticRaw, 'Commmand and Control');
});

test('normalizePlan: duplicate step ids are suffixed and reported', () => {
  const out = normalizePlan([header, step('a', 'T1105'), step('a', 'T1033')]);
  assert.deepEqual(out.steps.map((s) => s.stepUid), ['a', 'a#2']);
  assert.equal(out.warnings.length, 1);
});

test('normalizePlan: elements without id or name are skipped with a warning', () => {
  const out = normalizePlan([header, { name: 'no id' }, step('a', 'T1105')]);
  assert.equal(out.steps.length, 1);
  assert.equal(out.steps[0].ordinal, 1);
  assert.equal(out.warnings.length, 1);
});

test('normalizePlan: header-only plan has zero steps', () => {
  assert.equal(normalizePlan([header]).steps.length, 0);
});

test('normalizePlan: a file that is not a plan throws', () => {
  assert.throws(() => normalizePlan({}), /not a YAML list/);
  assert.throws(() => normalizePlan([step('a', 'T1105')]), /no emulation_plan_details/);
  assert.throws(() => normalizePlan([{ emulation_plan_details: { adversary_name: ' ' } }]), /adversary_name/);
});

test('upstreamUrl pins to the commit when known', () => {
  assert.equal(
    upstreamUrl('apt29/Emulation_Plan/yaml/APT29.yaml', 'abc123'),
    'https://github.com/center-for-threat-informed-defense/adversary_emulation_library/blob/abc123/apt29/Emulation_Plan/yaml/APT29.yaml',
  );
  assert.match(upstreamUrl('x.yaml', null), /\/blob\/master\/x\.yaml$/);
});

test('the workflow sparse-checks-out exactly the registry files', async () => {
  // The workflow clones blob-less and checks out only these paths; a plan
  // added to the registry but not to the workflow would make the ingest abort
  // on a missing file — this catches it before a scheduled run does.
  const { readFileSync } = await import('node:fs');
  const yml = readFileSync(new URL('../../.github/workflows/sync-emulation.yml', import.meta.url), 'utf8');
  const listed = [...yml.matchAll(/^\s+\/(\S+\.ya?ml)\s*\\?$/gm)].map((m) => m[1]).sort();
  assert.deepEqual(listed, EMULATION_PLANS.map((p) => p.path).sort());
});
