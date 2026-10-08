import { test } from 'node:test';
import assert from 'node:assert/strict';
import { submissionSchema } from '../../src/lib/profile-submit-schema.mjs';

test('submission schema caps array length', () => {
  const big = { variant: 'v1-4q', action: 'apply', sectors: Array(5000).fill('retail') };
  assert.equal(submissionSchema.safeParse(big).success, false);
});

test('submission schema caps element length', () => {
  const long = { variant: 'v1-4q', action: 'apply', sectors: ['x'.repeat(10000)] };
  assert.equal(submissionSchema.safeParse(long).success, false);
});

test('submission schema accepts a realistic payload', () => {
  const ok = { variant: 'v1-4q', action: 'apply', sectors: ['retail'], platforms: ['Windows'] };
  assert.equal(submissionSchema.safeParse(ok).success, true);
});

test('auto_close is a valid action and is not dismiss', () => {
  assert.equal(submissionSchema.safeParse({ variant:'v1-4q', action:'auto_close' }).success, true);
});

/* ────────────────────────────────────────────────────────────────────────────
 * Per-dimension enums at the edge
 *
 * `slugList` used to be `z.array(z.string().min(1).max(64))`, so all six
 * dimension columns accepted ANY 64-character string — on the repo's only
 * unauthenticated public write, 20 rows per IP per day. The spec's Optionality
 * table requires `z.enum` here ("never free-string"). These tests pin that, and
 * pin the thing that makes it safe: the vocabulary must not be narrower than
 * what the live UI actually sends.
 * ──────────────────────────────────────────────────────────────────────────── */

import fs from 'node:fs';
import path from 'node:path';
import {
  SECTOR_VALUES,
  PLATFORM_VALUES,
  ROLE_VALUES,
  FRAMEWORK_VALUES,
  ASSET_VALUES,
  PURDUE_LEVEL_VALUES,
} from '../../src/lib/profile-submit-values.mjs';

const REPO = path.resolve(import.meta.dirname, '../..');
const read = (rel) => fs.readFileSync(path.join(REPO, rel), 'utf8');

/**
 * Values of the first array literal in a `NAME = …[ 'a', 'b' ]` declaration.
 * `[^[]*` covers both the bare `NAME = [` form (SECTOR_SLUGS) and the wrapped
 * `NAME = z.enum([` form (purdueLevelSchema).
 */
function tsArrayLiteral(source, file, name) {
  const m = source.match(new RegExp(`${name}\\s*(?::[^=]*)?=\\s*[^[]*\\[([\\s\\S]*?)\\]`));
  assert.ok(m, `could not find ${name} in ${file} — the drift guard needs repointing`);
  return [...m[1].matchAll(/'((?:[^'\\]|\\.)*)'/g)].map((x) => x[1]);
}

test('vocabulary: sectors mirror SECTOR_SLUGS in src/lib/profile-options.ts', () => {
  const f = 'src/lib/profile-options.ts';
  assert.deepEqual(tsArrayLiteral(read(f), f, 'SECTOR_SLUGS'), SECTOR_VALUES);
});

test('vocabulary: platforms mirror the three per-domain lists in src/lib/profile-options.ts', () => {
  // PLATFORMS itself is assembled from the three, so the three are what to
  // mirror — and in that order, which is the order PLATFORMS spreads them in.
  const f = 'src/lib/profile-options.ts';
  const src = read(f);
  const expected = [
    ...tsArrayLiteral(src, f, 'ENTERPRISE_PLATFORMS'),
    ...tsArrayLiteral(src, f, 'MOBILE_PLATFORMS'),
    ...tsArrayLiteral(src, f, 'ICS_PLATFORMS'),
  ];
  assert.deepEqual(PLATFORM_VALUES, expected);
});

test('vocabulary: purdue levels mirror purdueLevelSchema in app/api/v1/lib/validate.ts', () => {
  const f = 'app/api/v1/lib/validate.ts';
  assert.deepEqual(tsArrayLiteral(read(f), f, 'purdueLevelSchema'), PURDUE_LEVEL_VALUES);
});

test('vocabulary: asset ids are exactly what assetIdSchema in validate.ts accepts', () => {
  // assetIdSchema is a bounded regex, not a list, so this asserts EQUIVALENCE
  // against the regex actually in the file — including the two boundaries the
  // bound exists for.
  const f = 'app/api/v1/lib/validate.ts';
  const m = read(f).match(/assetIdSchema\s*=\s*z\.string\(\)\.regex\((\/.*?\/)\)/);
  assert.ok(m, `could not find assetIdSchema in ${f} — the drift guard needs repointing`);
  const re = new RegExp(m[1].slice(1, -1));
  assert.equal(ASSET_VALUES.length, 18);
  for (const id of ASSET_VALUES) assert.ok(re.test(id), `${id} rejected by assetIdSchema`);
  for (const bad of ['A0000', 'A0019', 'A9999']) {
    assert.ok(!re.test(bad), `${bad} should be out of range`);
    assert.ok(!ASSET_VALUES.includes(bad));
  }
});

test('vocabulary: roles are no longer collected, but still parse for rows that have them', () => {
  /*
   * The role picker was REMOVED from the UI: it never reached the ranking
   * (`role` appears nowhere in app/api/v1/profile/route.ts) and a control that
   * changes nothing invites a visitor to work it back and forth expecting the
   * briefing to move. This guard used to hold the picker and the sink in sync;
   * with no picker it asserts the two things that still matter.
   *
   * ROLE_VALUES stays in the schema deliberately — profile_submissions holds
   * rows written while the question existed, and they must keep parsing.
   */
  const panel = read('src/components/profile/ProfilePanel.tsx');
  assert.ok(!panel.includes('ROLE_OPTIONS'), 'the role picker is back — restore the drift guard');
  assert.ok(ROLE_VALUES.length > 0, 'ROLE_VALUES must survive for historical rows');

  // An existing row still parses...
  assert.ok(submissionSchema.safeParse({
    variant: 'v1-4q', action: 'apply', sectors: ['financial'],
    platforms: [], roles: [ROLE_VALUES[0]], frameworks: [], assets: [], purdue_levels: [],
  }).success, 'a row written before the removal must still parse');

  // ...and what the UI sends now is an empty array, as `frameworks` is.
  assert.ok(submissionSchema.safeParse({
    variant: 'v1-4q', action: 'apply', sectors: ['financial'],
    platforms: [], roles: [], frameworks: [], assets: [], purdue_levels: [],
  }).success, 'the current payload shape must parse');
});

test('vocabulary: framework keys mirror SCF_FRAMEWORK_REGISTRY', () => {
  const f = 'src/lib/scf-framework-registry.ts';
  const keys = [...read(f).matchAll(/framework_key:\s*'([^']+)'/g)].map((m) => m[1]);
  assert.equal(keys.length, 22, 'registry entry count changed — update FRAMEWORK_VALUES');
  assert.deepEqual(keys, FRAMEWORK_VALUES);
});

test('vocabulary: an unknown value in ANY dimension is rejected', () => {
  const base = { variant: 'v1-4q', action: 'apply' };
  const bad = {
    sectors: ['aerospace'],
    platforms: ['Solaris'],
    roles: ['ciso'],
    frameworks: ['nist-csf-v1'],
    assets: ['A0019'],
    purdue_levels: ['l6'],
  };
  for (const [dim, value] of Object.entries(bad)) {
    const r = submissionSchema.safeParse({ ...base, [dim]: value });
    assert.equal(r.success, false, `${dim} must reject ${JSON.stringify(value)}`);
  }
});

test('vocabulary: a real v1-4q payload from the current UI still round-trips', () => {
  // The shape ProfilePanel's payloadRef builds for the IT variant: one sector,
  // the enterprise platform multi-select, roles, frameworks, and empty OT lists.
  const payload = {
    variant: 'v1-4q',
    action: 'apply',
    sectors: ['energy'],
    platforms: ['Windows', 'Linux', 'Network Devices'],
    roles: ['soc-detection', 'grc'],
    frameworks: ['nist-csf-v2', 'eu-nis2', 'iec-62443'],
    assets: [],
    purdue_levels: [],
  };
  const r = submissionSchema.safeParse(payload);
  assert.equal(r.success, true, JSON.stringify(r.error?.issues));
  assert.deepEqual(r.data, payload, 'nothing coerced or dropped');
});

test('vocabulary: a real v1-6q-ot payload from the current UI still round-trips', () => {
  // The OT variant deliberately reports empty sectors and platforms (the OT
  // panel never asks them) and carries assets + purdue_levels instead.
  const payload = {
    variant: 'v1-6q-ot',
    action: 'apply',
    sectors: [],
    platforms: [],
    roles: ['ot-engineering', 'incident-response'],
    frameworks: ['iec-62443', 'nerc-cip-2024'],
    assets: ['A0003', 'A0010', 'A0018'],
    purdue_levels: ['l1', 'l2', 'l3_5'],
  };
  const r = submissionSchema.safeParse(payload);
  assert.equal(r.success, true, JSON.stringify(r.error?.issues));
  assert.deepEqual(r.data, payload);
});

test('vocabulary: every row already in production parses', () => {
  // Replayed from Neon 2026-09-26 (SELECT the six dimension columns from
  // profile_submissions). A tightened vocabulary that rejects a row the live UI
  // already wrote would be a regression dressed as a fix.
  const live = [
    { variant: 'v1-4q', action: 'dismiss', sectors: [], platforms: [], roles: [], frameworks: [], assets: [], purdue_levels: [] },
    { variant: 'v1-4q', action: 'apply', sectors: ['defense'], platforms: ['Linux', 'macOS'], roles: [], frameworks: [], assets: [], purdue_levels: [] },
    { variant: 'v1-4q', action: 'auto_close', sectors: [], platforms: [], roles: [], frameworks: [], assets: [], purdue_levels: [] },
  ];
  for (const row of live) {
    assert.equal(submissionSchema.safeParse(row).success, true, JSON.stringify(row));
  }
});

test('vocabulary: the .max(24) bound is unchanged', () => {
  const ok = { variant: 'v1-4q', action: 'apply', platforms: PLATFORM_VALUES.slice(0, 20) };
  assert.equal(submissionSchema.safeParse(ok).success, true);
  const over = {
    variant: 'v1-4q', action: 'apply',
    assets: [...ASSET_VALUES, ...ASSET_VALUES].slice(0, 25),
  };
  assert.equal(submissionSchema.safeParse(over).success, false);
});
