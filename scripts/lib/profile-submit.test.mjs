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
