// scripts/lib/profile-peek.test.mjs — run with `npm test`, no DB required.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { peekReducer, PEEK_MS } from '../../src/lib/profile-peek.mjs';

test('peek: timer is armed only for an unsolicited peek', () => {
  assert.equal(peekReducer({ open: false, timer: null }, { type: 'PEEK' }).timer, PEEK_MS);
  assert.equal(peekReducer({ open: false, timer: null }, { type: 'CLICK_OPEN' }).timer, null);
});

test('peek: any interaction cancels the timer permanently', () => {
  let s = peekReducer({ open: false, timer: null }, { type: 'PEEK' });
  s = peekReducer(s, { type: 'INTERACT' });
  assert.equal(s.timer, null);
  s = peekReducer(s, { type: 'INTERACT' });
  assert.equal(s.timer, null, 'timer must not be re-armed');
});

test('peek: expiry closes with auto_close, never dismiss', () => {
  const s = peekReducer({ open: true, timer: PEEK_MS }, { type: 'EXPIRE' });
  assert.equal(s.open, false);
  assert.equal(s.report, 'auto_close');
});

test('peek: an explicit close reports dismiss', () => {
  const s = peekReducer({ open: true, timer: null }, { type: 'CLOSE' });
  assert.equal(s.report, 'dismiss');
});
