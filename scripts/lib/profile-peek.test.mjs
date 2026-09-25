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

test('peek: toggle-close closes silently — no report, so no telemetry row and no dismissal flag', () => {
  // Clicking the diamond a second time to put the panel away is not a
  // dismissal. `report` must stay null: ProfilePanel only POSTs (and
  // useProfileState only writes localStorage['mx-profile']) on a non-null
  // report, so a reported 'dismiss' here would silently cost the visitor the
  // feature for good for doing the ordinary thing with a popover.
  const s = peekReducer({ open: true, timer: null }, { type: 'TOGGLE_CLOSE' });
  assert.equal(s.open, false);
  assert.equal(s.report, null, 'toggle-close must not report — dismiss is for a real outside click / X');
});

test('peek: toggle-close and explicit close differ only in what they report', () => {
  const start = { open: true, timer: PEEK_MS };
  const toggled = peekReducer(start, { type: 'TOGGLE_CLOSE' });
  const closed = peekReducer(start, { type: 'CLOSE' });
  assert.equal(toggled.open, closed.open, 'both close the panel');
  assert.equal(toggled.timer, null, 'toggle-close clears the peek timer');
  assert.equal(closed.timer, null, 'explicit close clears the peek timer');
  assert.notEqual(toggled.report, closed.report, 'they must not be interchangeable');
});
