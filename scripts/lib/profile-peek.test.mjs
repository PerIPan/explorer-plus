// scripts/lib/profile-peek.test.mjs — run with `npm test`, no DB required.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { peekReducer, peekNudgeDelay, PEEK_MS, PEEK_NUDGE_LEAD_MS } from '../../src/lib/profile-peek.mjs';

test('peek: the unsolicited peek lasts 3s', () => {
  // Pinned as a literal on purpose. Every other assertion in this file uses
  // the symbol, so they would all keep passing if the duration silently
  // changed; this is the one that fails when it does.
  assert.equal(PEEK_MS, 3000);
});

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

test('peek: the diamond nudges shortly before the peek expires', () => {
  const armed = peekReducer({ open: false, timer: null }, { type: 'PEEK' });
  const delay = peekNudgeDelay(armed.timer);
  assert.equal(delay, PEEK_MS - PEEK_NUDGE_LEAD_MS);
  assert.equal(delay, 2750);
  assert.ok(delay > 0 && delay < PEEK_MS, 'the cue must land inside the peek, before the close');
});

test('peek: a click-opened panel never nudges — there is no auto-close to announce', () => {
  const clicked = peekReducer({ open: false, timer: null }, { type: 'CLICK_OPEN' });
  assert.equal(clicked.timer, null);
  assert.equal(peekNudgeDelay(clicked.timer), null);
});

test('peek: a cancelled peek never nudges', () => {
  let s = peekReducer({ open: false, timer: null }, { type: 'PEEK' });
  assert.notEqual(peekNudgeDelay(s.timer), null, 'armed: the cue is scheduled');
  s = peekReducer(s, { type: 'INTERACT' });
  // INTERACT cancels permanently, so the cue must be cancelled with it —
  // nudging at someone who is mid-answer would promise a close that is no
  // longer coming.
  assert.equal(peekNudgeDelay(s.timer), null);
});

test('peek: no cue is scheduled when it could not precede the close', () => {
  assert.equal(peekNudgeDelay(PEEK_NUDGE_LEAD_MS), null, 'exactly the lead time leaves no room');
  assert.equal(peekNudgeDelay(PEEK_NUDGE_LEAD_MS - 1), null);
  assert.equal(peekNudgeDelay(0), null);
  assert.equal(peekNudgeDelay(undefined), null);
  assert.equal(peekNudgeDelay(Number.NaN), null);
  assert.equal(peekNudgeDelay(Number.POSITIVE_INFINITY), null);
});
