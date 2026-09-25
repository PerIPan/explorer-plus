export const PEEK_MS = 3000;

/**
 * How long BEFORE the peek expires the diamond nudges.
 *
 * The auto-close was landing as a random event: the panel simply vanished,
 * with nothing to attribute it to. A small movement on the diamond just
 * beforehand makes the close read as caused — the thing the panel came out
 * of takes it back. It has to be long enough to be noticed as a separate
 * event and short enough to still be read as the same gesture; a quarter of
 * a second is both, and leaves 2750ms of the 3000ms peek undisturbed.
 */
export const PEEK_NUDGE_LEAD_MS = 250;

/**
 * @typedef {'apply' | 'dismiss' | 'auto_close' | null} PeekReport
 */

/**
 * @typedef {Object} PeekState
 * @property {boolean} open
 * @property {number | null} timer
 * @property {PeekReport} [report]
 */

/**
 * @typedef {Object} PeekEvent
 * @property {'PEEK' | 'CLICK_OPEN' | 'INTERACT' | 'EXPIRE' | 'CLOSE' | 'APPLY' | 'TOGGLE_CLOSE'} type
 */

/**
 * The 3s auto-close belongs to the unsolicited first-visit peek only. A click
 * opens with no timer. Any interaction cancels the timer permanently rather
 * than restarting it — closing the panel under someone mid-search is hostile,
 * and 3s is enough to read four labels, not to answer them. Shortly before it
 * expires the diamond nudges (see `peekNudgeDelay`), so the close reads as
 * caused rather than random.
 *
 * Closing has three distinct outcomes, not two. 'CLOSE' is a rejection and
 * reports 'dismiss'; 'EXPIRE' is an untouched peek and reports 'auto_close';
 * 'TOGGLE_CLOSE' is a visitor clicking the diamond a second time to put the
 * popover away, which is neither — it reports NOTHING, so no telemetry row is
 * written and the dismissal flag is never set. Folding it into 'CLOSE' would
 * record an ordinary toggle as a rejection and permanently suppress the peek
 * for someone who merely closed a panel they had just opened.
 *
 * @param {PeekState} state
 * @param {PeekEvent} event
 * @returns {PeekState}
 */
export function peekReducer(state, event) {
  switch (event.type) {
    case 'PEEK':       return { open: true,  timer: PEEK_MS, report: null };
    case 'CLICK_OPEN': return { open: true,  timer: null,    report: null };
    case 'INTERACT':   return { ...state, timer: null };
    case 'EXPIRE':     return { open: false, timer: null, report: 'auto_close' };
    case 'CLOSE':      return { open: false, timer: null, report: 'dismiss' };
    case 'TOGGLE_CLOSE': return { open: false, timer: null, report: null };
    case 'APPLY':      return { open: false, timer: null, report: 'apply' };
    default:           return state;
  }
}

/**
 * How long after the peek is armed the diamond should nudge, or `null` for
 * "never nudge".
 *
 * Pure, and derived from the SAME `timer` field the auto-close is driven by,
 * so the cue cannot outlive the thing it announces. `null` covers every case
 * where there is nothing to announce:
 *
 *  - a CLICK-OPENED panel (`timer === null`): there is no auto-close, so a
 *    cue promising one would be a lie;
 *  - an already-CANCELLED peek ('INTERACT' sets `timer` to null): the visitor
 *    touched the panel, the close was called off, and twitching the diamond
 *    at them would suggest it is about to happen anyway;
 *  - a timer too short to lead (<= the lead time), where the nudge would land
 *    at or after the close it is supposed to precede;
 *  - anything that is not a finite positive number, defensively.
 *
 * @param {number | null | undefined} timer  `PeekState.timer`
 * @returns {number | null} delay in ms from arming, or null
 */
export function peekNudgeDelay(timer) {
  if (typeof timer !== 'number' || !Number.isFinite(timer)) return null;
  if (timer <= PEEK_NUDGE_LEAD_MS) return null;
  return timer - PEEK_NUDGE_LEAD_MS;
}
