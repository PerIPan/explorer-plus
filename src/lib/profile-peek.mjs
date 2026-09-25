export const PEEK_MS = 5000;

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
 * @property {'PEEK' | 'CLICK_OPEN' | 'INTERACT' | 'EXPIRE' | 'CLOSE' | 'APPLY'} type
 */

/**
 * The 5s auto-close belongs to the unsolicited first-visit peek only. A click
 * opens with no timer. Any interaction cancels the timer permanently rather
 * than restarting it — closing the panel under someone mid-search is hostile,
 * and 5s is enough to read four labels, not to answer them.
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
    case 'APPLY':      return { open: false, timer: null, report: 'apply' };
    default:           return state;
  }
}
