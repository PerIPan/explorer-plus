'use client';

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type KeyboardEvent as ReactKeyboardEvent,
  type MouseEvent as ReactMouseEvent,
  type ReactNode,
  type RefObject,
} from 'react';
import { createPortal } from 'react-dom';

import { MultiSelect, type MultiSelectOption } from './MultiSelect';
import { useProfileState, type ProfileAnswers } from './useProfileState';
import { DEFAULT_DOMAIN } from '../../contexts/DomainContext';
import { SCF_FRAMEWORK_REGISTRY } from '../../lib/scf-framework-registry';
import { PLATFORMS, SECTOR_SLUGS, type Platform, type SectorSlug } from '../../lib/profile-options';

/* ────────────────────────────────────────────────────────────────────────────
 * Option sources
 *
 * Every list below is DERIVED from the module/registry that already owns those
 * values — never hand-copied — so a change at the source either flows through
 * or fails `npm run typecheck`, rather than silently leaving the picker
 * offering values the API will 400 on.
 *
 * `PLATFORMS`/`SECTOR_SLUGS` come from src/lib/profile-options.ts, NOT from
 * app/api/v1/lib/validate.ts, even though that module is where the matching
 * zod schemas live: validate.ts imports zod, and dragging zod into a
 * 'use client' component on the homepage would cost ~13 KB gz of first-load
 * JS to read two arrays. validate.ts builds its enums from the same module,
 * so there is still exactly one source of truth.
 * ──────────────────────────────────────────────────────────────────────────── */

/** Presentation only: the 12 slugs come from `SECTOR_SLUGS`, these are the
 *  human labels for them. Typed as a total `Record` so adding a slug to the
 *  shared list without a label is a compile error. */
const SECTOR_LABELS: Record<SectorSlug, string> = {
  defense: 'Defense',
  education: 'Education',
  energy: 'Energy & Utilities',
  financial: 'Financial Services',
  government: 'Government',
  healthcare: 'Healthcare',
  manufacturing: 'Manufacturing',
  media: 'Media',
  retail: 'Retail',
  technology: 'Technology',
  telecommunications: 'Telecommunications',
  transportation: 'Transportation',
};

export const SECTOR_OPTIONS: ReadonlyArray<{ value: SectorSlug; label: string }> =
  SECTOR_SLUGS.map((slug) => ({ value: slug, label: SECTOR_LABELS[slug] }));

/**
 * The ICS half of `PLATFORMS`. Named and exported so the OT variant can take
 * this set directly (and the IT variant below its complement) instead of both
 * hand-maintaining a copy of the split that then drifts apart.
 *
 * `satisfies readonly Platform[]` is the guard: if ATT&CK renames one of these
 * in `PLATFORMS`, this list stops compiling instead of quietly excluding
 * nothing from the IT picker.
 */
export const ICS_PLATFORMS = [
  'Field Controller/RTU/PLC/IED',
  'Safety Instrumented System/Protection Relay',
  'Engineering Workstation',
  'Human-Machine Interface',
  'Control Server',
  'Data Historian',
  'Input/Output Server',
] as const satisfies readonly Platform[];

const ICS_PLATFORM_SET: ReadonlySet<string> = new Set<string>(ICS_PLATFORMS);

/** Enterprise + mobile platforms — `PLATFORMS` minus the ICS values. */
export const IT_PLATFORMS: Platform[] = PLATFORMS.filter((p) => !ICS_PLATFORM_SET.has(p));

/** The complement, for the OT variant. Derived here so the two never diverge. */
export const OT_PLATFORMS: Platform[] = PLATFORMS.filter((p) => ICS_PLATFORM_SET.has(p));

const PLATFORM_OPTIONS: MultiSelectOption[] = IT_PLATFORMS.map((p) => ({ value: p, label: p }));

/**
 * Roles have no source of truth in this repo — no table, no schema, no enum.
 * This is an authored shortlist, deliberately short: it exists to colour the
 * briefing's tone, not to partition the visitor population.
 */
export const ROLE_OPTIONS: MultiSelectOption[] = [
  { value: 'soc-detection', label: 'SOC / detection engineering' },
  { value: 'threat-intel', label: 'Threat intelligence' },
  { value: 'incident-response', label: 'Incident response' },
  { value: 'appsec', label: 'Application security' },
  { value: 'grc', label: 'GRC / compliance' },
  { value: 'red-team', label: 'Red team / offensive security' },
  { value: 'ot-engineering', label: 'OT / engineering' },
];

/**
 * Framework NAMES ONLY. The registry also carries `short_blurb`, `scope` and
 * friends, and none of it goes in here as `meta`: this list includes ISO, PCI
 * DSS, SOC 2, IEC 62443 and CIS Controls, whose text this project may not
 * reproduce. A picker label is a name, not licensed section text — so nothing
 * from `src/lib/framework-section-text.ts` is imported here, on purpose.
 */
const FRAMEWORK_OPTIONS: MultiSelectOption[] = SCF_FRAMEWORK_REGISTRY.map((f) => ({
  value: f.framework_key,
  label: f.name,
}));

/* ────────────────────────────────────────────────────────────────────────────
 * Telemetry
 * ──────────────────────────────────────────────────────────────────────────── */

/** Mirrors `submissionSchema.variant` in src/lib/profile-submit-schema.mjs. */
export type ProfileVariant = 'v1-4q' | 'v1-6q-ot';

type SubmitAction = 'apply' | 'dismiss' | 'auto_close';

const SUBMIT_ENDPOINT = '/api/v1/profile/submit';

interface ProfileSubmission {
  variant: ProfileVariant;
  action: SubmitAction;
  sectors: string[];
  platforms: string[];
  roles: string[];
  frameworks: string[];
  assets: string[];
  purdue_levels: string[];
}

/**
 * Fire-and-forget POST to the telemetry sink. `useProfileState` deliberately
 * does not do this (it has no `variant`), so it belongs to whoever mounts the
 * panel.
 *
 * Nothing here may ever reach the visitor: the endpoint is rate-limited and
 * can legitimately 429, it can be blocked by an extension, and it can throw
 * synchronously if `fetch` is unavailable. A failed submission costs us one
 * analytics row; a thrown one would break the panel.
 */
function reportSubmission(body: ProfileSubmission): void {
  try {
    void fetch(SUBMIT_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      // The dismiss/auto_close cases often coincide with the visitor
      // navigating away; keepalive lets the request outlive the page.
      keepalive: true,
    }).catch(() => {
      /* swallowed on purpose — see above */
    });
  } catch {
    /* swallowed on purpose — see above */
  }
}

/* ────────────────────────────────────────────────────────────────────────────
 * Controller
 * ──────────────────────────────────────────────────────────────────────────── */

const EMPTY_SELECTION: string[] = [];

export interface ThreatProfileController {
  /** Panel is on screen — either the unsolicited peek or a click-open. */
  open: boolean;
  /** True only once click-opened: modal, focus moves in and Tab is trapped. */
  modal: boolean;
  /**
   * True at xl+ (>=1280px) only, where the diamond sits beside the intro and
   * the panel can anchor to it. At 1024-1279 and below lg the diamond is
   * CENTRED, so the panel renders as a sheet instead — same reason the spec
   * gives for <lg, applied to the mid-size diamond as well.
   */
  anchored: boolean;
  onTriggerClick: (event: ReactMouseEvent<HTMLButtonElement>) => void;
  panelProps: Omit<ProfilePanelProps, 'anchored'>;
}

function useThreatProfile(variant: ProfileVariant): ThreatProfileController {
  const { answers, setAnswer, applyProfile, dismiss, peek } = useProfileState();
  // `peek` is a fresh object every render; `dispatch` inside it is stable.
  const { open, timer, report, dispatch } = peek;

  // Sector is single-select, so it lives here rather than in the hook's
  // multi-select `answers` bag, and reaches `applyProfile` as `string | null`.
  const [sector, setSector] = useState<string | null>(null);
  const [modal, setModal] = useState(false);
  const [anchored, setAnchored] = useState(false);
  const returnFocusRef = useRef<HTMLElement | null>(null);

  /**
   * Tailwind's `xl` breakpoint, read once and on change. Starts false so the
   * server render and the first client render agree; the panel cannot be open
   * on either (the peek is armed from a mount effect), so there is no flash.
   *
   * `80rem`, NOT `1280px`. Tailwind v4 emits `@media (width >= 80rem)` for
   * `xl` (verified against the compiled stylesheet), and `rem` in a media
   * query resolves against the BROWSER's default font size, not the document
   * root — so for anyone who raised that default the two units disagree.
   * `anchored` would then go true while `hidden xl:block` still hides the
   * wrapper: the panel would render inside a `display:none` container,
   * `ProfileSheet` would bail, the visible diamond would do nothing, and a
   * cold load would still post a phantom `auto_close`. Same unit as the
   * utility is the only way these cannot drift.
   */
  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return undefined;
    const mql = window.matchMedia('(min-width: 80rem)');
    const sync = () => setAnchored(mql.matches);
    sync();
    mql.addEventListener('change', sync);
    return () => mql.removeEventListener('change', sync);
  }, []);

  // A closed panel is never modal — so the next unsolicited peek (next cold
  // visit after an auto_close) is non-modal again.
  useEffect(() => {
    if (!open) setModal(false);
  }, [open]);

  // Latest payload, kept in a ref so the outcome effect below depends only on
  // `report` and therefore cannot re-fire when an answer changes.
  const payloadRef = useRef<Pick<ProfileSubmission, 'sectors' | 'platforms' | 'roles' | 'frameworks'>>({
    sectors: [],
    platforms: [],
    roles: [],
    frameworks: [],
  });
  useEffect(() => {
    payloadRef.current = {
      sectors: sector ? [sector] : [],
      platforms: answers.platforms ?? [],
      roles: answers.roles ?? [],
      frameworks: answers.frameworks ?? [],
    };
  }, [sector, answers]);

  /**
   * Exactly one POST per outcome TRANSITION — not one per session and not one
   * per render. A session can legitimately produce two outcomes (peek expires
   * -> auto_close; visitor later clicks the diamond and applies), and
   * 'CLICK_OPEN' resets `report` to null in between, so the guard compares
   * against the last reported value instead of latching a boolean. Re-renders
   * leave `report` unchanged and therefore re-post nothing.
   */
  const lastReportRef = useRef<SubmitAction | null>(null);
  useEffect(() => {
    const next = report ?? null;
    if (next === lastReportRef.current) return;
    lastReportRef.current = next;
    if (!next) return;
    const payload = payloadRef.current;
    reportSubmission({
      variant,
      action: next,
      sectors: payload.sectors,
      platforms: payload.platforms,
      roles: payload.roles,
      frameworks: payload.frameworks,
      // Not asked in this variant. Sent explicitly rather than omitted so the
      // row shape is identical across variants.
      assets: [],
      purdue_levels: [],
    });
  }, [report, variant]);

  /**
   * Put the popover away without recording anything. A visitor clicking the
   * diamond a second time is toggling a disclosure shut, not rejecting the
   * feature — `dismiss()` would write a `dismiss` row AND set `mx-profile`,
   * silently costing them the peek for good. 'TOGGLE_CLOSE' reports null, so
   * neither happens.
   *
   * The flag guards the gesture's second half. This runs from the scrim's
   * `pointerdown`, and the scrim is unmounted before the matching `mouseup`,
   * so whether the resulting `click` is then delivered to the diamond
   * underneath is engine detail (the press target is detached, so there may be
   * no common ancestor and therefore no click at all). If it IS delivered,
   * `modal` is already false again and the trigger would re-open what was just
   * toggled shut. Rather than bet on the behaviour, swallow exactly one
   * trigger click and release the flag on the next click wherever it lands —
   * including the common case where none reaches the diamond.
   */
  const suppressTriggerClickRef = useRef(false);
  const releaseTriggerClick = useCallback(() => {
    suppressTriggerClickRef.current = false;
  }, []);

  const onToggleClose = useCallback(() => {
    suppressTriggerClickRef.current = true;
    document.addEventListener('click', releaseTriggerClick, { once: true });
    dispatch({ type: 'TOGGLE_CLOSE' });
  }, [dispatch, releaseTriggerClick]);

  const onTriggerClick = useCallback(
    (event: ReactMouseEvent<HTMLButtonElement>) => {
      // Tail of a toggle-close gesture that the scrim already handled.
      if (suppressTriggerClickRef.current) {
        suppressTriggerClickRef.current = false;
        return;
      }
      // Already click-opened: this is the toggle-shut half of the disclosure.
      // Gated on `modal`, not `open` — a click DURING an unsolicited peek must
      // still promote it to a real click-open, not close it.
      if (modal) {
        dispatch({ type: 'TOGGLE_CLOSE' });
        return;
      }
      // Read the node synchronously — `currentTarget` is cleared once the
      // event finishes dispatching. Focus returns here when the panel closes.
      returnFocusRef.current = event.currentTarget;
      setModal(true);
      dispatch({ type: 'CLICK_OPEN' });
    },
    [dispatch, modal],
  );

  const onInteract = useCallback(() => {
    // 'INTERACT' always returns a new state object, so dispatching it on every
    // keystroke once the timer is already cancelled would churn renders for
    // nothing. The timer is only ever armed once, so this is a permanent stop.
    if (timer == null) return;
    dispatch({ type: 'INTERACT' });
  }, [timer, dispatch]);

  const onApply = useCallback(() => {
    // One action, one push — `applyProfile` owns the single router.replace.
    applyProfile({ sector, domain: DEFAULT_DOMAIN });
  }, [applyProfile, sector]);

  const onClose = useCallback(() => {
    dismiss();
  }, [dismiss]);

  const panelProps = useMemo<Omit<ProfilePanelProps, 'anchored'>>(
    () => ({
      modal,
      sector,
      onSectorChange: setSector,
      answers,
      setAnswer,
      onApply,
      onClose,
      onToggleClose,
      onInteract,
      returnFocusRef,
    }),
    [modal, sector, answers, setAnswer, onApply, onClose, onToggleClose, onInteract],
  );

  return { open, modal, anchored, onTriggerClick, panelProps };
}

/* ────────────────────────────────────────────────────────────────────────────
 * Provider + the three mount points
 *
 * One controller, shared. The three hero diamonds are mutually exclusive by
 * breakpoint but ALL THREE stay mounted (they are hidden with `display:none`),
 * so giving each its own hook would arm three peek timers and post three
 * telemetry rows for one visitor.
 * ──────────────────────────────────────────────────────────────────────────── */

const ThreatProfileCtx = createContext<ThreatProfileController | null>(null);

/**
 * Mount this ONLY around the tree that actually shows the diamonds. The peek
 * timer arms on mount and reports `auto_close` when it expires, so mounting it
 * on a view where no panel is visible would post outcomes for a panel the
 * visitor was never shown.
 */
export function ThreatProfileProvider({
  variant,
  children,
}: {
  variant: ProfileVariant;
  children: ReactNode;
}) {
  const controller = useThreatProfile(variant);
  return <ThreatProfileCtx.Provider value={controller}>{children}</ThreatProfileCtx.Provider>;
}

function useController(): ThreatProfileController | null {
  return useContext(ThreatProfileCtx);
}

/**
 * The hero diamond, as a trigger. Drops `pointer-events-none` for the BUTTON
 * only — the four corner labels around it stay non-interactive, in all three
 * blocks. `focus-visible` gets the same nudge as `hover` so keyboard users see
 * the affordance.
 *
 * Reduced motion is handled by `.profile-diamond-img` in src/index.css, NOT by
 * a `motion-reduce:` utility. Tailwind v4 compiles `-translate-y-[3px]` to
 * `translate:` and `scale-[1.02]` to `scale:`, while `transform-none` emits
 * `transform: none` — a different property, so the utility the brief specified
 * cancels nothing (verified by compiling the utilities and reading the
 * output). The stylesheet rule neutralises `translate`/`scale`/`transition`
 * themselves. `motion-reduce:group-hover:opacity-90` stays: opacity is not a
 * transform and is a legitimate reduced-motion affordance.
 */
export function ProfileDiamondTrigger({ size }: { size: number }) {
  const ctl = useController();

  if (!ctl) {
    // Rendered outside a provider: keep the decoration, lose the affordance.
    return <img src="/diamond-favicon.svg" alt="" width={size} height={size} className="opacity-[0.55]" />;
  }

  return (
    <button
      type="button"
      data-profile-trigger=""
      onClick={ctl.onTriggerClick}
      aria-haspopup="dialog"
      aria-expanded={ctl.open}
      aria-label="Tailor this to what you defend"
      className="block pointer-events-auto group rounded-lg focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-[var(--accent-teal)]"
    >
      <img
        src="/diamond-favicon.svg"
        alt=""
        width={size}
        height={size}
        className="profile-diamond-img opacity-[0.55] transition-transform duration-150 ease-out
                   group-hover:-translate-y-[3px] group-hover:scale-[1.02] group-hover:opacity-80
                   group-focus-visible:-translate-y-[3px] group-focus-visible:scale-[1.02]
                   motion-reduce:group-hover:opacity-90"
      />
    </button>
  );
}

/** Place inside the xl diamond's existing `relative` wrapper. Renders nothing
 *  below xl, where `ProfileSheet` takes over. */
export function ProfileAnchoredPanel() {
  const ctl = useController();
  if (!ctl || !ctl.open || !ctl.anchored) return null;
  return <ProfilePanel anchored {...ctl.panelProps} />;
}

/** The below-xl sheet. Portalled to `document.body` so neither the diamond
 *  wrappers' `pointer-events-none` nor any transformed ancestor can alter its
 *  fixed positioning. */
export function ProfileSheet() {
  const ctl = useController();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  if (!mounted || !ctl || !ctl.open || ctl.anchored) return null;
  return createPortal(<ProfilePanel anchored={false} {...ctl.panelProps} />, document.body);
}

/* ────────────────────────────────────────────────────────────────────────────
 * The panel
 * ──────────────────────────────────────────────────────────────────────────── */

export interface ProfilePanelProps {
  /** Absolutely positioned against the diamond (xl+) vs. a centred sheet. */
  anchored: boolean;
  /** Click-opened: focus moves in, Tab is trapped, the background is marked
   *  `inert`, and `aria-modal="true"` is therefore true rather than claimed. */
  modal: boolean;
  sector: string | null;
  onSectorChange: (next: string | null) => void;
  answers: ProfileAnswers;
  setAnswer: (key: string, value: string[]) => void;
  onApply: () => void;
  /** Rejection: reports `dismiss` and sets the dismissal flag. */
  onClose: () => void;
  /** Toggle shut from the trigger: reports nothing, sets no flag. */
  onToggleClose: () => void;
  onInteract: () => void;
  returnFocusRef: RefObject<HTMLElement | null>;
}

const ANCHORED_WIDTH = 380;
const ANCHOR_GAP = 16;

const FOCUSABLE_SELECTOR = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',');

function hasLayoutBox(el: unknown): el is HTMLElement {
  return el instanceof HTMLElement && el.isConnected && el.getClientRects().length > 0;
}

function focusableWithin(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter(hasLayoutBox);
}

/**
 * Where focus goes when a click-opened panel closes.
 *
 * The trigger that opened it can have become `display:none` in the meantime —
 * crossing the xl breakpoint while open swaps which of the three diamonds is
 * rendered — and `focus()` on a hidden element silently no-ops, dropping focus
 * to `<body>`. Fall back to whichever trigger is actually on screen.
 */
function resolveReturnTarget(stored: HTMLElement | null): HTMLElement | null {
  if (hasLayoutBox(stored)) return stored;
  for (const el of Array.from(document.querySelectorAll<HTMLElement>('[data-profile-trigger]'))) {
    if (hasLayoutBox(el)) return el;
  }
  return null;
}

/**
 * Whether a pointerdown belongs to a diamond trigger.
 *
 * `closest()` alone is not enough once the modal scrim is in play: the scrim
 * covers the whole viewport, so the trigger is never the event target and the
 * trigger exemption would be unreachable — a click on the diamond to toggle
 * the popover shut would fall through to the outside-click path and be
 * recorded as a rejection. Fall back to hit-testing the pointer against each
 * visible trigger's rect, which works uniformly for the anchored panel and for
 * the portalled sheet (whose trigger is not even a DOM sibling of the panel).
 */
function pointerIsOverTrigger(target: Element | null, x: number, y: number): boolean {
  if (target && typeof target.closest === 'function' && target.closest('[data-profile-trigger]')) {
    return true;
  }
  for (const el of Array.from(document.querySelectorAll<HTMLElement>('[data-profile-trigger]'))) {
    if (!hasLayoutBox(el)) continue;
    const r = el.getBoundingClientRect();
    if (x >= r.left && x <= r.right && y >= r.top && y <= r.bottom) return true;
  }
  return false;
}

/**
 * The nearest ancestor that actually clips and scrolls the anchored panel.
 * On this site that is `<main>` (AppShell.tsx: `overflow-y-auto
 * overflow-x-hidden`), not the viewport — measuring against
 * `window.innerWidth/innerHeight` would let the panel be positioned into a
 * region `<main>` then clips away.
 */
function clippingAncestor(el: HTMLElement): HTMLElement | null {
  let node: HTMLElement | null = el.parentElement;
  while (node && node !== document.body && node !== document.documentElement) {
    const style = getComputedStyle(node);
    if (/(auto|scroll|hidden|clip)/.test(`${style.overflowX} ${style.overflowY}`)) return node;
    node = node.parentElement;
  }
  return null;
}

export function ProfilePanel({
  anchored,
  modal,
  sector,
  onSectorChange,
  answers,
  setAnswer,
  onApply,
  onClose,
  onToggleClose,
  onInteract,
  returnFocusRef,
}: ProfilePanelProps) {
  const panelRef = useRef<HTMLDivElement>(null);
  const wasModalRef = useRef(modal);
  const baseId = useId();
  const titleId = `${baseId}-title`;
  const statusId = `${baseId}-status`;
  const sectorId = `${baseId}-sector`;
  const ready = Boolean(sector);

  const [flipX, setFlipX] = useState<'left' | 'right'>('left');
  const [flipY, setFlipY] = useState<'top' | 'bottom'>('top');

  /**
   * Focus moves in only once click-opened. The peek is UNSOLICITED: taking
   * focus from a visitor mid-sentence in the search field is exactly the
   * WCAG 2.4.3 failure this panel must not commit, so in peek mode nothing
   * here touches focus at all.
   *
   * This also re-establishes the trap after an anchored<->sheet flip: crossing
   * the breakpoint while open unmounts one instance and mounts another in the
   * same commit, and the new instance runs this effect with `modal` already
   * true.
   */
  useEffect(() => {
    wasModalRef.current = modal;
    if (modal) panelRef.current?.focus();
  }, [modal]);

  /**
   * Make `aria-modal="true"` true rather than merely claimed. A Tab trap alone
   * still leaves the background reachable by a screen reader's virtual cursor,
   * by pointer and by browser find — so asserting modality without this was
   * telling assistive tech something false.
   *
   * Marks every SIBLING along the panel's ancestor chain `inert`, which is how
   * you inert "everything except this subtree": the panel's own ancestors stay
   * live, so the panel is unaffected. Outside-click still works — hit testing
   * skips inert subtrees and resolves to the nearest live ancestor, which is
   * never inside the panel.
   *
   * Declared BEFORE the focus-return effect on purpose. React runs a
   * component's cleanups in hook declaration order, and the diamond focus is
   * handed back to is itself one of the siblings marked here — so `inert` has
   * to come off first or the `focus()` would be refused.
   */
  useEffect(() => {
    if (!modal) return undefined;
    const root = panelRef.current;
    if (!root) return undefined;
    const marked: HTMLElement[] = [];
    let node: HTMLElement | null = root;
    while (node && node !== document.body) {
      const parent: HTMLElement | null = node.parentElement;
      if (!parent) break;
      for (const sibling of Array.from(parent.children)) {
        if (sibling === node || !(sibling instanceof HTMLElement)) continue;
        // The sheet's own scrim is a portal sibling of the panel. Leave it
        // live: it is already `aria-hidden`, and it is the element an
        // outside-click lands on, which must keep working whatever a given
        // engine does with pointer events over inert content.
        if (sibling.hasAttribute('data-profile-scrim')) continue;
        // Already inert for someone else's reason — not ours to restore.
        if (sibling.hasAttribute('inert')) continue;
        sibling.setAttribute('inert', '');
        marked.push(sibling);
      }
      node = parent;
    }
    return () => {
      for (const el of marked) el.removeAttribute('inert');
    };
  }, [modal]);

  // Return focus to the diamond that opened it — but only if it WAS
  // click-opened. Pulling focus back after a peek nobody asked for would be
  // the same WCAG failure in reverse.
  useEffect(
    () => () => {
      if (!wasModalRef.current) return;
      resolveReturnTarget(returnFocusRef.current)?.focus();
    },
    [returnFocusRef],
  );

  /**
   * Outside-click dismissal, modal only. In peek mode this would fire on the
   * visitor's very first click anywhere on the page — most obviously into the
   * search field — and record a `dismiss` for a panel they never engaged with,
   * corrupting the one ratio this whole feature is judged on. An untouched
   * peek closes on its timer as `auto_close`; that is the honest outcome.
   */
  useEffect(() => {
    if (!modal) return undefined;
    function handlePointerDown(event: PointerEvent) {
      const target = event.target as Element | null;
      if (panelRef.current?.contains(target)) return;
      // A click on the diamond is the disclosure toggling itself shut, not a
      // rejection of the feature — route it to the silent path so it writes no
      // `dismiss` row and does not set the dismissal flag.
      if (pointerIsOverTrigger(target, event.clientX, event.clientY)) {
        onToggleClose();
        return;
      }
      onClose();
    }
    document.addEventListener('pointerdown', handlePointerDown);
    return () => document.removeEventListener('pointerdown', handlePointerDown);
  }, [modal, onClose, onToggleClose]);

  /**
   * Escape net for focus OUTSIDE the trap (e.g. left on `<body>`).
   *
   * The bail-out when focus is INSIDE is load-bearing, not defensive. This
   * listener sits on `document` — and so does React's delegated keydown
   * listener, because Next's App Router hydrates `document` itself. Two
   * listeners on the SAME node are unaffected by `stopPropagation()`; only
   * `stopImmediatePropagation()` would suppress the second. So without this
   * guard, every Escape used to close a `MultiSelect` listbox (MultiSelect
   * swallows the key with `stopPropagation()`) would ALSO close the whole
   * panel, post a bogus `dismiss` row and call `markProfileSeen()` — leaving
   * `mx-profile` set so the visitor never peeks again.
   *
   * The alternative — switching MultiSelect to `stopImmediatePropagation` —
   * would fix it by coupling two components through event-dispatch internals.
   * The guard is local and says what it means.
   */
  useEffect(() => {
    if (!modal) return undefined;
    function handleKey(event: KeyboardEvent) {
      if (event.key !== 'Escape') return;
      const root = panelRef.current;
      if (root && root.contains(document.activeElement)) return;
      onClose();
    }
    document.addEventListener('keydown', handleKey);
    return () => document.removeEventListener('keydown', handleKey);
  }, [modal, onClose]);

  /**
   * Keep the anchored panel inside the box that actually clips it.
   *
   * Three things the first cut got wrong: it measured the viewport rather than
   * `<main>` (the real scroll/clip container); it never recomputed when the
   * container scrolled or the panel's own height changed (adding chips to a
   * combobox resizes it); and when NEITHER side had room it fell through to
   * 'left' and hung off-screen instead of taking the roomier side.
   */
  useEffect(() => {
    if (!anchored) return undefined;
    const el = panelRef.current;
    if (!el) return undefined;
    const container = clippingAncestor(el);

    function compute() {
      const node = panelRef.current;
      const anchor = node?.offsetParent as HTMLElement | null;
      if (!node || !anchor) return;
      const rect = anchor.getBoundingClientRect();
      const bounds = container
        ? container.getBoundingClientRect()
        : { left: 0, right: window.innerWidth, top: 0, bottom: window.innerHeight };

      const needed = ANCHORED_WIDTH + ANCHOR_GAP;
      const roomLeft = rect.left - bounds.left;
      const roomRight = bounds.right - rect.right;
      if (roomLeft >= needed) setFlipX('left');
      else if (roomRight >= needed) setFlipX('right');
      else setFlipX(roomLeft >= roomRight ? 'left' : 'right');

      // 'top' aligns the panel's top with the anchor's and grows down;
      // 'bottom' aligns their bottoms and grows up.
      const height = node.offsetHeight;
      const roomBelow = bounds.bottom - rect.top;
      const roomAbove = rect.bottom - bounds.top;
      if (height + 8 <= roomBelow) setFlipY('top');
      else setFlipY(roomBelow >= roomAbove ? 'top' : 'bottom');
    }

    compute();

    // The panel's own height changes as combobox chips are added/removed.
    const observer = typeof ResizeObserver === 'function' ? new ResizeObserver(compute) : null;
    observer?.observe(el);

    window.addEventListener('resize', compute);
    window.addEventListener('scroll', compute, { passive: true });
    container?.addEventListener('scroll', compute, { passive: true });
    return () => {
      observer?.disconnect();
      window.removeEventListener('resize', compute);
      window.removeEventListener('scroll', compute);
      container?.removeEventListener('scroll', compute);
    };
  }, [anchored]);

  const anchoredStyle: CSSProperties | undefined = anchored
    ? {
        position: 'absolute',
        width: ANCHORED_WIDTH,
        // Above the sidebar (Sidebar.tsx: `fixed … z-50`) and its scrim below,
        // so no fixed chrome is ever painted over the scrim — see the scrim's
        // note. Still under the AppShell help/API overlays at `z-[100]`, which
        // are genuinely higher-priority.
        zIndex: 61,
        ...(flipX === 'left'
          ? { right: `calc(100% + ${ANCHOR_GAP}px)` }
          : { left: `calc(100% + ${ANCHOR_GAP}px)` }),
        ...(flipY === 'top' ? { top: 0 } : { bottom: 0 }),
      }
    : undefined;

  function handleKeyDown(event: ReactKeyboardEvent<HTMLDivElement>) {
    onInteract();

    if (event.key === 'Escape') {
      // Stops ancestor React handlers reacting to the same keypress. It does
      // NOT suppress the document-level net above — that listener shares a
      // node with React's own delegated one — which is why the net checks
      // whether focus is inside the panel instead of relying on this.
      event.stopPropagation();
      onClose();
      return;
    }

    if (event.key !== 'Tab' || !modal) return;

    const root = panelRef.current;
    if (!root) return;
    const items = focusableWithin(root);
    if (items.length === 0) {
      event.preventDefault();
      root.focus();
      return;
    }
    const first = items[0];
    const last = items[items.length - 1];
    const active = document.activeElement as HTMLElement | null;
    if (event.shiftKey) {
      if (active === first || active === root || !active || !root.contains(active)) {
        event.preventDefault();
        last.focus();
      }
    } else if (active === last) {
      event.preventDefault();
      first.focus();
    }
  }

  function handleApply() {
    // No silent defaults: an unanswered load-bearing question is never filled
    // in on the visitor's behalf.
    if (!ready) return;
    onApply();
  }

  const shellClass = anchored
    ? 'pointer-events-auto select-text flex flex-col rounded-xl border border-[var(--border-color)] bg-[var(--surface-card)] shadow-2xl focus:outline-none'
    : 'pointer-events-auto select-text fixed inset-x-0 bottom-0 z-[61] mx-auto flex w-full max-h-[85vh] flex-col rounded-t-2xl border-t border-x border-[var(--border-color)] bg-[var(--surface-card)] shadow-2xl focus:outline-none sm:max-w-[560px]';

  return (
    <>
      {/* Scrim — CLICK-OPENED ONLY. The peek never gets one: it is explicitly
          `aria-modal="false"`, and capturing clicks would interrupt a visitor
          typing in the search field, which is the one thing it must not do.

          The anchored variant is FULLY TRANSPARENT — no dim, no blur, nothing
          visible. It is a popover, not a page-blocking modal. Its only job is
          to own the pointer, so an outside click always lands on a live
          element and the close path never depends on how a given engine
          treats pointer events over `inert` content (retarget vs. suppress —
          not something that can be settled without real browsers). `inert`
          keeps owning focus and AT; the scrim owns the pointer. The sheet's
          scrim keeps its dim, since a sheet does read as modal.

          Rendered as a SIBLING of the panel rather than portalled: sharing a
          parent means the z-order (60 under the panel's 61) is decided in one
          stacking context and cannot be inverted by an ancestor, which would
          leave the panel itself unclickable. `pointer-events-auto` because the
          xl diamond's wrapper is `pointer-events-none`. Excluded from the
          `inert` walk above by `data-profile-scrim`.

          60/61 rather than 40/50 because the sidebar is `fixed … z-50`
          (Sidebar.tsx) and would otherwise paint its ~208px over a z-40
          scrim, leaving a strip where a pointerdown lands on inert content —
          exactly the dependency this scrim exists to remove. Audited the rest
          of the layout for fixed elements at z>=40: the mobile drawer
          backdrop (z-40, `lg:hidden`, only while the drawer is open), the
          graph tooltip (z-50 but `pointer-events-none`), and the AppShell
          help/API and VT overlays at `z-[100]` — the last of which stay above
          us deliberately, being higher-priority full-page modals.

          A pointerdown on the scrim goes to the document listener above: over
          a diamond it routes to the silent toggle path, anywhere else it is an
          ordinary outside click and calls the same `dismiss` as before. No new
          telemetry action, no handler on the scrim itself. */}
      {modal && (
        <div
          data-profile-scrim=""
          aria-hidden="true"
          className={
            anchored
              ? 'fixed inset-0 z-[60] pointer-events-auto'
              : 'fixed inset-0 z-[60] bg-black/30'
          }
        />
      )}

      <div
        ref={panelRef}
        role="dialog"
        aria-modal={modal}
        aria-labelledby={titleId}
        tabIndex={-1}
        style={anchoredStyle}
        className={shellClass}
        onPointerEnter={onInteract}
        onFocus={onInteract}
        onKeyDown={handleKeyDown}
      >
        <div className="flex items-start justify-between gap-3 px-4 pt-4 pb-2">
          <div className="min-w-0">
            <h2 id={titleId} className="text-sm font-semibold text-[var(--text-primary)]">
              Tailor this to what you defend
            </h2>
            <p className="mt-0.5 text-xs text-[var(--text-secondary)]">
              Four questions. Only the sector is required — nothing is answered for you.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="shrink-0 flex items-center justify-center min-h-[44px] min-w-[44px] -mt-2 -mr-2 rounded-md text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--hover-overlay)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-teal)] transition-colors"
          >
            <span aria-hidden="true" className="text-lg leading-none">
              ×
            </span>
          </button>
        </div>

        <div className="flex flex-col gap-4 overflow-y-auto px-4 py-3 max-h-[min(60vh,420px)]" onScroll={onInteract}>
          {/* Sector is the load-bearing answer and is single-select, so it is a
              real single-select control. `MultiSelect` advertises
              aria-multiselectable="true" on its listbox, which would misreport
              this question to assistive tech; 12 options also need no search.
              A native <select> is what the sidebar's sector filter already
              uses (src/components/layout/SectorDropdown.tsx). */}
          <div>
            <label htmlFor={sectorId} className="block text-xs font-medium text-[var(--text-secondary)] mb-1">
              Sector you defend <span className="text-[var(--text-secondary)]">(required)</span>
            </label>
            <select
              id={sectorId}
              value={sector ?? ''}
              onChange={(e) => onSectorChange(e.target.value || null)}
              aria-describedby={statusId}
              className="w-full min-h-[44px] px-2 rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] text-sm text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent-teal)] focus-visible:ring-2 focus-visible:ring-[var(--accent-teal)] transition-colors"
            >
              <option value="">Select a sector…</option>
              {SECTOR_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </div>

          <MultiSelect
            id={`${baseId}-platforms`}
            label="Environment"
            options={PLATFORM_OPTIONS}
            selected={answers.platforms ?? EMPTY_SELECTION}
            onChange={(next) => setAnswer('platforms', next)}
            placeholder="Windows, SaaS, Containers…"
          />

          <MultiSelect
            id={`${baseId}-roles`}
            label="Your role"
            options={ROLE_OPTIONS}
            selected={answers.roles ?? EMPTY_SELECTION}
            onChange={(next) => setAnswer('roles', next)}
            placeholder="Search roles…"
          />

          <MultiSelect
            id={`${baseId}-frameworks`}
            label="Compliance regime"
            options={FRAMEWORK_OPTIONS}
            selected={answers.frameworks ?? EMPTY_SELECTION}
            onChange={(next) => setAnswer('frameworks', next)}
            placeholder="Search frameworks…"
          />
        </div>

        <div className="flex items-center justify-between gap-3 border-t border-[var(--border-color)] px-4 py-3">
          <p
            id={statusId}
            aria-live="polite"
            className={`text-xs font-medium ${ready ? 'text-[var(--accent-green)]' : 'text-[var(--accent-yellow)]'}`}
          >
            {ready ? 'Ready' : 'Pick at least one sector'}
          </p>
          <button
            type="button"
            onClick={handleApply}
            // aria-disabled, not `disabled`: a disabled button leaves the tab
            // order, so a keyboard visitor could neither reach it nor be told
            // by `aria-describedby` why it will not fire yet.
            aria-disabled={!ready}
            aria-describedby={statusId}
            className={`shrink-0 min-h-[44px] px-4 rounded-md text-sm font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-teal)] ${
              ready
                ? 'bg-[var(--accent-teal)] text-[var(--surface-card)] hover:opacity-90'
                : 'bg-[var(--surface-alt)] text-[var(--text-secondary)] cursor-not-allowed'
            }`}
          >
            Apply
          </button>
        </div>
      </div>
    </>
  );
}
