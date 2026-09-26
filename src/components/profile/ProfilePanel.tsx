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
import { PurdueAssetPickerLoader } from './PurdueAssetPicker';
import { useProfileState, type ProfileAnswers } from './useProfileState';
import { DEFAULT_DOMAIN } from '../../contexts/DomainContext';
import { SCF_FRAMEWORK_REGISTRY } from '../../lib/scf-framework-registry';
import { SECTOR_OPTIONS, ICS_PLATFORMS, IT_PLATFORMS } from '../../lib/profile-options';

/* ─────────────────────────────────────────────────────────────────────────────
 * Option sources
 *
 * Every list below is DERIVED from the module/registry that already owns those
 * values — never hand-copied — so a change at the source either flows through
 * or fails `npm run typecheck`, rather than silently leaving the picker
 * offering values the API will 400 on.
 *
 * The sector and platform lists come from src/lib/profile-options.ts, NOT from
 * app/api/v1/lib/validate.ts, even though that module is where the matching
 * zod schemas live: validate.ts imports zod, and dragging zod into a
 * 'use client' component on the homepage would cost ~13 KB gz of first-load
 * JS to read two arrays. validate.ts builds its enums from the same module,
 * so there is still exactly one source of truth.
 *
 * They were DEFINED here until /profile needed them as well. Importing this
 * module to read them pulled `SCF_FRAMEWORK_REGISTRY` (254 entries, below)
 * into that page's bundle for nothing, so the definitions moved down to
 * profile-options.ts — which is exactly the module for plain shared value
 * lists — and are re-exported here unchanged. Every existing importer of
 * `SECTOR_OPTIONS`/`ICS_PLATFORMS`/`IT_PLATFORMS` from this file keeps
 * working; nothing about the panel's behaviour changes. `OT_PLATFORMS` is
 * gone — all seven ICS platform values match ZERO live techniques, so the OT
 * path asks about assets and Purdue levels instead and there is no list to
 * re-export.
 * ───────────────────────────────────────────────────────────────────────────── */

export { SECTOR_OPTIONS, ICS_PLATFORMS, IT_PLATFORMS };

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

/**
 * Which ENGINE the visitor is answering for. A mode, not a fifth question: it
 * decides which questions follow, so it is rendered as a two-option control at
 * the top of the panel rather than as another dropdown among them.
 *
 * 'it' -> domain `enterprise-attack`, ranked on sector lift and CTI/CVE evidence.
 * 'ot' -> domain `ics-attack`, ranked on the visitor's ATT&CK ICS asset surface.
 *
 * Until this existed nothing in the app could produce an OT briefing at all:
 * the provider hardcoded `v1-4q` and Apply hardcoded `DEFAULT_DOMAIN`, so the
 * ICS engine — which is built, measured and tested — was unreachable.
 */
export type ProfileMode = 'it' | 'ot';

/**
 * The telemetry variant string for a mode.
 *
 * `'v1-6q-ot'` keeps its digit even though the OT panel renders THREE controls
 * (plant surface, role, compliance regime).
 * It is a CHECK-constraint value on `profile_submissions.variant`; migrating a
 * constraint for a cosmetic digit would be a schema change to make a string
 * read nicer. Treat it as an opaque id.
 */
function variantFor(mode: ProfileMode): ProfileVariant {
  return mode === 'ot' ? 'v1-6q-ot' : 'v1-4q';
}

/** ATT&CK domain for a mode. The OT branch of the assembler fires on
 *  `domain=ics-attack` ALONE, so this is the whole switch. */
function domainFor(mode: ProfileMode, defaultDomain: string): string {
  return mode === 'ot' ? 'ics-attack' : defaultDomain;
}

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
  /**
   * Open as the LARGE centred modal, from the sidebar entry — the third
   * presentation, available on every page. Outranks `anchored`: while this
   * is true neither the anchored popover nor the sheet renders, so the same
   * controller never has two presentations on screen at once.
   */
  large: boolean;
  /**
   * The diamond should make its small "about to take this back" movement
   * now — the last ~250ms of an unsolicited peek. Always false for a
   * click-opened panel (no timer) and for a peek that has been cancelled.
   */
  peekNudge: boolean;
  /** Arm the unsolicited peek. Called ONLY from the homepage landing state
   *  (see `ProfilePeekArmer`) — mounting the provider must not peek. */
  armPeek: () => void;
  onTriggerClick: (event: ReactMouseEvent<HTMLButtonElement>) => void;
  /** The sidebar entry. Same questions, same telemetry, larger modal. */
  onSidebarTriggerClick: (event: ReactMouseEvent<HTMLButtonElement>) => void;
  /**
   * Called by each NON-LARGE presentation for as long as it is mounted, and
   * returns its own unregister. When the last one goes, an open non-large
   * panel is closed silently — see `registerPresentation` in the controller.
   */
  registerPresentation: () => () => void;
  panelProps: Omit<ProfilePanelProps, 'anchored' | 'large'>;
}

function useThreatProfile(defaultVariant: ProfileVariant): ThreatProfileController {
  const { answers, setAnswer, applyProfile, dismiss, armPeek, peek, peekNudge } = useProfileState();
  // `peek` is a fresh object every render; `dispatch` inside it is stable.
  const { open, timer, report, dispatch } = peek;

  /**
   * The engine switch, defaulting to IT and VISIBLY selected in the panel.
   *
   * The mount point still passes a variant, and it is now the DEFAULT mode
   * rather than the only one — which is the point: `variant="v1-4q"` in
   * AppShell used to be an invisible hardcode that no visitor could see or
   * change, and the ICS engine was unreachable behind it. The same value now
   * seeds a control that shows what was chosen for you and lets you choose
   * otherwise.
   */
  const [mode, setMode] = useState<ProfileMode>(defaultVariant === 'v1-6q-ot' ? 'ot' : 'it');
  const variant = variantFor(mode);

  // Sector is single-select, so it lives here rather than in the hook's
  // multi-select `answers` bag, and reaches `applyProfile` as `string | null`.
  // It is asked in IT mode ONLY — see `onApply`.
  const [sector, setSector] = useState<string | null>(null);
  const [modal, setModal] = useState(false);
  const [large, setLarge] = useState(false);
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

  // A closed panel is never modal, and never large — so the next unsolicited
  // peek (next cold visit after an auto_close) is a non-modal popover again
  // rather than inheriting the sidebar's presentation.
  useEffect(() => {
    if (!open) {
      setModal(false);
      setLarge(false);
    }
  }, [open]);

  /**
   * Presentation presence, and the silent close that follows it.
   *
   * The two non-large presentations (`ProfileAnchoredPanel`, `ProfileSheet`)
   * are mounted by the homepage's landing branch, while this controller lives
   * in AppShell and survives it. Selecting an entity mid-peek therefore took
   * the panel off the screen while leaving `open` and `modal` true, with two
   * visible consequences: the peek timer ran on and `EXPIRE` still posted an
   * `auto_close` row for a panel that had left the screen after ~1s, and the
   * next click on the sidebar entry hit `openFromTrigger`'s `if (modal)`
   * branch and did nothing at all, so the visitor had to click it twice.
   *
   * A counter rather than a boolean because both presentations are mounted
   * together on the homepage (only one renders non-null, by breakpoint), and
   * only when the LAST of them goes has the state lost its presentation.
   *
   * `TOGGLE_CLOSE`, not `CLOSE`: nobody rejected anything, so this must not
   * write a telemetry row and must not set the dismissal flag — the same
   * reasoning the diamond's second click already gets. `large` is checked
   * because `ProfileLargeModal` is mounted app-wide in AppShell and does not
   * register here: a sidebar-opened modal is not affected by the homepage's
   * branch unmounting underneath it.
   */
  const presentationsRef = useRef(0);
  const openRef = useRef(open);
  const largeRef = useRef(large);
  useEffect(() => {
    openRef.current = open;
    largeRef.current = large;
  }, [open, large]);

  const registerPresentation = useCallback(() => {
    presentationsRef.current += 1;
    return () => {
      presentationsRef.current = Math.max(0, presentationsRef.current - 1);
      if (presentationsRef.current === 0 && openRef.current && !largeRef.current) {
        dispatch({ type: 'TOGGLE_CLOSE' });
      }
    };
  }, [dispatch]);

  // Latest payload, kept in a ref so the outcome effect below depends only on
  // `report` and therefore cannot re-fire when an answer changes.
  type ReportedAnswers = Omit<ProfileSubmission, 'variant' | 'action'>;
  const payloadRef = useRef<ReportedAnswers>({
    sectors: [],
    platforms: [],
    roles: [],
    frameworks: [],
    assets: [],
    purdue_levels: [],
  });
  useEffect(() => {
    // Only what the CURRENT mode actually asked. A row that carried the
    // sector/platform answers a visitor gave before switching to OT would
    // report questions the OT panel never put to them — and `sectors` on an
    // OT row would be read as evidence that sector matters to the ICS ranking,
    // which is exactly the claim this variant exists to avoid making.
    const ot = mode === 'ot';
    payloadRef.current = {
      sectors: !ot && sector ? [sector] : [],
      platforms: ot ? [] : (answers.platforms ?? []),
      roles: answers.roles ?? [],
      frameworks: answers.frameworks ?? [],
      assets: ot ? (answers.assets ?? []) : [],
      purdue_levels: ot ? (answers.purdue_levels ?? []) : [],
    };
  }, [sector, answers, mode]);

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
    // Every field is sent on every row, whichever mode produced it, so the
    // row shape is identical across variants and an unasked question is an
    // empty list rather than a missing key.
    reportSubmission({ variant, action: next, ...payload });
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

  /**
   * Every click-open path, for both triggers. `asLarge` is the ONLY
   * difference between them: the sidebar entry opens the big centred modal,
   * a diamond opens the anchored popover or the sheet. Same controller, same
   * questions, same telemetry — so a submission from the sidebar is still
   * `variant: 'v1-4q'` with the same actions, and 'CLICK_OPEN' arms no timer,
   * which is what keeps `auto_close` impossible from this presentation.
   */
  const openFromTrigger = useCallback(
    (event: ReactMouseEvent<HTMLButtonElement>, asLarge: boolean) => {
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
      setLarge(asLarge);
      setModal(true);
      dispatch({ type: 'CLICK_OPEN' });
    },
    [dispatch, modal],
  );

  const onTriggerClick = useCallback(
    (event: ReactMouseEvent<HTMLButtonElement>) => openFromTrigger(event, false),
    [openFromTrigger],
  );

  const onSidebarTriggerClick = useCallback(
    (event: ReactMouseEvent<HTMLButtonElement>) => openFromTrigger(event, true),
    [openFromTrigger],
  );

  const onInteract = useCallback(() => {
    // 'INTERACT' always returns a new state object, so dispatching it on every
    // keystroke once the timer is already cancelled would churn renders for
    // nothing. The timer is only ever armed once, so this is a permanent stop.
    if (timer == null) return;
    dispatch({ type: 'INTERACT' });
  }, [timer, dispatch]);

  const onApply = useCallback(() => {
    // One action, one push — `applyProfile` owns the single router.push, to
    // the briefing at /profile.
    //
    // Roles and frameworks are collected for the telemetry row and deliberately
    // stay out of the URL in BOTH modes, since nothing on `/profile` consumes
    // them. `domain` is passed explicitly and is written even when it equals
    // the default — on `/profile` an absent `domain` is no filter at all, not
    // "enterprise".
    //
    // OT sends NO sector and NO platforms. Not as an omission: the ICS engine
    // ranks on assets, `meta.ignoredParams` names both as received-and-ignored,
    // and putting either in the URL would suggest it narrowed something.
    if (mode === 'ot') {
      applyProfile({
        sector: null,
        domain: domainFor('ot', DEFAULT_DOMAIN),
        params: {
          assets: answers.assets ?? EMPTY_SELECTION,
          purdue_levels: answers.purdue_levels ?? EMPTY_SELECTION,
        },
      });
      return;
    }

    applyProfile({
      sector,
      domain: domainFor('it', DEFAULT_DOMAIN),
      params: { platforms: answers.platforms ?? EMPTY_SELECTION },
    });
  }, [applyProfile, sector, answers, mode]);

  const onClose = useCallback(() => {
    dismiss();
  }, [dismiss]);

  const onModeChange = useCallback(
    (next: ProfileMode) => {
      // Switching mode is an interaction like any other: it must cancel the
      // unsolicited peek's timer, or the panel would close under a visitor who
      // had just told us which estate they defend.
      onInteract();
      setMode(next);
    },
    [onInteract],
  );

  const panelProps = useMemo<Omit<ProfilePanelProps, 'anchored' | 'large'>>(
    () => ({
      modal,
      mode,
      onModeChange,
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
    [modal, mode, onModeChange, sector, answers, setAnswer, onApply, onClose, onToggleClose, onInteract],
  );

  return {
    open,
    modal,
    anchored,
    large,
    peekNudge,
    armPeek,
    onTriggerClick,
    onSidebarTriggerClick,
    registerPresentation,
    panelProps,
  };
}

/* ────────────────────────────────────────────────────────────────────────────
 * Provider + the mount points
 *
 * One controller, shared by every trigger and every presentation. The three
 * hero diamonds are mutually exclusive by breakpoint but ALL THREE stay
 * mounted (they are hidden with `display:none`), so giving each its own hook
 * would arm three peek timers and post three telemetry rows for one visitor.
 * The sidebar entry joins them on the same controller for the same reason.
 *
 * Presentations (at most one on screen at a time):
 *   ProfileAnchoredPanel — xl+, anchored beside the homepage diamond
 *   ProfileSheet         — below xl, a bottom sheet
 *   ProfileLargeModal    — the sidebar entry's larger centred modal, any page
 *
 * Plus `ProfilePeekArmer`, which renders nothing and is the homepage-only
 * rule for the unsolicited peek.
 * ──────────────────────────────────────────────────────────────────────────── */

const ThreatProfileCtx = createContext<ThreatProfileController | null>(null);

/**
 * Mount this once, app-wide (AppShell). It is the panel's AVAILABILITY, not
 * its peek: mounting it arms nothing, posts nothing and shows nothing.
 *
 * It used to be mounted only around the homepage diamonds, because arming
 * happened on mount and an expired peek posts `auto_close` — mounting it
 * anywhere else would have posted outcomes for a panel the visitor was never
 * shown. The sidebar entry needs the panel on every page, so those two
 * concerns were separated instead of the rule being relaxed: `armPeek` is now
 * an explicit call, and `ProfilePeekArmer` — the only caller — still renders
 * only in the homepage landing state.
 */
export function ThreatProfileProvider({
  variant,
  children,
}: {
  /**
   * The DEFAULT engine mode, as a variant id. The panel now renders a visible
   * two-option control over it, so this seeds the control rather than pinning
   * the panel to one engine — which is what made the OT path unreachable.
   */
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
 *
 * `.profile-diamond-nudge` — the pre-close cue — is a keyframe animation on
 * the SAME element, added to that same rule (`animation: none !important`)
 * rather than given a competing `motion-reduce:` mechanism, for exactly the
 * reason above: one place decides what this element does under reduced
 * motion. The class is applied from `ctl.peekNudge`, which is only ever true
 * for an armed, untouched peek.
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
      // Not `ctl.open`: the sidebar entry can have the same questions open as
      // the large modal, which this diamond did not expand and does not
      // control. Claiming otherwise would point a screen reader at the wrong
      // trigger.
      aria-expanded={ctl.open && !ctl.large}
      aria-label="Tailor this to what you defend"
      className="block pointer-events-auto group rounded-lg focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-[var(--accent-teal)]"
    >
      <img
        src="/diamond-favicon.svg"
        alt=""
        width={size}
        height={size}
        className={`profile-diamond-img opacity-[0.55] transition-transform duration-150 ease-out
                   group-hover:-translate-y-[3px] group-hover:scale-[1.02] group-hover:opacity-80
                   group-focus-visible:-translate-y-[3px] group-focus-visible:scale-[1.02]
                   motion-reduce:group-hover:opacity-90${ctl.peekNudge ? ' profile-diamond-nudge' : ''}`}
      />
    </button>
  );
}

/**
 * Arms the unsolicited peek. Renders nothing.
 *
 * This component IS the homepage-only rule, made explicit and placed where
 * the rule lives: inside the landing state, alongside the diamonds. The
 * provider is app-wide, so without this every route would peek at visitors
 * and post an `auto_close` per mount.
 *
 * `armPeek` is idempotent per page load (see useProfileState), so the effect
 * re-running or the armer remounting — landing -> select an entity -> clear
 * the selection — cannot arm a second peek.
 */
export function ProfilePeekArmer() {
  const ctl = useController();
  const armPeek = ctl?.armPeek;
  useEffect(() => {
    armPeek?.();
  }, [armPeek]);
  return null;
}

/**
 * Registers this component as a mounted non-large presentation for its whole
 * lifetime — whether or not it currently renders anything.
 *
 * "Mounted" has to mean "in the tree", not "rendering": both presentations
 * return null most of the time (wrong breakpoint, panel shut), and the state
 * this guards is exactly the state where one of them WOULD render. So the
 * hook runs before any early return, which is also the only place a hook can
 * run.
 */
function useNonLargePresence(ctl: ThreatProfileController | null) {
  const register = ctl?.registerPresentation;
  useEffect(() => register?.(), [register]);
}

/** Place inside the xl diamond's existing `relative` wrapper. Renders nothing
 *  below xl, where `ProfileSheet` takes over, and nothing while the sidebar's
 *  large modal is up — that presentation replaces this one rather than
 *  stacking with it. */
export function ProfileAnchoredPanel() {
  const ctl = useController();
  useNonLargePresence(ctl);
  if (!ctl || !ctl.open || !ctl.anchored || ctl.large) return null;
  return <ProfilePanel anchored large={false} {...ctl.panelProps} />;
}

/** The below-xl sheet. Portalled to `document.body` so neither the diamond
 *  wrappers' `pointer-events-none` nor any transformed ancestor can alter its
 *  fixed positioning. */
export function ProfileSheet() {
  const ctl = useController();
  useNonLargePresence(ctl);
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  if (!mounted || !ctl || !ctl.open || ctl.anchored || ctl.large) return null;
  return createPortal(<ProfilePanel anchored={false} large={false} {...ctl.panelProps} />, document.body);
}

/**
 * The third presentation: the larger centred modal the sidebar entry opens.
 *
 * Mounted once in AppShell, so it is reachable from every page, and portalled
 * to `document.body` for the same reason the sheet is. It renders only when
 * the sidebar opened it, at every breakpoint — an entry in the sidebar is a
 * deliberate request, so unlike the diamonds there is nothing breakpoint-
 * dependent to decide.
 *
 * No new modal machinery: it is `ProfilePanel` with `modal` already true, so
 * `aria-modal`, the focus move, the Tab trap, the inert sibling walk, the
 * focus return to the sidebar entry, the scrim and both close paths are the
 * ones the anchored panel already uses.
 */
export function ProfileLargeModal() {
  const ctl = useController();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  if (!mounted || !ctl || !ctl.open || !ctl.large) return null;
  return createPortal(<ProfilePanel anchored={false} large {...ctl.panelProps} />, document.body);
}

/**
 * The sidebar entry, as a trigger.
 *
 * A `<button>`, not a `<Link>`: it opens the questions in place on whatever
 * page the visitor is on. Apply still owns the single navigation to
 * `/profile`.
 *
 * Carries `data-profile-trigger` like the diamonds do, which buys the whole
 * disclosure-toggle contract for free: clicking it while the modal is open
 * routes through `pointerIsOverTrigger` to the SILENT close, so re-clicking
 * the entry you opened it from is not recorded as a rejection and does not
 * set the dismissal flag — exactly the ruling that already covers the
 * diamond. Every other way of closing it (the X, Escape, a click anywhere
 * else) is an ordinary `dismiss`, and no timer exists on this presentation,
 * so `auto_close` is unreachable from here.
 *
 * `className` comes from the caller: this is a nav row, and the sidebar owns
 * what a nav row looks like.
 */
export function ProfileSidebarTrigger({
  className,
  label = 'Threat Profile',
  title,
}: {
  className?: string;
  label?: string;
  title?: string;
}) {
  const ctl = useController();
  // Rendered outside a provider (e.g. the sidebar in isolation): no
  // controller, no panel to open, so no dead affordance either.
  if (!ctl) return null;
  return (
    <button
      type="button"
      data-profile-trigger=""
      onClick={ctl.onSidebarTriggerClick}
      aria-haspopup="dialog"
      aria-expanded={ctl.open && ctl.large}
      title={title}
      className={className}
    >
      {label}
    </button>
  );
}

/* ────────────────────────────────────────────────────────────────────────────
 * The panel
 * ──────────────────────────────────────────────────────────────────────────── */

export interface ProfilePanelProps {
  /** Absolutely positioned against the diamond (xl+) vs. a centred sheet. */
  anchored: boolean;
  /**
   * The sidebar's presentation: a larger centred modal, at every breakpoint.
   * Mutually exclusive with `anchored` — the two mount points that can set
   * this both pass `anchored={false}`.
   */
  large: boolean;
  /** Click-opened: focus moves in, Tab is trapped, the background is marked
   *  `inert`, and `aria-modal="true"` is therefore true rather than claimed. */
  modal: boolean;
  /** Which engine the questions below belong to. */
  mode: ProfileMode;
  onModeChange: (next: ProfileMode) => void;
  /** IT mode only — the OT panel does not ask for a sector. */
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
  large,
  modal,
  mode,
  onModeChange,
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
  // Describes the two questions that are collected but never ranked.
  const contextNoteId = `${baseId}-context-note`;
  const isOt = mode === 'ot';

  /**
   * The load-bearing question, per mode. Apply stays inert until it is
   * answered, and the reason is shown — the same "no silent defaults" rule the
   * IT panel already followed, applied to the OT question set.
   *
   * OT readiness is "a level or an asset was ticked", with no need to resolve
   * the level to its assets first: the picker renders a level that holds no
   * asset as DISABLED (measured: `l5` is the only one, at zero), so a level
   * that made it into this answer necessarily resolves to at least one. The
   * engine's `empty-selection` state is the backstop if that ever stops being
   * true — it says so rather than ranking nothing.
   */
  const otAnswered =
    (answers.assets?.length ?? 0) > 0 || (answers.purdue_levels?.length ?? 0) > 0;
  const ready = isOt ? otAnswered : Boolean(sector);

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

  /**
   * Three presentations, one panel.
   *
   * The large one is centred with `top-1/2 left-1/2` + a -50% translate
   * rather than flex centring, because it is portalled to `<body>` and has
   * no layout parent to centre within. `w-[calc(100%-2rem)]` keeps a gutter
   * on a narrow viewport, where it is still the right shape — an entry in
   * the sidebar is a deliberate request, so it gets a real modal at every
   * width rather than degrading into the sheet the diamonds use.
   *
   * z-[61] on both portalled variants, matching the anchored panel's inline
   * z-index and sitting one above the shared scrim at z-60.
   */
  const shellClass = large
    ? 'pointer-events-auto select-text fixed left-1/2 top-1/2 z-[61] -translate-x-1/2 -translate-y-1/2 flex w-[calc(100%-2rem)] max-w-[620px] max-h-[85vh] flex-col rounded-2xl border border-[var(--border-color)] bg-[var(--surface-card)] shadow-2xl focus:outline-none'
    : anchored
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
            anchored && !large
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
            {/* What each answer DOES, stated rather than implied. This used to
                read "Four questions. Only the sector is required" — which
                implied all four feed the ranking, when role and compliance
                regime are collected for context and are deliberately kept out
                of the URL because nothing on /profile reads them. "Four" was
                also wrong the moment the OT set (plant surface, role, regime)
                shipped. The count is now derived from the mode rather than
                written down, so it cannot go stale again. */}
            <p className="mt-0.5 text-xs leading-snug text-[var(--text-secondary)]">
              {isOt
                ? 'One question ranks your briefing: the plant surface, which is required. '
                : 'Two questions rank your briefing: sector — the only required one — and environment. '}
              Role and compliance regime are context for us and change nothing in the ranking.
              Nothing is answered for you.
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

        {/* The scroll box grows with the presentation: the popover is pinned
            beside a diamond and must stay compact, the large modal is centred
            with the whole viewport to itself and can show more of the form at
            once — which also means less scrolling behind an open listbox. */}
        <div
          className={`flex flex-col gap-4 overflow-y-auto px-4 py-3 ${
            large ? 'max-h-[min(70vh,560px)]' : 'max-h-[min(60vh,420px)]'
          }`}
          onScroll={onInteract}
        >
          {/* ── The engine switch ────────────────────────────────────────
              A MODE, not a fifth question: it changes which questions follow,
              so it sits above them and is not another dropdown in the stack.

              Native radios rather than `role="radio"` buttons. Arrow-key
              navigation, the single tab stop for the group, and the
              checked/unchecked announcement all come free and correct from the
              platform, and the visually-hidden input still has a client rect —
              so the panel's own Tab trap (`focusableWithin`, which filters on
              `getClientRects()`) still finds it.

              IT is the default, and the whole point of rendering it is that it
              is now VISIBLY the default. It used to be a hardcoded
              `variant="v1-4q"` in AppShell plus a hardcoded `DEFAULT_DOMAIN`
              in Apply, which is the same choice made silently — and it left
              the ICS engine unreachable from anywhere in the app. */}
          <fieldset className="min-w-0">
            <legend className="block text-xs font-medium text-[var(--text-secondary)] mb-1">
              Which estate are you asking about?
            </legend>
            <div className="flex w-full rounded-md border border-[var(--border-color)] p-0.5 gap-0.5">
              {(
                [
                  { value: 'it', label: 'IT estate', hint: 'ATT&CK Enterprise — ranked on your sector and platforms.' },
                  { value: 'ot', label: 'OT plant', hint: 'ATT&CK for ICS — ranked on the plant assets you run.' },
                ] as const
              ).map((opt) => (
                <label
                  key={opt.value}
                  title={opt.hint}
                  className="flex-1 min-w-0 cursor-pointer"
                >
                  <input
                    type="radio"
                    name={`${baseId}-mode`}
                    value={opt.value}
                    checked={mode === opt.value}
                    onChange={() => onModeChange(opt.value)}
                    className="sr-only peer"
                  />
                  <span
                    className="flex items-center justify-center min-h-[44px] px-2 rounded text-sm font-medium text-[var(--text-secondary)] transition-colors
                               peer-checked:bg-[var(--teal-ghost)] peer-checked:text-[var(--accent-teal)] peer-checked:font-semibold
                               peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-[var(--accent-teal)]
                               hover:text-[var(--text-primary)]"
                  >
                    {opt.label}
                  </span>
                </label>
              ))}
            </div>
            <p className="mt-1 text-[11px] leading-snug text-[var(--text-secondary)]">
              {isOt
                ? 'ATT&CK for ICS ranks on the assets you run, so there is no sector question here — a sector answer could not change the result.'
                : 'ATT&CK Enterprise. Switch to OT plant for the ICS engine, which asks about Purdue levels and plant assets instead.'}
            </p>
          </fieldset>

          {isOt ? (
            /* ── OT: assets and Purdue levels ─────────────────────────────
               Deliberately NO sector question, and deliberately no platform
               question. Per-sector ICS technique counts are an artefact of
               automated group attribution rather than OT exposure — measured,
               technology 34 and government 33 outrank energy 12 and
               manufacturing 19, and transportation, a classic OT sector, has
               zero — so asking would be a question that cannot honestly affect
               the answer. All seven ICS platform values match zero live
               techniques, so a platform question could only ever empty the
               pool. */
            <PurdueAssetPickerLoader
              id={`${baseId}-plant`}
              selectedAssets={answers.assets ?? EMPTY_SELECTION}
              selectedLevels={answers.purdue_levels ?? EMPTY_SELECTION}
              // One gesture, one selection. Both keys are written from the
              // same reported value, and `setAnswer` is a functional
              // `setState`, so neither call can read a stale `answers` — the
              // race the briefing page's two `router.replace` calls had.
              onSelectionChange={(next) => {
                setAnswer('assets', next.assets);
                setAnswer('purdue_levels', next.levels);
              }}
              onInteract={onInteract}
              compact={!large}
            />
          ) : (
            <>
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
            </>
          )}

          {/* ── The two questions that are collected but never ranked ─────
              Asked in BOTH modes, and in neither does anything on /profile
              read them: `onApply` keeps both out of the URL on purpose, and
              the two briefings have no notion of either. That is a settled
              decision — it is the copy that had to change. The note is placed
              BEFORE the fields, not after, so it is read while deciding
              whether to answer, and it is wired with `aria-describedby` so a
              screen-reader visitor is told the same thing at the same point
              rather than meeting it after the fact. */}
          <div role="group" aria-describedby={contextNoteId} className="flex flex-col gap-4">
            <p
              id={contextNoteId}
              className="text-[11px] leading-snug text-[var(--text-secondary)] border-t border-[var(--border-color)] pt-3"
            >
              The next two are{' '}
              <span className="font-semibold text-[var(--text-primary)]">context, not ranking</span>
              : they tell us which briefing to build next. Neither reaches the results page, so
              neither changes a row of it.
            </p>

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
        </div>

        <div className="flex items-center justify-between gap-3 border-t border-[var(--border-color)] px-4 py-3">
          <p
            id={statusId}
            aria-live="polite"
            className={`text-xs font-medium ${ready ? 'text-[var(--accent-green)]' : 'text-[var(--accent-yellow)]'}`}
          >
            {ready ? 'Ready' : isOt ? 'Pick a Purdue level or an asset' : 'Pick a sector'}
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
