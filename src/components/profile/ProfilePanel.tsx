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
import { platformSchema, sectorSlugSchema, type Platform } from '../../../app/api/v1/lib/validate';

/* ────────────────────────────────────────────────────────────────────────────
 * Option sources
 *
 * Every list below is DERIVED from the schema/registry that already owns those
 * values — never hand-copied — so a change at the source either flows through
 * or fails `npm run typecheck`, rather than silently leaving the picker
 * offering values the API will 400 on.
 * ──────────────────────────────────────────────────────────────────────────── */

type SectorSlug = (typeof sectorSlugSchema.options)[number];

/** Presentation only: the 12 slugs come from `sectorSlugSchema`, these are the
 *  human labels for them. Typed as a total `Record` so adding a slug to the
 *  schema without a label is a compile error. */
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
  sectorSlugSchema.options.map((slug) => ({ value: slug, label: SECTOR_LABELS[slug] }));

/**
 * The ICS half of `platformSchema`. Named and exported so the OT variant can
 * take this set directly (and the IT variant below its complement) instead of
 * both hand-maintaining a copy of the split that then drifts apart.
 *
 * `satisfies readonly Platform[]` is the guard: if ATT&CK renames one of these
 * in `platformSchema`, this list stops compiling instead of quietly excluding
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

/** Enterprise + mobile platforms — `platformSchema` minus the ICS values. */
export const IT_PLATFORMS: Platform[] = platformSchema.options.filter((p) => !ICS_PLATFORM_SET.has(p));

/** The complement, for the OT variant. Derived here so the two never diverge. */
export const OT_PLATFORMS: Platform[] = platformSchema.options.filter((p) => ICS_PLATFORM_SET.has(p));

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

  // Tailwind's `xl` breakpoint, read once and on change. Starts false so the
  // server render and the first client render agree; the panel cannot be open
  // on either (the peek is armed from a mount effect), so there is no flash.
  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return undefined;
    const mql = window.matchMedia('(min-width: 1280px)');
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

  const onTriggerClick = useCallback(
    (event: ReactMouseEvent<HTMLButtonElement>) => {
      // Read the node synchronously — `currentTarget` is cleared once the
      // event finishes dispatching. Focus returns here when the panel closes.
      returnFocusRef.current = event.currentTarget;
      setModal(true);
      dispatch({ type: 'CLICK_OPEN' });
    },
    [dispatch],
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
      onInteract,
      returnFocusRef,
    }),
    [modal, sector, answers, setAnswer, onApply, onClose, onInteract],
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
 * the affordance, and `motion-reduce` drops the transform entirely.
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
        className="opacity-[0.55] transition-transform duration-150 ease-out
                   group-hover:-translate-y-[3px] group-hover:scale-[1.02] group-hover:opacity-80
                   group-focus-visible:-translate-y-[3px] group-focus-visible:scale-[1.02]
                   motion-reduce:transform-none motion-reduce:group-hover:opacity-90"
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
  /** Click-opened: `aria-modal`, focus moves in, Tab is trapped. */
  modal: boolean;
  sector: string | null;
  onSectorChange: (next: string | null) => void;
  answers: ProfileAnswers;
  setAnswer: (key: string, value: string[]) => void;
  onApply: () => void;
  onClose: () => void;
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

function focusableWithin(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter(
    (el) => el.getClientRects().length > 0,
  );
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
   */
  useEffect(() => {
    wasModalRef.current = modal;
    if (modal) panelRef.current?.focus();
  }, [modal]);

  // Return focus to the diamond that opened it — but only if it WAS
  // click-opened. Pulling focus back after a peek nobody asked for would be
  // the same WCAG failure in reverse.
  useEffect(
    () => () => {
      if (wasModalRef.current) returnFocusRef.current?.focus();
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
      if (!target) return;
      if (panelRef.current?.contains(target)) return;
      // A click on the diamond is the toggle's own business, not an outside
      // click — otherwise it would dismiss then immediately reopen, posting a
      // phantom `dismiss` on the way through.
      if (typeof target.closest === 'function' && target.closest('[data-profile-trigger]')) return;
      onClose();
    }
    document.addEventListener('pointerdown', handlePointerDown);
    return () => document.removeEventListener('pointerdown', handlePointerDown);
  }, [modal, onClose]);

  // Safety net for Escape when focus somehow sits outside the trap (e.g. on
  // <body>). The in-panel handler below stops propagation, so this never
  // double-fires for the normal case.
  useEffect(() => {
    if (!modal) return undefined;
    function handleKey(event: KeyboardEvent) {
      if (event.key === 'Escape') onClose();
    }
    document.addEventListener('keydown', handleKey);
    return () => document.removeEventListener('keydown', handleKey);
  }, [modal, onClose]);

  // Flip the anchored panel to stay in the viewport. Left is the usual side —
  // the xl diamond sits at the right edge of the content column — so the flip
  // only engages on a narrow xl window.
  useEffect(() => {
    if (!anchored) return undefined;
    function compute() {
      const el = panelRef.current;
      const anchor = el?.offsetParent as HTMLElement | null;
      if (!el || !anchor) return;
      const rect = anchor.getBoundingClientRect();
      const needed = ANCHORED_WIDTH + ANCHOR_GAP;
      const fitsLeft = rect.left >= needed;
      const fitsRight = window.innerWidth - rect.right >= needed;
      setFlipX(fitsLeft || !fitsRight ? 'left' : 'right');
      setFlipY(rect.top + el.offsetHeight <= window.innerHeight - 8 ? 'top' : 'bottom');
    }
    compute();
    window.addEventListener('resize', compute);
    return () => window.removeEventListener('resize', compute);
  }, [anchored]);

  const anchoredStyle: CSSProperties | undefined = anchored
    ? {
        position: 'absolute',
        width: ANCHORED_WIDTH,
        zIndex: 50,
        ...(flipX === 'left'
          ? { right: `calc(100% + ${ANCHOR_GAP}px)` }
          : { left: `calc(100% + ${ANCHOR_GAP}px)` }),
        ...(flipY === 'top' ? { top: 0 } : { bottom: 0 }),
      }
    : undefined;

  function handleKeyDown(event: ReactKeyboardEvent<HTMLDivElement>) {
    onInteract();

    if (event.key === 'Escape') {
      // Stop here so the document-level net above does not also fire, and so
      // a parent listener does not react to the same keypress.
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
    : 'pointer-events-auto select-text fixed inset-x-0 bottom-0 z-50 mx-auto flex w-full max-h-[85vh] flex-col rounded-t-2xl border-t border-x border-[var(--border-color)] bg-[var(--surface-card)] shadow-2xl focus:outline-none sm:max-w-[560px]';

  return (
    <>
      {/* Scrim for the click-opened sheet only. The peek never dims or blocks
          the page behind it — it was not asked for. */}
      {!anchored && modal && <div className="fixed inset-0 z-40 bg-black/30" aria-hidden="true" />}

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
