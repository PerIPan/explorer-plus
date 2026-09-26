'use client';

import { useEffect, useMemo, useRef, useState } from 'react';

export interface MultiSelectOption {
  value: string;
  label: string;
  meta?: string;
}

interface MultiSelectProps {
  id: string;
  label: string;
  options: MultiSelectOption[];
  selected: string[];
  onChange: (next: string[]) => void;
  placeholder?: string;
}

// Cap on rendered rows once options are filtered. The longest list here is the
// framework picker at 32 entries (this comment claimed 254 for a while; it was
// never true) — so filter the full array first, then slice for render, and the
// DOM never holds more than this many rows. The cap is kept because it is the
// list length that must not matter, not because 32 needs it, and no
// virtualisation library is warranted at any size these reach.
const MAX_VISIBLE = 60;

// DOM ids only ever need to be unique and attribute-safe — the option's own
// `value` is an opaque string with no format guarantee, so strip anything
// outside the safe set before interpolating it into an id.
function domSafe(value: string): string {
  return value.replace(/[^A-Za-z0-9_-]/g, '_');
}

/**
 * How tall the open listbox may get.
 *
 * 176px (11rem) — four 44px rows. It was 256px, which is most of the ~500px
 * panel this lives in: opening one combobox hid the form behind it, so there
 * was no visible context to return to and no obvious way back. Four rows is
 * enough to browse without the listbox swallowing the questions underneath.
 */
const LISTBOX_MAX_H = 'max-h-[11rem]';

/**
 * Selected-value chips, in the site's house pill style.
 *
 * These are the same three classes `Badge` (src/components/shared/Badge.tsx)
 * emits for its `teal` variant — faint fill, accent text, dim border — and the
 * chip's own geometry (`px-1.5 py-px rounded-full text-[10px] font-medium
 * leading-tight border`) matches Badge's too. Teal because it is the app's
 * primary accent and these pills are the visitor's OWN selections, not a
 * severity or a taxonomy colour.
 *
 * Matched locally rather than rendered through `Badge`: a chip is a label
 * PLUS a remove button, and `Badge` takes `label: string` with no children.
 * Teaching it to carry a button would mean adding a prop that exactly one of
 * its ~90 call sites uses, which is a worse trade than duplicating three
 * class names behind this constant.
 */
const CHIP_VARIANT = 'bg-[var(--teal-faint)] text-[var(--accent-teal)] border-[var(--teal-dim)]';

/**
 * Searchable multi-select combobox. Selected values render as removable
 * chips ahead of the text input; the input filters `options`
 * case-insensitively and drives a listbox via `aria-activedescendant`.
 *
 * DOM focus never leaves the input FOR LIST NAVIGATION — options are plain,
 * non-focusable `<li>` rows referenced only through
 * `aria-activedescendant`/`aria-selected`, so Tab always leaves the whole
 * control (landing on chip remove buttons, the input, then the chevron
 * toggle, since those are the only real tab stops) instead of tabbing into
 * the open list. The chevron suppresses focus on `mousedown` and hands focus
 * back to the input, so pointer use never moves focus off the input either.
 *
 * The list opens on CLICK, TYPING and ArrowDown — never on bare focus.
 * Opening on focus made Escape useless: it closed the list, and the click
 * that returned focus to the input immediately reopened it, with no way out
 * short of clicking elsewhere on the page. "Dismissed but still focused" has
 * to be a reachable state, so `open` is only ever set by a deliberate act.
 */
export function MultiSelect({ id, label, options, selected, onChange, placeholder }: MultiSelectProps) {
  const [query, setQuery] = useState('');
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(-1);
  const containerRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const listboxId = `${id}-listbox`;
  const selectedSet = useMemo(() => new Set(selected), [selected]);
  const optionByValue = useMemo(() => new Map(options.map((o) => [o.value, o])), [options]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return options;
    return options.filter(
      (o) =>
        o.label.toLowerCase().includes(q) ||
        o.value.toLowerCase().includes(q) ||
        (o.meta ?? '').toLowerCase().includes(q),
    );
  }, [options, query]);
  const visible = filtered.slice(0, MAX_VISIBLE);

  // A stale index from the previous filter must never land Enter (or
  // aria-activedescendant) on the wrong row. Resetting via an effect runs
  // after commit, so the first paint after a keystroke would briefly render
  // with the old index against the new `visible` array. Reset it during
  // render instead — the React-documented way to adjust state when a value
  // it depends on changes — so no stale-index frame ever reaches the screen.
  const [prevQuery, setPrevQuery] = useState(query);
  let effectiveActiveIndex = activeIndex;
  if (query !== prevQuery) {
    setPrevQuery(query);
    setActiveIndex(-1);
    effectiveActiveIndex = -1;
  }
  const activeOption = effectiveActiveIndex >= 0 ? visible[effectiveActiveIndex] : undefined;

  // Click-outside close. Deliberately `pointerdown`, not `click` — it fires
  // before the option rows' own `onMouseDown` handler below, so a click on
  // an option toggles it via that handler rather than being swallowed here.
  useEffect(() => {
    function handlePointerDown(e: PointerEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener('pointerdown', handlePointerDown);
    return () => document.removeEventListener('pointerdown', handlePointerDown);
  }, []);

  function toggle(value: string) {
    if (selectedSet.has(value)) onChange(selected.filter((v) => v !== value));
    else onChange([...selected, value]);
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (!open) setOpen(true);
      setActiveIndex((i) => (visible.length ? Math.min(i + 1, visible.length - 1) : -1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (!open) setOpen(true);
      setActiveIndex((i) => Math.max(i - 1, -1));
    } else if (e.key === 'Enter') {
      // preventDefault whenever the list is open, even with nothing active —
      // otherwise Enter with no highlighted row falls through to the native
      // keystroke and submits whatever form this combobox is mounted in.
      if (open) {
        e.preventDefault();
        if (activeOption) {
          toggle(activeOption.value);
          setQuery('');
        }
      }
    } else if (e.key === 'Escape') {
      // Close only the list. Swallow the key so a parent panel that also
      // closes on Escape does not react to the same keypress.
      if (open) {
        e.stopPropagation();
        setOpen(false);
      }
    } else if (e.key === 'Backspace' && query === '' && selected.length > 0) {
      onChange(selected.slice(0, -1));
    }
  }

  // Tab-away close: fires when focus leaves the whole control for anywhere
  // outside it (the pointerdown listener above only covers pointer clicks).
  function handleBlur(e: React.FocusEvent<HTMLDivElement>) {
    if (!e.currentTarget.contains(e.relatedTarget as Node | null)) {
      setOpen(false);
    }
  }

  return (
    <div ref={containerRef} className="relative" onBlur={handleBlur}>
      <label htmlFor={id} className="block text-xs font-medium text-[var(--text-secondary)] mb-1">
        {label}
      </label>

      <div className="flex flex-wrap items-center gap-1.5 min-h-[44px] px-2 py-1 rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] focus-within:border-[var(--accent-teal)] transition-colors">
        {selected.map((value) => {
          const chipLabel = optionByValue.get(value)?.label ?? value;
          return (
            <span
              key={value}
              className={`inline-flex items-center gap-0.5 py-px pl-1.5 pr-1 rounded-full text-[10px] font-medium leading-tight border max-w-full ${CHIP_VARIANT}`}
            >
              <span className="truncate max-w-[160px]">{chipLabel}</span>
              {/* The remove target is 44x44 and the pill is not.
                  `min-h-[44px] min-w-[44px]` on this button used to force the
                  whole pill to 44px tall, which is what made it bulky — the
                  touch target was doing the pill's layout. The hit region is
                  now an absolutely-positioned pseudo-element, so it is 44x44
                  without contributing a single pixel to the pill's box.

                  Anchored to the button's RIGHT edge rather than centred on
                  it: the extra 32px then falls back over this chip's own
                  (inert) label instead of over the NEXT chip, so the worst a
                  stray press can do is remove the chip you aimed at. The
                  vertical 44px still bleeds ~14px above and below the pill —
                  unavoidable once a 16px pill carries a 44px target, and
                  harmless since the row above/below is the field's own
                  padding. */}
              <button
                type="button"
                onClick={() => toggle(value)}
                aria-label={`Remove ${chipLabel}`}
                className="relative shrink-0 flex items-center justify-center rounded-full opacity-70 hover:opacity-100 focus-visible:opacity-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-teal)] transition-opacity
                           before:content-[''] before:absolute before:right-0 before:top-1/2 before:h-11 before:w-11 before:-translate-y-1/2"
              >
                <span aria-hidden="true" className="text-[11px] leading-none">
                  ×
                </span>
              </button>
            </span>
          );
        })}

        <input
          id={id}
          ref={inputRef}
          type="text"
          role="combobox"
          aria-expanded={open}
          aria-autocomplete="list"
          // Only while the list EXISTS. The <ul id={listboxId}> is rendered
          // under `open` below, so an unconditional aria-controls is a
          // dangling IDREF for most of this control's life — assistive tech is
          // pointed at an element that is not in the document.
          aria-controls={open ? listboxId : undefined}
          aria-activedescendant={open && activeOption ? `${id}-option-${domSafe(activeOption.value)}` : undefined}
          value={query}
          placeholder={placeholder}
          onChange={(e) => { setQuery(e.target.value); setOpen(true); }}
          // Click, not focus: a click is a deliberate act, so Escape (or an
          // outside click) followed by Tab back into the field leaves the
          // list shut. See the component doc for why focus cannot do this.
          onClick={() => setOpen(true)}
          onKeyDown={handleKeyDown}
          className="flex-1 min-w-[120px] min-h-[44px] bg-transparent text-sm text-[var(--text-primary)] placeholder:text-[var(--text-secondary)] focus:outline-none"
        />

        {/* The close affordance. The question directly above this one is a
            native <select> WITH a chevron, so the hand goes looking for the
            same target here — and until this existed the only <button> in the
            control was a chip's "×". A real button, not a decorative glyph:
            it has an accessible name, it toggles (so it closes as well as
            opens), and it reports `aria-expanded` for the same listbox the
            input controls.

            `mousedown` is prevented so the press cannot pull DOM focus off
            the input, and focus is handed back explicitly for the case where
            it was somewhere else entirely — the combobox contract is that the
            input keeps focus while the list is open. Escape is handled here
            too, and swallowed, for the keyboard visitor who tabbed to the
            chevron: without it the key would bubble to the panel and close
            the whole thing. */}
        <button
          type="button"
          aria-label={open ? `Hide ${label} options` : `Show ${label} options`}
          aria-expanded={open}
          // Conditional for the same reason as the input's, above.
          aria-controls={open ? listboxId : undefined}
          onMouseDown={(e) => e.preventDefault()}
          onClick={() => {
            setOpen((wasOpen) => !wasOpen);
            inputRef.current?.focus();
          }}
          onKeyDown={(e) => {
            if (e.key === 'Escape' && open) {
              e.stopPropagation();
              setOpen(false);
            }
          }}
          className="shrink-0 flex items-center justify-center min-h-[44px] min-w-[44px] -mr-1 rounded-md text-[var(--text-secondary)] hover:text-[var(--text-primary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-teal)] transition-colors"
        >
          <svg
            aria-hidden="true"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={2}
            className={`w-3.5 h-3.5 transition-transform duration-150 motion-reduce:transition-none ${open ? 'rotate-180' : ''}`}
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
          </svg>
        </button>
      </div>

      {/* Screen-reader-only status: option count updates as the query narrows
          the list, independent of the visible chips/checkmarks that carry
          selection state on each row. */}
      <div aria-live="polite" className="sr-only">
        {open
          ? `${filtered.length} option${filtered.length === 1 ? '' : 's'} available${
              filtered.length > visible.length ? `, showing first ${visible.length}` : ''
            }`
          : ''}
      </div>

      {open && (
        <ul
          id={listboxId}
          role="listbox"
          aria-label={label}
          aria-multiselectable="true"
          className={`absolute z-50 mt-1 w-full ${LISTBOX_MAX_H} overflow-y-auto rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] shadow-xl`}
        >
          {visible.length === 0 && (
            <li className="px-3 py-2.5 text-xs text-[var(--text-secondary)] italic">No matches</li>
          )}
          {visible.map((opt, i) => {
            const isSelected = selectedSet.has(opt.value);
            const isActive = i === effectiveActiveIndex;
            return (
              <li
                key={opt.value}
                id={`${id}-option-${domSafe(opt.value)}`}
                role="option"
                aria-selected={isSelected}
                onMouseDown={(e) => {
                  // Prevent the mousedown from stealing focus off the input —
                  // these rows are not focusable, but preventDefault also
                  // stops the default text-selection drag on rapid clicks.
                  e.preventDefault();
                  toggle(opt.value);
                  setQuery('');
                }}
                onMouseEnter={() => setActiveIndex(i)}
                className={`flex items-center justify-between gap-2 min-h-[44px] px-3 py-2 text-sm cursor-pointer transition-colors ${
                  isActive
                    ? 'bg-[var(--teal-ghost)] text-[var(--accent-teal)]'
                    : 'text-[var(--text-primary)]'
                }`}
              >
                <span className="min-w-0">
                  <span className="block truncate">{opt.label}</span>
                  {opt.meta && (
                    <span className="block truncate text-[11px] text-[var(--text-secondary)]">{opt.meta}</span>
                  )}
                </span>
                {isSelected && (
                  <span className="shrink-0 text-[var(--accent-teal)]" aria-hidden="true">
                    ✓
                  </span>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
