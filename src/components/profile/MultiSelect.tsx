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

// Cap on rendered rows once options are filtered. The framework picker alone
// carries 254 entries — filter the full array first, then slice for render
// so the DOM never has to hold more than this many rows. No virtualisation
// library is warranted at this size.
const MAX_VISIBLE = 60;

// DOM ids only ever need to be unique and attribute-safe — the option's own
// `value` is an opaque string with no format guarantee, so strip anything
// outside the safe set before interpolating it into an id.
function domSafe(value: string): string {
  return value.replace(/[^A-Za-z0-9_-]/g, '_');
}

/**
 * Searchable multi-select combobox. Selected values render as removable
 * chips ahead of the text input; the input filters `options`
 * case-insensitively and drives a listbox via `aria-activedescendant`.
 *
 * DOM focus never leaves the input — options are plain, non-focusable `<li>`
 * rows referenced only through `aria-activedescendant`/`aria-selected`, so
 * Tab always leaves the whole control (landing on chip remove buttons first,
 * then the input, since those are the only real tab stops) instead of
 * tabbing into the open list.
 */
export function MultiSelect({ id, label, options, selected, onChange, placeholder }: MultiSelectProps) {
  const [query, setQuery] = useState('');
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(-1);
  const containerRef = useRef<HTMLDivElement>(null);

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
              className="inline-flex items-center gap-0.5 pl-2.5 rounded-full text-xs font-medium border border-[var(--border-color)] bg-[var(--surface-alt)] text-[var(--text-primary)] max-w-full"
            >
              <span className="truncate max-w-[160px]">{chipLabel}</span>
              <button
                type="button"
                onClick={() => toggle(value)}
                aria-label={`Remove ${chipLabel}`}
                className="flex items-center justify-center min-h-[44px] min-w-[44px] rounded-full text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--hover-overlay)] focus-visible:text-[var(--text-primary)] focus-visible:bg-[var(--hover-overlay)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-teal)] transition-colors"
              >
                <span aria-hidden="true">×</span>
              </button>
            </span>
          );
        })}

        <input
          id={id}
          type="text"
          role="combobox"
          aria-expanded={open}
          aria-autocomplete="list"
          aria-controls={listboxId}
          aria-activedescendant={open && activeOption ? `${id}-option-${domSafe(activeOption.value)}` : undefined}
          value={query}
          placeholder={placeholder}
          onChange={(e) => { setQuery(e.target.value); setOpen(true); }}
          onFocus={() => setOpen(true)}
          onKeyDown={handleKeyDown}
          className="flex-1 min-w-[120px] min-h-[44px] bg-transparent text-sm text-[var(--text-primary)] placeholder:text-[var(--text-secondary)] focus:outline-none"
        />
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
          className="absolute z-50 mt-1 w-full max-h-64 overflow-y-auto rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] shadow-xl"
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
