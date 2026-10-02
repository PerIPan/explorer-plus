'use client';

import { useState } from 'react';
import { EntityLink } from '../shared/EntityLink';
import {
  CISA_IR_PLAYBOOK,
  CISA_IR_SOURCE,
  CISA_IR_TACTIC_COUNT,
} from '../../lib/cisa-ir-playbook';

interface Technique {
  attackId: string;
  name: string;
}

/**
 * CISA's "where to look first" strip for a tactic. Renders nothing for the 50
 * of 57 tactics their table does not cover.
 *
 * Collapsed by default, but the header carries the counts so it advertises
 * what is inside — a section that says only "CISA IR starting points" gives a
 * reader no reason to open it.
 *
 * Technique NAMES come from `techniques`, the list the page already fetched —
 * never from the constant. See the header of src/lib/cisa-ir-playbook.ts for
 * why: an id that no longer resolves (renamed, revoked, re-mapped) is dropped
 * rather than rendered from a stale hard-coded copy. `resolved` can therefore
 * be shorter than the stored id list, which is the intended behaviour.
 *
 * No sanitize() anywhere here: every string is our own module constant, not DB
 * or feed text. Adding it would imply otherwise.
 */
export function IrStartingPoints({
  tacticId,
  techniques,
}: {
  tacticId: string;
  techniques: Technique[];
}) {
  const [open, setOpen] = useState(false);
  const row = CISA_IR_PLAYBOOK.get(tacticId);
  if (!row) return null;

  const byId = new Map(techniques.map((t) => [t.attackId, t]));
  const resolved = row.techniqueIds
    .map((id) => byId.get(id))
    .filter((t): t is Technique => t !== undefined);

  return (
    <div className="mb-6 rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] p-4">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-1.5 text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors w-full text-left"
        aria-expanded={open}
      >
        <svg
          className={`w-3 h-3 shrink-0 transition-transform duration-150 ${open ? 'rotate-90' : ''}`}
          fill="none"
          stroke="currentColor"
          strokeWidth={2}
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
        </svg>
        <span className="text-xs font-semibold uppercase tracking-wider">
          CISA IR starting points
        </span>
        <span className="ml-auto text-[10px] text-[var(--text-secondary)] font-mono tabular-nums shrink-0">
          {row.logSources.length} log sources · {row.indicators.length} indicators
          {resolved.length > 0 ? ` · ${resolved.length} techniques` : ''}
        </span>
      </button>

      {open && (
        <div className="mt-3 space-y-3">
          <Group label="Log and event sources">
            <div className="flex flex-wrap gap-1.5">
              {row.logSources.map((s) => (
                <span
                  key={s}
                  className="text-[11px] px-1.5 py-0.5 rounded border border-[var(--border-color)] text-[var(--text-primary)]"
                >
                  {s}
                </span>
              ))}
            </div>
          </Group>

          <Group label="Indicators to look for">
            <ul className="space-y-0.5">
              {row.indicators.map((i) => (
                <li key={i} className="text-xs text-[var(--text-primary)] flex gap-1.5">
                  <span className="text-[var(--text-secondary)] shrink-0">·</span>
                  <span>{i}</span>
                </li>
              ))}
            </ul>
          </Group>

          {resolved.length > 0 && (
            <Group label="Techniques CISA calls common here">
              <div className="flex flex-wrap gap-2">
                {resolved.map((t) => (
                  <EntityLink
                    key={t.attackId}
                    type="technique"
                    attackId={t.attackId}
                    name={t.name}
                  />
                ))}
              </div>
            </Group>
          )}

          <p className="pt-1 text-[10px] text-[var(--text-secondary)] leading-relaxed">
            An example set from{' '}
            <a
              href={CISA_IR_SOURCE.url}
              target="_blank"
              rel="noopener noreferrer"
              className="hover:underline"
            >
              {CISA_IR_SOURCE.publisher}, <em>{CISA_IR_SOURCE.title}</em>
            </a>{' '}
            ({CISA_IR_SOURCE.published}), {CISA_IR_SOURCE.table} — a US
            government work in the public domain. It covers{' '}
            {CISA_IR_TACTIC_COUNT} tactics, so most tactic pages have no strip,
            and it is illustrative rather than a complete mapping of this
            tactic&rsquo;s techniques.
          </p>
        </div>
      )}
    </div>
  );
}

function Group({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <h4 className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-secondary)] mb-1.5">
        {label}
      </h4>
      {children}
    </div>
  );
}
