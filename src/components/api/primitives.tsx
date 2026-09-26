'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { Badge } from '../shared/Badge';
import { PAGINATION_PARAMS } from '../../lib/api-catalog';
import type { ApiEntry, ApiParam } from '../../lib/api-catalog';

/** Method pill in the house style — faint fill, accent text, dim border. */
export function MethodPill({ method }: { method: 'GET' | 'POST' }) {
  return <Badge label={method} variant={method === 'GET' ? 'teal' : 'orange'} className="font-mono tracking-wide" />;
}

/**
 * Copy to clipboard, best effort. The Clipboard API is absent over plain HTTP
 * and rejects when the document is not focused, so a failure has to be a visible
 * state rather than an unhandled rejection. Nothing is persisted — the
 * "copied" flag lives for two seconds in component state.
 */
export function CopyButton({ value, label = 'copy' }: { value: string; label?: string }) {
  const [state, setState] = useState<'idle' | 'done' | 'failed'>('idle');
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => () => { if (timer.current) clearTimeout(timer.current); }, []);

  const copy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(value);
      setState('done');
    } catch {
      setState('failed');
    }
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => setState('idle'), 2000);
  }, [value]);

  return (
    <button
      type="button"
      onClick={copy}
      className="shrink-0 rounded-md border border-[var(--border-color)] px-2 py-1 text-[10px] font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--teal-dim)] hover:text-[var(--accent-teal)]"
    >
      {state === 'done' ? 'copied' : state === 'failed' ? 'select it instead' : label}
    </button>
  );
}

/** A monospace fact line: label, value, optional copy. */
export function FactRow({ label, value, copy }: { label: string; value: string; copy?: boolean }) {
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
      <span className="w-[5.5rem] shrink-0 text-[10px] font-semibold uppercase tracking-wider text-[var(--text-secondary)]">
        {label}
      </span>
      <code className="min-w-0 break-all font-mono text-xs text-[var(--text-primary)]">{value}</code>
      {copy && <CopyButton value={value} />}
    </div>
  );
}

/** A labelled block of prose or code, used throughout both pages. */
export function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div>
      <div className="mb-1.5 text-[11px] font-bold uppercase tracking-wider text-[var(--accent-teal)]">{title}</div>
      {children}
    </div>
  );
}

export function CodeBlock({ children, wrap = false }: { children: string; wrap?: boolean }) {
  return (
    <pre
      className={`rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-3 py-2.5 font-mono text-[11px] leading-relaxed text-[var(--text-primary)] ${
        wrap ? 'whitespace-pre-wrap break-all' : 'overflow-x-auto whitespace-pre'
      }`}
    >
      {children}
    </pre>
  );
}

/**
 * Parameters, with the shared pagination set folded in for a paginated route so
 * `page`/`limit` are documented once in the catalogue and shown on every list
 * endpoint that accepts them.
 */
export function ParamTable({ entry }: { entry: ApiEntry }) {
  const own = entry.params ?? [];
  const shared = entry.paginated ? PAGINATION_PARAMS : [];
  // A route that names `page`/`limit` itself (it validates them without the
  // shared schema) must not be listed twice.
  const ownNames = new Set(own.map((p) => p.name));
  const rows: ApiParam[] = [...own, ...shared.filter((p) => !ownNames.has(p.name))];

  if (rows.length === 0) {
    return <p className="text-xs text-[var(--text-secondary)]">No parameters. Unknown query parameters are ignored, never rejected.</p>;
  }

  return (
    <ul className="divide-y divide-[var(--border-color)] rounded-md border border-[var(--border-color)]">
      {rows.map((p) => (
        <li key={p.name} className="px-3 py-2">
          <div className="flex flex-wrap items-center gap-2">
            <code className="font-mono text-xs text-[var(--text-primary)]">{p.name}</code>
            <Badge label={p.type} variant="neutral" />
            {p.required ? <Badge label="required" variant="orange" /> : null}
          </div>
          {p.values && (
            <div className="mt-1 flex flex-wrap gap-1">
              {p.values.map((v) => (
                <code key={v} className="rounded bg-[var(--hover-overlay)] px-1 py-px font-mono text-[10px] text-[var(--text-secondary)]">
                  {v}
                </code>
              ))}
            </div>
          )}
          {p.note && <p className="mt-1 text-[11px] leading-snug text-[var(--text-secondary)]">{p.note}</p>}
        </li>
      ))}
    </ul>
  );
}

/** The parameter schema of an agent tool, in the Gemini dialect it is declared in. */
export function ToolParamTable({
  parameters,
}: {
  parameters?: { type: string; properties?: Record<string, unknown>; required?: string[] };
}) {
  const props = parameters?.properties ?? {};
  const names = Object.keys(props);
  if (names.length === 0) {
    return <p className="text-xs text-[var(--text-secondary)]">Takes no arguments.</p>;
  }
  const required = new Set(parameters?.required ?? []);
  return (
    <ul className="divide-y divide-[var(--border-color)] rounded-md border border-[var(--border-color)]">
      {names.map((name) => {
        const raw = props[name] as { type?: string; description?: string; enum?: string[] } | undefined;
        return (
          <li key={name} className="px-3 py-2">
            <div className="flex flex-wrap items-center gap-2">
              <code className="font-mono text-xs text-[var(--text-primary)]">{name}</code>
              {raw?.type && <Badge label={raw.type.toLowerCase()} variant="neutral" />}
              {required.has(name) ? <Badge label="required" variant="orange" /> : null}
            </div>
            {raw?.enum && (
              <div className="mt-1 flex flex-wrap gap-1">
                {raw.enum.map((v) => (
                  <code key={v} className="rounded bg-[var(--hover-overlay)] px-1 py-px font-mono text-[10px] text-[var(--text-secondary)]">
                    {v}
                  </code>
                ))}
              </div>
            )}
            {raw?.description && (
              <p className="mt-1 text-[11px] leading-snug text-[var(--text-secondary)]">{raw.description}</p>
            )}
          </li>
        );
      })}
    </ul>
  );
}
