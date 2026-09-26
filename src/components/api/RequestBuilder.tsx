'use client';

import { useCallback, useMemo, useState } from 'react';
import { Badge } from '../shared/Badge';
import { PAGINATION_PARAMS } from '../../lib/api-catalog';
import { composePath, pathVariables, seedValues } from '../../lib/api-request.mjs';
import type { ApiEntry, ApiParam } from '../../lib/api-catalog';

export interface BuilderField extends ApiParam {
  /** A `{segment}` of the path, or a `?query=` parameter. */
  kind: 'path' | 'query';
}

/**
 * The fields one endpoint offers, path segments first.
 *
 * A path variable is always required — there is no URL without it — and the
 * shared pagination set is folded in for a paginated route, minus any parameter
 * the route documents itself, so `limit` is never offered twice.
 */
function fieldsFor(entry: ApiEntry): BuilderField[] {
  const own = entry.params ?? [];
  const ownNames = new Set(own.map((p) => p.name));
  return [
    ...pathVariables(entry.path).map((v) => ({
      kind: 'path' as const,
      name: v.name,
      type: 'string' as const,
      required: true,
      note: v.catchAll ? 'Several segments, separated by /' : undefined,
    })),
    ...own.map((p) => ({ ...p, kind: 'query' as const })),
    ...(entry.paginated ? PAGINATION_PARAMS : [])
      .filter((p) => !ownNames.has(p.name))
      .map((p) => ({ ...p, kind: 'query' as const })),
  ];
}

/**
 * Editable request state for one endpoint.
 *
 * Seeded from the catalogue's worked example, so the modal opens on a call that
 * already returns 200: the reader edits a working request instead of composing
 * one from the parameter table and guessing at the id format. That is the whole
 * difference between documentation you read and documentation you use.
 */
export function useRequestBuilder(entry: ApiEntry) {
  const fields = useMemo(() => fieldsFor(entry), [entry]);
  const seed = useMemo(() => seedValues(entry.path, entry.example), [entry]);
  const [values, setValues] = useState<{ path: Record<string, string>; query: Record<string, string> }>(seed);

  const setValue = useCallback((kind: 'path' | 'query', name: string, value: string) => {
    setValues((prev) => ({ ...prev, [kind]: { ...prev[kind], [name]: value } }));
  }, []);
  const reset = useCallback(() => setValues(seed), [seed]);

  /* Query order follows the FIELD order, not object-key order, so the URL reads
     the way the form does however the reader filled it in. */
  const composed = useMemo(
    () =>
      composePath(
        entry.path,
        values.path,
        fields.filter((f) => f.kind === 'query').map((f) => [f.name, values.query[f.name] ?? '']),
      ),
    [entry.path, fields, values],
  );

  const dirty = useMemo(
    () => JSON.stringify(values) !== JSON.stringify(seed),
    [values, seed],
  );

  return { fields, values, setValue, reset, composed, dirty, seed };
}

const INPUT_CLASS =
  'w-full rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-2 py-1 font-mono text-xs text-[var(--text-primary)] placeholder:text-[var(--text-secondary)] focus:border-[var(--teal-dim)] focus:outline-none';

/** One row: the parameter's contract, then the box you type it into. */
function Field({
  field,
  value,
  onChange,
  id,
  isExample,
}: {
  field: BuilderField;
  value: string;
  onChange: (value: string) => void;
  id: string;
  /** Still holding the catalogue's worked value, untouched by the reader. */
  isExample: boolean;
}) {
  const options = field.values ?? (field.type === 'boolean' ? (['true', 'false'] as const) : undefined);
  /* Bold italic while a value is still ours rather than yours. Every runnable
     endpoint opens pre-filled with a request that really returns 200, so the
     Run button gives a result on the first press — but a reader cannot tell a
     prefilled id from one they typed, and would not know it is theirs to edit.
     The styling drops the moment the value changes. */
  const exampleClass = isExample ? ' font-bold italic' : '';

  return (
    <li className="px-3 py-2">
      <div className="flex flex-wrap items-center gap-2">
        <label htmlFor={id} className="font-mono text-xs text-[var(--text-primary)]">
          {field.kind === 'path' ? `{${field.name}}` : field.name}
        </label>
        <Badge label={field.type} variant="neutral" />
        {field.required ? <Badge label="required" variant="orange" /> : null}
        {field.kind === 'path' && <Badge label="path" variant="teal" />}
        {isExample && <Badge label="example" variant="neutral" />}
      </div>
      <div className="mt-1.5">
        {options ? (
          <select id={id} value={value} onChange={(e) => onChange(e.target.value)} className={INPUT_CLASS + exampleClass}>
            {/* An unset optional filter must stay unset — see composePath. */}
            <option value="">{field.required ? '— choose —' : '— not set —'}</option>
            {options.map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </select>
        ) : (
          <input
            id={id}
            type={field.type === 'number' ? 'number' : 'text'}
            value={value}
            onChange={(e) => onChange(e.target.value)}
            placeholder={field.required ? 'required' : 'optional'}
            className={INPUT_CLASS + exampleClass}
          />
        )}
      </div>
      {field.note && <p className="mt-1 text-[11px] leading-snug text-[var(--text-secondary)]">{field.note}</p>}
    </li>
  );
}

/** The whole form. Renders nothing when an endpoint takes no input at all. */
export function RequestFields({
  entry,
  builder,
}: {
  entry: ApiEntry;
  builder: ReturnType<typeof useRequestBuilder>;
}) {
  const { fields, values, setValue, reset, dirty } = builder;

  if (fields.length === 0) {
    return (
      <p className="text-xs text-[var(--text-secondary)]">
        Takes no parameters. Unknown query parameters are ignored, never rejected.
      </p>
    );
  }

  return (
    <div className="space-y-2">
      <ul className="divide-y divide-[var(--border-color)] rounded-md border border-[var(--border-color)]">
        {fields.map((f) => {
          const id = `req-${entry.method}-${entry.path}-${f.kind}-${f.name}`.replace(/[^a-zA-Z0-9-]/g, '_');
          const value = values[f.kind][f.name] ?? '';
          return (
            <Field
              key={`${f.kind}:${f.name}`}
              id={id}
              field={f}
              value={value}
              isExample={value !== '' && value === (builder.seed[f.kind][f.name] ?? '')}
              onChange={(v) => setValue(f.kind, f.name, v)}
            />
          );
        })}
      </ul>
      <p className="text-[11px] leading-snug text-[var(--text-secondary)]">
        Values in <span className="font-bold italic">bold italic</span> are our worked example, chosen so the call
        returns 200 on the first press. Edit any of them — the URL, the curl and the request all follow what you type.
      </p>

      {dirty && (
        <button
          type="button"
          onClick={reset}
          className="rounded-md border border-[var(--border-color)] px-2 py-1 text-[10px] font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--teal-dim)] hover:text-[var(--accent-teal)]"
        >
          reset to the example
        </button>
      )}
    </div>
  );
}
