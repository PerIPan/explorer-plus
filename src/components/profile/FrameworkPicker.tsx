'use client';

import { MultiSelect, type MultiSelectOption } from './MultiSelect';
import { SCF_FRAMEWORK_REGISTRY } from '../../lib/scf-framework-registry';

/* ────────────────────────────────────────────────────────────────────────────
 * The compliance-regime question, in its own module so its option source can
 * leave the shared chunk.
 *
 * `ProfilePanel` is statically imported by `AppShell`, so everything it
 * statically imports ships in the client chunk that EVERY route downloads —
 * including the ~8,000 indexed deep-link pages, where the panel exists only as
 * a sidebar entry nobody has clicked. `SCF_FRAMEWORK_REGISTRY` is 16 KB of
 * source read for nothing more than 32 `{ value, label }` pairs, so the panel
 * now reaches this component through `next/dynamic` and the registry loads on
 * the first open instead of on the first page view.
 *
 * It is a component rather than an exported option array because a lazily
 * loaded array would still have to be awaited somewhere, and a picker rendered
 * with an empty option list is a question that cannot be answered.
 * ──────────────────────────────────────────────────────────────────────────── */

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

export default function FrameworkPicker({
  id,
  selected,
  onChange,
}: {
  id: string;
  selected: string[];
  onChange: (next: string[]) => void;
}) {
  return (
    <MultiSelect
      id={id}
      label="Compliance regime"
      options={FRAMEWORK_OPTIONS}
      selected={selected}
      onChange={onChange}
      placeholder="Search frameworks…"
    />
  );
}
