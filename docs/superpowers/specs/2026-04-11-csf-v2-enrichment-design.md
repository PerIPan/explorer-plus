# NIST CSF v2 Enrichment — Design

**Date:** 2026-04-11
**Status:** Approved — ready for implementation
**Bundles with:** AppShell horizontal-overflow fix (see § Layout Fix)

## Problem

The CSF v2 framework page at `/frameworks/csf` has three gaps:

1. **Empty authoritative mappings.** CTID's CRI Profile covers only 24 out of 185 subcategories (13%). All of Govern, Respond, and Recover have zero ATT&CK technique mappings — not a bug, just CTID's intentional scoping of the direct-mapping set. Users expanding those rows see only "No ATT&CK technique mappings yet."
2. **No cross-framework context.** The page doesn't surface what other authoritative frameworks (ISO 27001, NIST 800-53, CIS Controls, 800-221A) say about each subcategory, even though NIST publishes these mappings officially as part of CSF v2.
3. **No implementation guidance.** NIST CSF v2 ships with Implementation Examples per subcategory — plain-text "how organizations can do this" content. None of it is currently displayed.

Additionally, the page has a **horizontal overflow bug** on wide viewports: the main content extends ~400px past the viewport on the right because of a missing `min-w-0` on the flex wrapper in `AppShell`. Long subcategory names with the `truncate` utility expose the classic flexbox min-width-auto trap.

## Goals

- Fill empty Govern/Respond/Recover rows with real content (Implementation Examples + Informative References)
- Surface cross-framework context on every subcategory, not just those CTID mapped
- Add category-level descriptions (currently we show only category *name*)
- Add one-line function descriptions as tooltips
- Fix the AppShell horizontal overflow so CSF layout works like every other page

## Non-Goals

- No transitive ATT&CK mapping via NIST 800-53 chaining (previously discussed — rejected as noisy)
- No OpenCRE integration (deferred — see `2026-04-08-opencre-research.md`)
- No PCI DSS or ASVS/WSTG in this phase
- No standalone browse pages for ISO 27001, CIS, or 800-221A — references surface only on the CSF page
- No CSF Implementation Tiers or Profiles (org-maturity and template content, out of scope)

## Data Source

**NIST CSF v2 OLIR JSON feed** — https://csrc.nist.gov/extensions/nudp/services/json/csf/download?olirids=all

NIST publishes the CSF v2 core, Implementation Examples, and all Informative References in a single JSON bundle as part of the OLIR (Online Informative Reference) program. Public domain (US government work), no license friction, stable URL.

**Fallback:** if the OLIR endpoint is unavailable, the same data is mirrored in the NIST CSF v2 Reference Tool Excel and in the `usnistgov/csf` GitHub repo — we can extend the ingest script later if needed.

## Scope of New Data

| Dataset | Value tier | Status |
|---|---|---|
| Implementation Examples | **Highest** — fills empty rows with NIST-authored text | In scope |
| Informative References (800-53r5, CIS v8, ISO 27001:2022, 800-221A) | **High** — cross-framework context | In scope |
| Category descriptions | Low-medium — enriches category header | In scope |
| Function descriptions | Low — one-line tooltip | In scope |
| Implementation Tiers | N/A — not per-subcategory | Skip |
| Profiles | N/A — templates, not data | Skip |
| Quick-Start Guides | Low — link out | Skip (can add later) |

## Schema

Two new tables, one denormalized column addition.

### `csf_implementation_examples` (new)

```sql
CREATE TABLE csf_implementation_examples (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  csf_subcategory_uuid uuid NOT NULL REFERENCES csf_subcategories(id) ON DELETE CASCADE,
  subcategory_id text NOT NULL,          -- denormalized for fast lookup
  example_id text NOT NULL,              -- e.g. "GV.OC-01.Ex1"
  ordinal smallint NOT NULL,             -- display order (1, 2, 3…)
  text text NOT NULL,
  source text NOT NULL DEFAULT 'nist-csf-v2',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (subcategory_id, example_id)
);

CREATE INDEX idx_csf_examples_subcat ON csf_implementation_examples(subcategory_id);
```

### `csf_informative_references` (new)

```sql
CREATE TABLE csf_informative_references (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  csf_subcategory_uuid uuid NOT NULL REFERENCES csf_subcategories(id) ON DELETE CASCADE,
  subcategory_id text NOT NULL,
  target_framework text NOT NULL,        -- '800-53r5' | 'cis-v8' | 'iso-27001-2022' | '800-221a' | ...
  target_id text NOT NULL,               -- 'PM-9', '5.1.1', 'A.5.19', 'GV.OV-01'
  target_text text,                      -- short label from NIST (may be null if OLIR provides only ID)
  relationship text,                     -- 'subset of' | 'intersects with' | 'equal' | etc. (OLIR relationship type)
  source text NOT NULL DEFAULT 'nist-csf-v2',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (subcategory_id, target_framework, target_id)
);

CREATE INDEX idx_csf_refs_subcat ON csf_informative_references(subcategory_id);
CREATE INDEX idx_csf_refs_target ON csf_informative_references(target_framework, target_id);
```

The `target_framework` value is normalized at ingest time to a stable short slug. Mapping table (populated by the ingest script):

| OLIR source value | Normalized slug |
|---|---|
| `NIST_SP_800-53_Rev_5` | `800-53r5` |
| `CIS_Controls_v8` | `cis-v8` |
| `ISO/IEC_27001_2022` | `iso-27001-2022` |
| `NIST_SP_800-221A` | `800-221a` |
| `NIST_SP_800-207` | `800-207` |
| *(others)* | kebab-cased lowercase |

### `csf_subcategories.category_description` (new column)

```sql
ALTER TABLE csf_subcategories ADD COLUMN category_description text;
```

Denormalized onto the subcategory row since we already have `category_id` and `category_name` there. Avoids creating a `csf_categories` table for a single extra field. Populated by the same ingest script.

### Function descriptions

Static constant in the UI — 6 entries, each <200 chars. No DB needed. Lives in `src/views/CsfFramework.tsx` alongside the existing `FUNCTIONS` array.

## Ingest

**Script:** `scripts/seed-csf-enrichment.mjs`

Pulls the OLIR JSON, parses, upserts in transaction:

1. Fetch `https://csrc.nist.gov/extensions/nudp/services/json/csf/download?olirids=all`
2. For each subcategory in the core:
   - Upsert `category_description` onto `csf_subcategories`
   - Upsert Implementation Examples into `csf_implementation_examples` (ordinal = array index + 1)
   - Upsert Informative References into `csf_informative_references` (normalize framework slug)
3. Hook into the existing `scripts/sync-frameworks.mjs` runner so `npm run sync-frameworks` refreshes both CRI mappings and this enrichment data.

**Idempotency:** all upserts keyed on natural IDs (`subcategory_id + example_id` or `subcategory_id + target_framework + target_id`). Re-running the script is safe.

**Expected volume:**
- ~185 subcategories → ~400 implementation examples (~2 avg) + ~900 informative references (~5 avg). Trivial.

## API Changes

Extend `app/api/v1/frameworks/csf/[subcategoryId]/route.ts`:

```ts
interface CsfDetailResponse {
  // existing
  subcategoryId: string;
  name: string;
  description: string | null;
  categoryId: string;
  categoryName: string;
  categoryDescription: string | null;        // NEW
  function: string;
  techniques: Array<{ attackId: string; name: string | null }>;
  relatedSubcategories: Array<{ subcategoryId: string; name: string; sharedCount: number }>;

  // NEW
  implementationExamples: Array<{
    exampleId: string;
    ordinal: number;
    text: string;
  }>;
  informativeReferences: Array<{
    framework: string;         // normalized slug
    id: string;
    text: string | null;
    relationship: string | null;
  }>;
}
```

Data is fetched via a single additional query against the two new tables (plus a SELECT of `category_description`). Three parallel queries issued with `Promise.all` — no added latency in the happy path.

The list endpoint `/api/v1/frameworks/csf` does NOT need to change — the category description is only shown on expanded rows, so we fetch it alongside the detail.

## UI Changes

All in `src/views/CsfFramework.tsx`. No new components — reuse collapsible pattern already present.

### Function descriptions (tooltip)

Extend the `FUNCTIONS` constant:

```ts
const FUNCTIONS = [
  { id: 'GV', name: 'Govern',   description: 'Establish and monitor cybersecurity risk management strategy, expectations, and policy.' },
  { id: 'ID', name: 'Identify', description: 'Help determine the current cybersecurity risk to the organization.' },
  { id: 'PR', name: 'Protect',  description: 'Use safeguards to prevent or reduce cybersecurity risk.' },
  { id: 'DE', name: 'Detect',   description: 'Find and analyze possible cybersecurity attacks and compromises.' },
  { id: 'RS', name: 'Respond',  description: 'Take action regarding a detected cybersecurity incident.' },
  { id: 'RC', name: 'Recover',  description: 'Restore assets and operations affected by a cybersecurity incident.' },
];
```

Applied via `title` attribute on the function filter buttons. One-line tooltip — no new DOM.

### Category description (inline under category header)

Below the existing `{group.function} — {group.functionName} (N)` heading, add a single line showing `{group.categoryName}: {categoryDescription}` for the first subcategory in each new category block. Only rendered when description exists. Muted color, single paragraph, no wrapper card.

Subtle — the user's eye still lands on the subcategory rows first.

### Expanded row — new sections

Current structure of the expanded detail region at [CsfFramework.tsx:170-240](src/views/CsfFramework.tsx#L170):

```
Description (existing)
Category: <name> (existing)
ATT&CK Techniques — if any
Related Subcategories — if any
```

New structure:

```
Description (existing)
Category: <name> (existing, unchanged)

[NEW] If techniques.length === 0 AND implementationExamples.length > 0 AND informativeReferences.length > 0:
  Remove the current "No ATT&CK technique mappings yet" fallback entirely.
  The new sections replace the empty state.

ATT&CK Techniques (N) — if any (existing, unchanged)

[NEW] Implementation Examples (N)     [collapsible, default OPEN when techniques empty, CLOSED otherwise]
  • Ex1: {text}
  • Ex2: {text}

[NEW] Cross-framework References (N)  [collapsible, default CLOSED]
  NIST 800-53r5:  [PM-9] [PM-11] [PR-IP-3]
  CIS Controls v8:  [14.1] [14.2]
  ISO 27001:2022:  [A.5.1] [A.5.19]
  NIST 800-221A:  [GV.OV-01]

Related Subcategories (existing, unchanged)
```

**Chip styling:** same compact pill style already used for Related Subcategories. Grouped by framework (framework name as group label on the left, chips on the right).

**Click-throughs:**
- `800-53r5` chips → internal `/frameworks/nist-800-53/:id` if that route exists (check at implementation time; if not, plain label with `title` tooltip)
- `cis-v8` → external: `https://www.cisecurity.org/controls/v8`  (family-level link; CIS doesn't provide stable deep links per safeguard)
- `iso-27001-2022` → external: ISO's standards catalogue page (no public deep links per control)
- `800-221a` → external: NIST SP 800-221A landing page
- `800-207` → external: NIST SP 800-207 landing page

If no deep link is available, the chip is a plain `<span>` with a `title` tooltip — no dead `href`.

### Row chevron — move to left, right→down rotation

The current CSF row places a down-arrow chevron on the right that flips 180° when expanded. Change to a standard disclosure-widget pattern:

- **Position:** move the chevron to the **left** of the row, before the subcategory ID
- **Icon:** single right-pointing chevron (`M9 5l7 7-7 7`)
- **State:** closed → right-pointing (`›`), open → rotated 90° down (`∨`) via `rotate-90` class
- Matches the pattern introduced on `/frameworks/owasp` rows (same left-chevron placement)

### Collapsible mechanism

Reuse the existing `expanded` state pattern. Add local `useState` for two new toggles per expanded row:

```ts
const [examplesOpen, setExamplesOpen] = useState(false);
const [refsOpen, setRefsOpen] = useState(false);
```

Initial state of `examplesOpen` is `techniques.length === 0` — so empty rows land on the examples open by default.

## Layout Fix (bundled)

`src/components/layout/AppShell.tsx` — the main content wrapper at line 78:

```diff
- <div className="flex-1 flex flex-col lg:ml-52 min-h-screen">
+ <div className="flex-1 flex flex-col lg:ml-52 min-h-screen min-w-0">
```

**Root cause:** Flex items have implicit `min-width: auto`, which resolves to the item's min-content size — blocking descendant shrink-to-fit. CSF's long subcategory names with `truncate` (which sets `white-space: nowrap`) have a large min-content width. The wrapper grows past viewport to accommodate them, defeating the `overflow-x-hidden` on `<main>`. `min-w-0` overrides the auto default and lets the wrapper shrink normally.

**Why other pages work today:** they don't have long nowrap text that exceeds ~1000px of intrinsic min-content width. CSF was the first page to expose it.

**Verified:** with the fix applied via JS in a live Playwright session against the production site, wrapper width dropped from 1664px → 1061px at a 1275px viewport.

## Phases

Single bundled phase. No reason to split — ingest, API, and UI changes are tightly coupled, and the layout fix is a one-liner.

1. **Schema migration** — add two tables + one column, SQL file in `scripts/`
2. **Ingest script** — `scripts/seed-csf-enrichment.mjs`, run manually once, then hook into `sync-frameworks.mjs`
3. **API extension** — add fields to `CsfDetail` response type + route
4. **UI changes** — `CsfFramework.tsx` updates (new sections, category description, function tooltips)
5. **Layout fix** — `AppShell.tsx` one-line change
6. **Commit + push + verify on Vercel**

## Open Questions

None remaining — all previously-raised questions answered:

- ✅ Scope confirmed: Implementation Examples + Informative References + category descriptions + function tooltips
- ✅ Bundle with layout fix
- ✅ Collapsible sections inside expanded row
- ✅ External links for CIS/ISO/800-221A; internal for 800-53 where route exists

## Risks

1. **OLIR endpoint instability** — NIST occasionally reorganizes its OLIR services. Mitigation: ingest script validates response structure before upserting; if the endpoint is down, the script errors cleanly without corrupting data. Manual refresh cadence = low blast radius.
2. **Category description duplication** — denormalized onto every subcategory row (~185 copies of ~30 unique descriptions). Trivial DB footprint, simpler JOIN. Accepted trade-off.
3. **Chip visual density** — a subcategory with 20+ informative references could produce a busy row. Mitigation: `Cross-framework References (N)` header stays collapsible and defaults closed unless techniques are empty.
