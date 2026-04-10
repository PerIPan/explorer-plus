# NIST CSF v2 Integration Design

**Date:** 2026-04-10
**Status:** Approved — architect-reviewer feedback incorporated

## Goal

Add NIST Cybersecurity Framework v2 (Feb 2024) as a new framework overlay in MITRE Explorer Plus. Users should be able to browse CSF subcategories, see which ATT&CK techniques they map to, and pivot from any technique to the relevant CSF subcategories that cover it.

## Scope

- NIST CSF v2 with 6 Functions, ~22 Categories, ~106 Subcategories
- **Direct CTID CSF → ATT&CK technique mappings only** (one-hop, no 800-53 bridge)
- New entity type: `csf` (14th entity type)
- Dedicated page at `/frameworks/csf` + detail pages at `/frameworks/csf/[subcategoryId]`
- Integration into Technique detail page (Frameworks tab)
- Searchable from global SearchBar and as an entity in Relationships 360 explorer
- CSF as color-coded overlay on ATT&CK Matrix (by Function)
- New entity in data model force graph
- Sitemap + SSR metadata for all 106 subcategory pages

**Out of scope (deferred):**
- CSF → NIST 800-53 bridge (dropped due to semantic noise from generic controls)
- CVEs on CSF detail page (no clean bridge)
- Applications on CSF detail page (no clean bridge)
- Framework-overlay abstraction refactor (separate ADR)

## Data Model Rationale

**Why no 800-53 bridge?** CSF → 800-53 → ATT&CK is transitive but not logically entailing. Generic 800-53 controls (e.g., AC-06 Least Privilege) map to many techniques AND many CSF subcategories, producing noisy false connections. A CSF subcategory would appear connected to techniques it has no conceptual relationship to. Dropping the bridge eliminates this risk and cuts ~40% of the code complexity.

**Trade-off:** Users lose the "which 800-53 controls implement this CSF subcategory" view on the CSF page. Mitigation: they can already browse `/frameworks/nist` independently for 800-53 controls.

**Source of truth:** CTID's `center-for-threat-informed-defense/mappings-explorer` GitHub repo publishes direct CSF v2 subcategory → ATT&CK technique mappings as JSON/YAML, updated periodically.

---

## 1. Database Schema

Two new tables, added via idempotent migration.

### `csf_subcategories` (106 rows)

```sql
CREATE TABLE IF NOT EXISTS csf_subcategories (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  subcategory_id  VARCHAR(10) UNIQUE NOT NULL,  -- 'PR.AA-01'
  function        VARCHAR(4) NOT NULL,          -- 'PR'
  function_name   VARCHAR(50) NOT NULL,         -- 'Protect'
  category_id     VARCHAR(10) NOT NULL,         -- 'PR.AA'
  category_name   VARCHAR(100) NOT NULL,        -- 'Identity Management and Access Control'
  name            VARCHAR(255) NOT NULL,
  description     TEXT,
  version         VARCHAR(10) NOT NULL DEFAULT '2.0',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_csf_sub_function ON csf_subcategories(function);
CREATE INDEX IF NOT EXISTS idx_csf_sub_category ON csf_subcategories(category_id);
```

Function/category names are denormalized to avoid 3-level JOIN chains. 106 static rows — normalization gain is negligible.

### `csf_technique_mappings`

```sql
CREATE TABLE IF NOT EXISTS csf_technique_mappings (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  subcategory_id      VARCHAR(10) NOT NULL,
  attack_technique_id VARCHAR(20) NOT NULL,
  mapping_source      VARCHAR(50) NOT NULL DEFAULT 'ctid',
  is_draft            BOOLEAN NOT NULL DEFAULT FALSE,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (subcategory_id, attack_technique_id),
  FOREIGN KEY (subcategory_id) REFERENCES csf_subcategories(subcategory_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_csf_tech_attackid ON csf_technique_mappings(attack_technique_id);
CREATE INDEX IF NOT EXISTS idx_csf_tech_subcat   ON csf_technique_mappings(subcategory_id);
```

`is_draft` preserves CTID's draft flag where applicable. FK with cascade ensures a subcategory deletion cleans up its mappings.

### Migration file

`seed/migrate-csf.sql` — contains both `CREATE TABLE IF NOT EXISTS` statements + indexes + FK. Safe to run on existing production DB.

---

## 2. Data Ingestion

### One-time seed

`seed/seed-csf-subcategories.ts` — reads the 106 CSF v2 subcategories from a bundled JSON (source: NIST CSF v2 Core document). Upsert by `subcategory_id`. Static data, only re-run on CSF version bump.

### Weekly cron

`app/api/cron/sync-csf/route.ts` — mirrors `sync-d3fend` pattern:

```
Schedule: "0 5 * * 1"  // Mondays at 05:00 UTC
maxDuration: 300
```

**Sync strategy — transaction-wrapped nuke-and-replace:**

```ts
await client.query('BEGIN');
await client.query("DELETE FROM csf_technique_mappings WHERE mapping_source = 'ctid'");
// Fetch full mappings from CTID GitHub
// Bulk INSERT
await client.query('COMMIT');
```

Why nuke-and-replace: CTID occasionally removes/refines mappings. Append-only upsert would accumulate stale rows. The `WHERE mapping_source = 'ctid'` scope prevents touching any future non-CTID data.

**Failure handling:**
- Fetch 404 → fail loudly, log to `feed_sync_log`, do not touch DB
- JSON schema validation before DELETE — fail if required fields missing
- Transaction rollback on any error

**Data source URL:**
`https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/mappings/nist_csf/nist_csf-2.0/...` (exact path verified during implementation)

---

## 3. API Endpoints

### `GET /api/v1/frameworks/csf`

List all subcategories grouped by function. Cache 3600s.

```json
{
  "data": [
    { "function": "GV", "functionName": "Govern", "subcategories": [...] },
    { "function": "ID", "functionName": "Identify", "subcategories": [...] },
    ...
  ],
  "total": 106
}
```

Each subcategory item: `{ subcategoryId, categoryId, categoryName, name, description, techniqueCount }`.

### `GET /api/v1/frameworks/csf/[subcategoryId]`

Detail for one subcategory. Cache 3600s. Validates `^(GV|ID|PR|DE|RS|RC)\.[A-Z]{2}-\d{2}$`.

```json
{
  "subcategoryId": "PR.AA-01",
  "function": "PR",
  "functionName": "Protect",
  "categoryId": "PR.AA",
  "categoryName": "Identity Management and Access Control",
  "name": "Identities and credentials for authorized users...",
  "description": "...",
  "techniques": [
    { "attackId": "T1078", "name": "Valid Accounts", "tacticName": "Defense Evasion" }
  ],
  "relatedSubcategories": [
    { "subcategoryId": "ID.AM-03", "name": "..." }
  ]
}
```

`relatedSubcategories` are other subcategories sharing ≥3 techniques (a lightweight "see also" graph).

### `GET /api/v1/frameworks/csf/[subcategoryId]/techniques`

Techniques array only — used for Matrix highlight filter. Mirrors the existing `nist/[controlId]/techniques` endpoint.

### Updates to existing endpoints

- `GET /api/v1/frameworks/technique/[attackId]` — add `csf` array to response:
  ```json
  { "csf": [{ "subcategoryId": "PR.AA-01", "name": "...", "function": "PR" }] }
  ```
- `GET /api/v1/search` — include CSF subcategories in results (search `subcategory_id` + `name`)
- `GET /api/v1/entities` — add CSF subcategories to entity search index
- `GET /api/v1/frameworks/status` — add `csf_subcategories` + `csf_technique_mappings` counts
- `GET /api/v1/frameworks/by-techniques` — include CSF in aggregate response (for sector/actor maps)

---

## 4. Frontend Integration

### New page: `/frameworks/csf`

Mirrors existing `/frameworks/owasp` pattern but **flattened** — CSF has 106 subcategories across 6 functions. A 3-level nested accordion (function → category → subcategory) is UX-hostile. Instead:

**Layout:**
- **Top:** 6 function filter pills (GV/ID/PR/DE/RS/RC), click to filter
- **Search box** — filter by subcategory ID or name
- **Flat list** grouped by function (with category as an inline label, not a collapsible level)
- Each subcategory row: ID badge, name, technique count badge, expand chevron
- Expanded view: description, techniques list, related subcategories, "360 →" link

**Routing:**
- `app/frameworks/csf/page.tsx` — list view
- `app/frameworks/csf/[subcategoryId]/page.tsx` — same component, auto-expands the URL-matched subcategory (mirrors OWASP pattern)

**SEO:**
- `generateMetadata` per subcategory with unique `<title>` and `<meta description>` (subcategory description slice, not templated)
- Distinct `<h1>` per page — "PR.AA-01: Identities and credentials..." — to avoid thin/doorway page SEO penalty
- ISR with `revalidate = 3600`
- Add 106 URLs to `app/sitemap.ts`

### Technique detail page

New section in the Frameworks tab (after NIST 800-53):

```
NIST CSF v2 (3)
[PR.AA-01]  Identities and credentials... (Protect)
[DE.CM-06]  External service provider activities (Detect)
[PR.PS-05]  Installation and execution of unauthorized software (Protect)
```

Each entry is a clickable `EntityLink` to `/frameworks/csf/[subcategoryId]`. Function shown as a muted suffix for context.

### Relationships 360 Explorer

CSF becomes the 14th entity type:
- Added to `EntityType` union in `src/lib/types.ts`
- `EntityLink.tsx` gets CSF config (color indigo `#6366f1`, path `frameworks/csf`)
- `SearchBar.tsx` returns CSF in search results
- `Relationships.tsx` → `CsfMapView.tsx` new component (see §5)
- `RelationshipModel.tsx` force graph — add CSF node, edges to technique
- Data model legend — new CSF badge

### Matrix filter

`/matrix?entity=PR&type=csf-function` highlights techniques covered by the Protect function. Reuses the existing highlight pattern — add `'csf-function'` + `'csf'` to `highlightType` query handling in `Matrix.tsx`. The technique fetch calls the new `/api/v1/frameworks/csf/[subcategoryId]/techniques` endpoint (or a new `/functions/[function]/techniques` endpoint for the function-level filter).

### Component refactor: `FrameworkMapCard`

Before creating `CsfMapView.tsx`, extract shared MapCard logic from `OwaspMapView.tsx` into `src/components/relationships/shared/FrameworkMapCard.tsx`. This is ~200 lines of duplication today; extracting it pays back immediately on CSF and again on future frameworks.

The shared card handles: collapse state, section title with count badge, item list rendering, "show more" toggle, consistent spacing.

### `CsfMapView.tsx`

Renders sections (all via `FrameworkMapCard`):
- Subcategory details (ID, function, category, description)
- Linked ATT&CK techniques (with tactic groupings)
- Related CSF subcategories (see-also)
- Link to `/frameworks/csf/[subcategoryId]` for full detail page

**No CVE section, no applications section** (deferred per scope decision).

---

## 5. Color & Visual Design

CSF color: **indigo `#6366f1`** — distinct from existing framework colors:
- NIST 800-53: (existing, check current value)
- OWASP: `#059669` (emerald)
- Engage: (existing)
- VERIS: (existing)
- Data sources: neutral/gray (memory rule)

Used in:
- `EntityLink` badge background/border for CSF entities
- Force graph node fill for CSF nodes
- Data model legend
- Matrix filter highlight (light indigo background on matching cells)

---

## 6. Files to Create / Modify

### Create
- `seed/migrate-csf.sql` — table DDL + indexes + FK
- `seed/seed-csf-subcategories.ts` — one-time 106-row seed
- `seed/data/csf-v2-subcategories.json` — bundled CSF v2 Core data
- `app/api/v1/frameworks/csf/route.ts`
- `app/api/v1/frameworks/csf/[subcategoryId]/route.ts`
- `app/api/v1/frameworks/csf/[subcategoryId]/techniques/route.ts`
- `app/api/cron/sync-csf/route.ts`
- `app/frameworks/csf/page.tsx`
- `app/frameworks/csf/[subcategoryId]/page.tsx`
- `src/views/CsfFramework.tsx` — main CSF browser component
- `src/components/relationships/CsfMapView.tsx`
- `src/components/relationships/shared/FrameworkMapCard.tsx` — extracted shared component

### Modify
- `app/api/v1/frameworks/technique/[attackId]/route.ts` — add CSF to response
- `app/api/v1/search/route.ts` — add CSF search
- `app/api/v1/entities/route.ts` — add CSF to entity index
- `app/api/v1/frameworks/status/route.ts` — add CSF counts
- `app/api/v1/frameworks/by-techniques/route.ts` — add CSF aggregate
- `app/sitemap.ts` — add 106 CSF URLs
- `app/lib/data.ts` — add `fetchCsfSubcategory` with `cache()`
- `src/lib/types.ts` — add `'csf'` to `EntityType`, add `CsfSubcategory` interface
- `src/components/shared/EntityLink.tsx` — CSF entity config
- `src/components/layout/SearchBar.tsx` — CSF search results
- `src/views/TechniqueDetail.tsx` — CSF section in Frameworks tab
- `src/views/Relationships.tsx` — CSF entity handling + CsfMapView
- `src/views/Matrix.tsx` — CSF function highlight filter
- `src/components/relationships/RelationshipModel.tsx` — CSF node + edges
- `src/components/relationships/OwaspMapView.tsx` — migrate to use `FrameworkMapCard`
- `vercel.json` — add `sync-csf` cron schedule
- `README.md` — add CSF to features table

---

## 7. Testing Checklist

Before merging:
- [ ] Migration runs cleanly on production DB (`IF NOT EXISTS` safe on re-run)
- [ ] Seed script populates 106 subcategories
- [ ] Cron fetches from CTID and inserts mappings in a transaction
- [ ] Cron failure (404, bad JSON) does NOT delete existing data
- [ ] `/frameworks/csf` list view renders 106 items grouped by function
- [ ] Search filter within page works
- [ ] Function filter pills work
- [ ] `/frameworks/csf/PR.AA-01` deep link auto-expands the correct row
- [ ] Technique detail page T1078 shows PR.AA-01 in Frameworks tab
- [ ] Click on CSF badge navigates to subcategory page
- [ ] Global search for "PR.AA-01" returns the subcategory
- [ ] 360 map view for a CSF subcategory renders CsfMapView correctly
- [ ] Matrix `?entity=PR&type=csf-function` highlights Protect techniques
- [ ] `curl` on `/frameworks/csf/PR.AA-01` shows SSR `<title>` and `<meta description>`
- [ ] `/sitemap.xml` includes all 106 CSF URLs
- [ ] Force graph shows CSF nodes with indigo color
- [ ] OWASP page still works after `FrameworkMapCard` extraction

---

## 8. Risks & Mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| CTID repo structure drift (file path changes) | MEDIUM | Schema validate before DELETE; fail loudly on 404; monitor `feed_sync_log` |
| Thin/duplicate CSF pages → SEO demotion | MEDIUM | Unique `<h1>`, unique `<meta description>` per subcategory (not templated) |
| CSF v2.1 / v3 release | LOW | `version` column on `csf_subcategories` allows multi-version coexistence |
| Force graph clutter with 14th entity type | LOW | CSF appears only when searched; not added to default node set |
| `FrameworkMapCard` extraction breaks OWASP | MEDIUM | Extract first, run OwaspMapView tests, then clone |
| Subcategory ID URL encoding | LOW | `PR.AA-01` is URL-safe (dot and dash), but add encoding in EntityLink defensively |
| Low CSF adoption post-launch | LOW | Add telemetry counter on `/frameworks/csf` visits; reassess in 30 days |

---

## 9. Phased Implementation

### Phase 0 — Foundation (1 session)
- Migration file + run on production DB
- Seed script + 106 subcategories populated
- Extract `FrameworkMapCard` from OwaspMapView (refactor in place, verify OWASP still works)

### Phase 1 — API Layer (1 session)
- 3 new CSF route handlers
- Update 5 existing endpoints (technique, search, entities, status, by-techniques)
- `sync-csf` cron handler (nuke-and-replace transaction)
- Manual curl verification of all endpoints

### Phase 2 — Frontend (1-2 sessions)
- `/frameworks/csf` page + subcategory detail page
- `CsfMapView` component
- Update `EntityLink`, `SearchBar`, `Relationships`, `Matrix`, `RelationshipModel`, `TechniqueDetail`
- Add to `app/lib/data.ts` + sitemap

### Phase 3 — Verification (1 session)
- Full testing checklist
- Playwright E2E: navigate CSF page, click subcategory, verify technique shows CSF badge
- Lighthouse check on CSF detail page (SEO score)
- Deploy + Google Search Console submit updated sitemap

**Total: 4-5 sessions**

---

## 10. Rollback Plan

If the feature needs to be reverted after deploy:
1. Set `vercel.json` cron to disabled (or remove the entry)
2. Revert the git commit range
3. Tables stay in place (no data loss) — harmless if unused
4. Vercel instant rollback if production breaks

No destructive DB operation involved. The migration is additive only.
