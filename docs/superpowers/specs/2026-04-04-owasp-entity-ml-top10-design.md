# OWASP Entity + ML/LLM Top 10 Design

**Date:** 2026-04-04
**Status:** Draft — reviewed by architect-reviewer + postgres-pro

## Goal

Make OWASP a full entity type in MITRE Explorer Plus — searchable, linkable, visible on technique/CVE detail pages — and extend coverage to OWASP ML Top 10 (2023) and LLM Top 10 (2025) for AI/ML security risks.

## Scope

- OWASP as `EntityType` with pills, detail pages, search
- ML Top 10 + LLM Top 10 seeded alongside Web Top 10
- Relationship model edges
- Technique detail: show OWASP categories in Frameworks tab
- CVE detail: show OWASP category badges
- A2A agent skills updated
- About modal + sidebar updated

**Out of scope:** OpenCRE integration (future phase), 360 map view for OWASP.

---

## 1. Database Schema

### 1.1 Migration

```sql
BEGIN;

-- Add columns
ALTER TABLE owasp_top10
  ADD COLUMN framework VARCHAR(50) NOT NULL DEFAULT 'web-2021',
  ADD COLUMN atlas_technique_ids TEXT[] NOT NULL DEFAULT '{}',
  ADD COLUMN is_draft BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- Backfill existing rows explicitly
UPDATE owasp_top10 SET framework = 'web-2021' WHERE framework = 'web-2021';

-- Drop old unique constraint (it's a constraint, not just an index)
ALTER TABLE owasp_top10 DROP CONSTRAINT IF EXISTS owasp_top10_category_id_key;

-- Drop redundant single-column index
DROP INDEX IF EXISTS idx_owasp_top10_category;

-- New composite unique index
CREATE UNIQUE INDEX idx_owasp_category_framework
  ON owasp_top10(category_id, framework);

-- Framework CHECK constraint
ALTER TABLE owasp_top10
  ADD CONSTRAINT chk_owasp_framework
  CHECK (framework IN ('web-2021', 'ml-2023', 'llm-2025'));

-- GIN indexes for array overlap queries
CREATE INDEX idx_owasp_cwe_ids_gin ON owasp_top10 USING gin(cwe_ids);
CREATE INDEX idx_owasp_atlas_ids_gin ON owasp_top10 USING gin(atlas_technique_ids);

COMMIT;
```

### 1.2 Framework values

| framework | Categories | Bridge to techniques | is_draft |
|-----------|-----------|---------------------|----------|
| `web-2021` | A01–A10 | `cwe_ids` → `capec_mappings` → `techniques` | false |
| `ml-2023` | ML01–ML10 | `atlas_technique_ids` → `techniques` (domain=atlas-attack) + hand-mapped CWEs | true (v0.3) |
| `llm-2025` | LLM01–LLM10 | `atlas_technique_ids` + community `cwe_ids` → CAPEC → `techniques` | false |

**ATLAS data confirmed:** 155 ATLAS techniques exist in `techniques` table with `domain = 'atlas-attack'`, IDs format `AML.Txxxx`.

### 1.3 Seed data

Seed script uses `ON CONFLICT (category_id, framework) DO NOTHING` inside a single transaction for idempotency.

**ML Top 10 (2023 v0.3):**

| ID | Name | atlas_technique_ids | cwe_ids |
|----|------|-------------------|---------|
| ML01 | Input Manipulation Attack | {AML.T0043} | {CWE-20} |
| ML02 | Data Poisoning Attack | {AML.T0020} | {CWE-506} |
| ML03 | Model Inversion Attack | {AML.T0024} | {} |
| ML04 | Membership Inference Attack | {AML.T0025} | {} |
| ML05 | Model Theft | {AML.T0044} | {} |
| ML06 | AI Supply Chain Attacks | {AML.T0010} | {CWE-1357} |
| ML07 | Transfer Learning Attack | {AML.T0019} | {} |
| ML08 | Model Skewing | {AML.T0031} | {} |
| ML09 | Output Integrity Attack | {AML.T0047} | {CWE-345} |
| ML10 | Model Poisoning | {AML.T0018} | {CWE-506} |

**LLM Top 10 (2025 v2.0):**

| ID | Name | atlas_technique_ids | cwe_ids |
|----|------|-------------------|---------|
| LLM01 | Prompt Injection | {AML.T0051} | {CWE-1352,CWE-74} |
| LLM02 | Sensitive Information Disclosure | {AML.T0024,AML.T0025} | {CWE-200,CWE-359} |
| LLM03 | Supply Chain | {AML.T0010} | {CWE-1357} |
| LLM04 | Data and Model Poisoning | {AML.T0020,AML.T0018} | {CWE-506} |
| LLM05 | Improper Output Handling | {} | {CWE-116,CWE-79} |
| LLM06 | Excessive Agency | {} | {CWE-250,CWE-269} |
| LLM07 | System Prompt Leakage | {AML.T0024} | {CWE-200} |
| LLM08 | Vector and Embedding Weaknesses | {AML.T0020} | {} |
| LLM09 | Misinformation | {AML.T0048} | {} |
| LLM10 | Unbounded Consumption | {} | {CWE-400,CWE-770} |

**URLs:**
- ML: `https://mltop10.info/` (category pages TBD)
- LLM: `https://genai.owasp.org/llmrisk/llmXX-slug/`

---

## 2. EntityType + EntityLink

### 2.1 types.ts

Add to `EntityType` union:

```ts
export type EntityType =
  | 'technique' | 'group' | 'software' | 'campaign'
  | 'mitigation' | 'data_source' | 'tactic'
  | 'owasp';  // NEW
```

Add TypeScript interface:

```ts
export interface OwaspCategory {
  categoryId: string;
  name: string;
  description: string | null;
  url: string | null;
  framework: string;
  isDraft: boolean;
  cweCount: number;
  techniqueCount: number;
  atlasCount: number;
  cveCount: number;
}
```

### 2.2 EntityLink.tsx

Rename `attackId` prop → `entityId` (with `attackId` kept as alias for backward compat during migration).

Add OWASP config:

```ts
owasp: {
  color: 'text-[var(--accent-orange)]',
  bg: 'bg-[var(--orange-faint)]',
  border: 'border-[var(--orange-dim)]',
  path: 'frameworks/owasp',
}
```

`MAP_TABS`: defer 360 view — omit `owasp` entry for now.

### 2.3 Validation

Update `api/v1/lib/validate.ts` to include `'owasp'` in allowed entity types.
Update `api/v1/export/[entityType].ts` to support OWASP export.

---

## 3. API Changes

### 3.1 `GET /frameworks/owasp`

Add optional `?framework=web-2021|ml-2023|llm-2025` query param. Default: return all.

Rewrite as single CTE-based query to avoid N+1 correlated subqueries:

```sql
WITH counts AS (
  SELECT o.id,
    (SELECT COUNT(DISTINCT cm.attack_technique_id)
     FROM capec_mappings cm
     WHERE cm.technique_id IS NOT NULL AND cm.cwe_id = ANY(o.cwe_ids)) AS technique_count,
    (SELECT COUNT(DISTINCT cw.cve_id)
     FROM cve_weaknesses cw
     WHERE cw.cwe_id = ANY(o.cwe_ids)) AS cve_count,
    array_length(o.atlas_technique_ids, 1) AS atlas_count
  FROM owasp_top10 o
)
SELECT o.*, c.technique_count, c.cve_count, c.atlas_count
FROM owasp_top10 o JOIN counts c ON c.id = o.id
ORDER BY o.framework, o.category_id;
```

Response shape:

```ts
{
  data: OwaspCategory[],
  frameworks: string[]
}
```

Cache TTL: 3600s. Note: after seeding ML/LLM data, caches will take up to 1h to refresh.

### 3.2 `GET /frameworks/owasp/:categoryId`

Extend validation regex: `/^(A|ML|LLM)\d{2}$/i`.

Response gains:
- `framework: string`
- `isDraft: boolean`
- `atlasTechniques: Array<{ attackId: string; name: string }>` — joined from `techniques WHERE attack_id = ANY(atlas_technique_ids) AND domain = 'atlas-attack'`
- `relatedCategories: Array<{ categoryId: string; name: string; framework: string }>` — categories from other frameworks sharing ≥1 CWE or ATLAS ID

### 3.3 `GET /frameworks/technique/:attackId`

Extend `FrameworkData` to include:

```ts
owasp: Array<{ categoryId: string; name: string; framework: string }>
```

Two query paths:
- **ATT&CK techniques:** find OWASP categories whose `cwe_ids` overlap with CWEs linked to this technique via `capec_mappings`
- **ATLAS techniques:** find OWASP categories whose `atlas_technique_ids` contain this `attack_id`

### 3.4 Search

Add OWASP to search endpoint — match on `category_id` or `name`. Return in new `owasp` key in `SearchResponse`.

Add text search support: `CREATE INDEX idx_owasp_search ON owasp_top10 USING gin(to_tsvector('english', name || ' ' || COALESCE(description, '')))`.

---

## 4. Frontend Changes

### 4.1 OWASP page (`OwaspTop10.tsx`)

- Add framework tab bar at top: **Web (2021)** | **ML (2023)** | **LLM (2025)** | **All**
- Filter categories by selected framework
- ML categories with `is_draft = true` show a "DRAFT" badge
- ML/LLM categories show ATLAS technique links alongside CWE→ATT&CK techniques
- Update page title dynamically: "OWASP Top 10 — Web" / "ML" / "LLM"
- Update subtitle per framework

### 4.2 Technique detail — Frameworks tab

Add "OWASP Categories" section after existing NIST/Engage/VERIS/Cloud sections:

```tsx
{data.owasp?.length > 0 && (
  <section>
    <h3>OWASP Categories ({data.owasp.length})</h3>
    {data.owasp.map(cat => (
      <EntityLink type="owasp" entityId={cat.categoryId} name={`${cat.name} (${cat.framework})`} />
    ))}
    <Link to="/frameworks/owasp">Browse all OWASP categories</Link>
  </section>
)}
```

### 4.3 CVE detail

Add OWASP badges. New API call or inline query: CVE → `cve_weaknesses.cwe_id` → match against `owasp_top10.cwe_ids` (array `&&` overlap).

New section showing: `A03 Injection`, `LLM05 Improper Output Handling`.

### 4.4 Search page

Add OWASP results section with orange pills.

### 4.5 Sidebar

Update tooltip:

```ts
{ path: '/frameworks/owasp', label: 'OWASP Top 10', tooltip: 'web, ML, and LLM security risks mapped to ATT&CK + ATLAS' },
```

---

## 5. Relationship Model

### 5.1 Add edges

```ts
{ from: 'owasp', to: 'technique', label: 'maps via CWE', style: 'dashed' },
{ from: 'owasp', to: 'atlas', label: 'AI risks', style: 'dashed' },
{ from: 'owasp', to: 'cve', label: 'categorizes', style: 'dashed' },
```

### 5.2 Update node description

```ts
{ id: 'owasp', label: 'OWASP Top 10', x: 1240, y: 50, color: '#f97316', bg: '#f9731618',
  path: '/frameworks/owasp',
  description: 'Web, ML, and LLM security risks mapped to techniques via CWE + ATLAS',
  category: 'compliance' },
```

---

## 6. A2A Agent Protocol

### 6.1 Update skills in `agent-card.json`

```json
{
  "id": "owasp-top10",
  "name": "OWASP Top 10 Analysis",
  "description": "Get OWASP Top 10 categories for Web (2021), ML (2023), and LLM (2025) security risks mapped to ATT&CK + ATLAS techniques via CWE.",
  "examples": [
    "Show me the OWASP Top 10 categories",
    "What techniques relate to OWASP A01 Broken Access Control?",
    "Show me the ML Top 10 AI security risks",
    "Which ATLAS techniques map to LLM01 Prompt Injection?",
    "Compare Web and LLM OWASP supply chain risks"
  ],
  "tags": ["owasp", "top10", "web-security", "appsec", "compliance", "ml-security", "llm-security", "ai-risks"]
}
```

### 6.2 Update A2A handler (`api/a2a/index.ts`)

- `get_owasp_top10`: add optional `framework` param
- `get_owasp_category`: extend regex to accept `ML\d{2}` and `LLM\d{2}`
- Update system prompt to mention ML/LLM Top 10

---

## 7. About Modal

Update OWASP bullet in `App.tsx`:

```
OWASP Top 10 — Web (2021), ML (2023), LLM (2025) security risks mapped to techniques via CWE→CAPEC + ATLAS
```

---

## 8. Seed Script

Create `scripts/seed-owasp-ml-llm.mjs`:
- Runs migration (ALTER TABLE) first, idempotent with `IF NOT EXISTS` / `ADD COLUMN IF NOT EXISTS`
- Inserts ML01–ML10 and LLM01–LLM10 into `owasp_top10`
- Uses `ON CONFLICT (category_id, framework) DO NOTHING` inside a single transaction
- Sources: hardcoded from OWASP official lists

---

## Resolved Questions (from review)

1. **ATLAS data** — Confirmed: 155 ATLAS techniques in `techniques` table, IDs `AML.Txxxx`
2. **ML Top 10 draft status** — `is_draft` boolean column added; UI shows "DRAFT" badge
3. **EntityLink prop naming** — Rename `attackId` → `entityId` (keep alias for backward compat)
4. **N+1 queries** — Rewritten as CTE-based query; `atlasCount` from `array_length` (no subquery)
5. **Index gaps** — GIN indexes added for `cwe_ids` and `atlas_technique_ids`; text search GIN for search
6. **Constraint safety** — `DROP CONSTRAINT` instead of `DROP INDEX`; wrapped in transaction
7. **360 view** — Deferred to future phase

## Resolved Open Questions

1. **ATLAS IDs verified** — all 12 unique ATLAS IDs from seed data confirmed in `techniques` table (domain=atlas-attack)
2. **CWE mapping confidence** — add `mapping_confidence` indicator on EntityLink pills. Web (2021) = "official", ML (2023) = "community", LLM (2025) = "community". Show as tooltip on hover: "Community-mapped CWEs — not OWASP-official"
3. **Cache after seed** — accept 1h stale window; seed script logs a reminder to wait or manually purge via Vercel dashboard
