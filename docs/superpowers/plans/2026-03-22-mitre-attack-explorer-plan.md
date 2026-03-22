# MITRE ATT&CK Explorer — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a full-stack ATT&CK threat intelligence explorer with live CTI feeds, deployed on Vercel.

**Architecture:** React 18 + TypeScript frontend (Vite, Tailwind, TanStack Query, D3, Recharts) → Vercel serverless TypeScript API (`@vercel/postgres`) → PostgreSQL (local / Neon). Python seed pipeline loads STIX data. Vercel Cron + GitHub Actions ingest live CTI feeds.

**Tech Stack:** React 18, TypeScript, Tailwind CSS, Vite, TanStack Query, D3.js, Recharts, DOMPurify, `@vercel/postgres`, `pg`, `zod`, `psycopg` 3, `mitreattack-python`

**Spec:** `docs/superpowers/specs/2026-03-22-mitre-attack-explorer-design.md`

**Repo:** https://github.com/PerIPan/mitre-attack-explorer

---

## Chunk 1: Database Schema + Seed Pipeline

### File Structure

```
seed/
  schema.sql              all CREATE TABLE + INDEX statements
  extract.py              STIX → normalized Python dicts
  sector_extractor.py     keyword matching for group → sector tags
  verify.py               post-seed integrity checks
  seed.py                 orchestrator: schema → extract → insert → verify
  requirements.txt        psycopg[binary], mitreattack-python, requests
  sectors.json            curated keyword map
```

---

### Task 1.1: Create database and schema.sql

**Files:**
- Create: `seed/schema.sql`

- [ ] **Step 1: Create the local database**

```bash
/Applications/Postgres.app/Contents/Versions/18/bin/psql -U postgres -c "CREATE DATABASE mitre_attack;"
```

- [ ] **Step 2: Write schema.sql**

Write all CREATE TABLE statements from the spec's "Database Schema" section. Include:
- 10 entity tables: `seed_metadata`, `tactics`, `techniques`, `threat_groups`, `attack_software`, `mitigations`, `campaigns`, `data_sources`, `data_components`, `sectors`
- 11 relationship tables: `technique_tactics`, `group_techniques`, `group_software`, `software_techniques`, `mitigation_techniques`, `technique_data_components`, `campaign_techniques`, `campaign_software`, `group_campaigns`, `group_sectors`
- All indexes from spec (full-text GIN, lookup, FK, partial)
- Wrap in `BEGIN; ... COMMIT;` transaction
- Start with `TRUNCATE ... CASCADE` for idempotency (not DROP)

Ref: Spec "Database Schema" section — copy SQL verbatim.

- [ ] **Step 3: Run schema against local DB**

```bash
/Applications/Postgres.app/Contents/Versions/18/bin/psql -U postgres -d mitre_attack -f seed/schema.sql
```

Expected: no errors, all tables created.

- [ ] **Step 4: Verify tables exist**

```bash
/Applications/Postgres.app/Contents/Versions/18/bin/psql -U postgres -d mitre_attack -c "\dt"
```

Expected: 21+ tables listed.

- [ ] **Step 5: Commit**

```bash
git add seed/schema.sql
git commit -m "feat: database schema with all entity + relationship tables"
```

---

### Task 1.2: Seed requirements + sectors.json

**Files:**
- Create: `seed/requirements.txt`
- Create: `seed/sectors.json`

- [ ] **Step 1: Write seed/requirements.txt**

```
mitreattack-python==5.4.3
psycopg[binary]==3.2.6
requests==2.32.5
```

- [ ] **Step 2: Write seed/sectors.json**

Copy the keyword map from the spec's "Sector Keyword Map" section. Use word-boundary regex patterns for short keywords (e.g. `\\bIT\\b`).

- [ ] **Step 3: Install into venv**

```bash
source venv/bin/activate
pip install -r seed/requirements.txt
```

- [ ] **Step 4: Commit**

```bash
git add seed/requirements.txt seed/sectors.json
git commit -m "feat: seed dependencies and sector keyword map"
```

---

### Task 1.3: Extract module — STIX → normalized dicts

**Files:**
- Create: `seed/extract.py`

- [ ] **Step 1: Write extract.py**

Module that loads `data/enterprise-attack.json` via `MitreAttackData` and returns normalized dicts for each entity type. Must extract:

- **Tactics**: `stix_id`, `attack_id`, `name`, `description`, `url`, `sort_order` (from kill chain phase ordering), `stix_created`, `stix_modified`
- **Techniques**: all fields including `platforms`, `is_subtechnique`, `parent_technique_id` (resolve via attack_id prefix), `detection`, `is_revoked`, `is_deprecated`, `revoked_by_stix_id`
- **Groups**: all fields including `aliases`
- **Software**: all fields including `type` (malware vs tool), `platforms`, `aliases`
- **Mitigations**: all fields
- **Campaigns**: all fields including `first_seen`, `last_seen`
- **Data Sources**: all fields
- **Data Components**: all fields including `data_source_id` (resolve via STIX relationship)
- **All relationships**: `group_techniques`, `group_software`, `software_techniques`, `mitigation_techniques`, `technique_data_components`, `campaign_techniques`, `campaign_software`, `group_campaigns`, `technique_tactics`

Each relationship also extracts the `description` field (procedure examples).

Key implementation notes:
- Use `attack.get_techniques(remove_revoked_deprecated=False)` — keep revoked/deprecated with flags
- For `sort_order` on tactics: map kill chain phase names to integers (Reconnaissance=1, Resource Development=2, ..., Impact=14)
- For `url`: build from `https://attack.mitre.org/{type}/{attack_id}`
- Extract `stix_created`/`stix_modified` from STIX object `.created`/`.modified` properties
- `data_components` don't have their own ATT&CK IDs — that's expected

Function signature:
```python
def extract_all(stix_path: str) -> dict:
    """Returns {'tactics': [...], 'techniques': [...], 'groups': [...], ...}"""
```

- [ ] **Step 2: Test extraction locally**

```python
source venv/bin/activate
python -c "from seed.extract import extract_all; d = extract_all('data/enterprise-attack.json'); print({k: len(v) for k, v in d.items()})"
```

Expected: counts matching spec (~14 tactics, ~691 techniques, ~172 groups, etc.)

- [ ] **Step 3: Commit**

```bash
git add seed/extract.py
git commit -m "feat: STIX extraction module for all ATT&CK entity types"
```

---

### Task 1.4: Sector extractor

**Files:**
- Create: `seed/sector_extractor.py`

- [ ] **Step 1: Write sector_extractor.py**

Loads `sectors.json`, scans each group's description against keyword patterns using `re.search` with word-boundary matching. Returns list of `{group_attack_id, sector_name, matched_keywords}` dicts. Marks `source='auto'`.

```python
def extract_sectors(groups: list[dict], sectors_path: str = 'seed/sectors.json') -> list[dict]:
    """Returns [{'group_attack_id': 'G0016', 'sector_name': 'Government', 'matched_keywords': ['government'], 'source': 'auto'}, ...]"""
```

- [ ] **Step 2: Test sector extraction**

```python
python -c "
from seed.extract import extract_all
from seed.sector_extractor import extract_sectors
d = extract_all('data/enterprise-attack.json')
sectors = extract_sectors(d['groups'])
print(f'Total mappings: {len(sectors)}')
# Show sample
for s in sectors[:5]: print(s)
"
```

- [ ] **Step 3: Commit**

```bash
git add seed/sector_extractor.py
git commit -m "feat: sector keyword extractor for group-industry mapping"
```

---

### Task 1.5: Seed orchestrator

**Files:**
- Create: `seed/seed.py`

- [ ] **Step 1: Write seed.py**

Main script that:
1. Parses args: `--update` (download fresh STIX), `--confirm-destructive` (required for prod)
2. Checks `DATABASE_URL` — refuses to run against Neon/Vercel without `--confirm-destructive`
3. Optionally downloads fresh STIX JSON with SHA-256 hash verification
4. Runs `schema.sql` via psycopg
5. Calls `extract_all()` to get normalized data
6. Calls `extract_sectors()` for sector mappings
7. Inserts all entities in dependency order (tactics first, then techniques, etc.)
8. Inserts all relationships
9. Writes `seed_metadata` record with version, hash, counts, duration
10. All within a single transaction

Insert order (respects FK dependencies):
1. tactics
2. techniques (parent techniques first, then sub-techniques)
3. threat_groups
4. attack_software
5. mitigations
6. campaigns
7. data_sources
8. data_components
9. sectors
10. All relationship tables
11. group_sectors
12. seed_metadata

Use `psycopg.Connection` with `executemany()` for batch inserts. Use parameterized queries throughout.

- [ ] **Step 2: Run seed against local DB**

```bash
source venv/bin/activate
DATABASE_URL=postgresql://postgres@localhost:5432/mitre_attack python seed/seed.py
```

Expected: seed completes with counts printed. No errors.

- [ ] **Step 3: Commit**

```bash
git add seed/seed.py
git commit -m "feat: seed orchestrator with transaction safety and prod guard"
```

---

### Task 1.6: Post-seed verification

**Files:**
- Create: `seed/verify.py`

- [ ] **Step 1: Write verify.py**

Connects to DB, checks:
- Entity counts (techniques, groups, etc.) are within expected ranges
- All FK references in relationship tables resolve (no orphans)
- `seed_metadata` has an entry
- Prints summary report

```python
def verify(database_url: str) -> bool:
    """Returns True if all checks pass, prints report."""
```

- [ ] **Step 2: Run verification**

```bash
DATABASE_URL=postgresql://postgres@localhost:5432/mitre_attack python -c "from seed.verify import verify; verify('postgresql://postgres@localhost:5432/mitre_attack')"
```

- [ ] **Step 3: Add verify call to seed.py** (after commit in the transaction)

- [ ] **Step 4: Commit**

```bash
git add seed/verify.py seed/seed.py
git commit -m "feat: post-seed verification with integrity checks"
```

---

### Task 1.7: Add npm seed scripts to package.json

**Files:**
- Create: `package.json`

- [ ] **Step 1: Initialize npm project**

```bash
npm init -y
```

- [ ] **Step 2: Add seed scripts to package.json**

```json
{
  "scripts": {
    "seed": "./venv/bin/python seed/seed.py",
    "seed:prod": "DATABASE_URL=$POSTGRES_URL ./venv/bin/python seed/seed.py --confirm-destructive",
    "seed:update": "./venv/bin/python seed/seed.py --update"
  }
}
```

- [ ] **Step 3: Test npm run seed**

```bash
npm run seed
```

- [ ] **Step 4: Commit and push**

```bash
git add package.json
git commit -m "feat: npm seed scripts"
git push origin main
```

---

## Chunk 2: API Layer

### File Structure

```
api/
  v1/
    dashboard.ts
    matrix.ts
    search.ts
    procedures.ts
    export/
      [entityType].ts
    techniques/
      index.ts
      [attackId].ts
    groups/
      index.ts
      [attackId].ts
    campaigns/
      index.ts
      [attackId].ts
    software/
      index.ts
      [attackId].ts
    data-sources/
      index.ts
      [attackId].ts
    mitigations/
      index.ts
      [attackId].ts
    tactics/
      index.ts
      [attackId].ts
    sectors/
      index.ts
      [slug].ts
    relationships/
      [attackId].ts
    _lib/
      db.ts
      validate.ts
      middleware.ts
      queries.ts
      types.ts
      rateLimit.ts
server/
  dev-server.ts
tsconfig.json
vercel.json
```

---

### Task 2.1: Project setup — TypeScript, dependencies, config

**Files:**
- Create: `tsconfig.json`
- Modify: `package.json`
- Create: `vercel.json`

- [ ] **Step 1: Install TypeScript + API dependencies**

```bash
npm install typescript @vercel/postgres @vercel/node pg zod
npm install -D @types/node @types/pg tsx
```

- [ ] **Step 2: Create tsconfig.json**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "outDir": "dist",
    "rootDir": ".",
    "baseUrl": ".",
    "paths": { "@lib/*": ["api/v1/_lib/*"] }
  },
  "include": ["api/**/*.ts", "server/**/*.ts", "src/**/*.ts"],
  "exclude": ["node_modules", "dist"]
}
```

- [ ] **Step 3: Create vercel.json**

Copy from spec "Vercel Configuration" section — includes `crons`, `rewrites`, `headers` (security headers + CSP).

- [ ] **Step 4: Commit**

```bash
git add tsconfig.json vercel.json package.json package-lock.json
git commit -m "feat: TypeScript + Vercel config with security headers"
```

---

### Task 2.2: API shared library — db, types, validate, middleware

**Files:**
- Create: `api/v1/_lib/db.ts`
- Create: `api/v1/_lib/types.ts`
- Create: `api/v1/_lib/validate.ts`
- Create: `api/v1/_lib/middleware.ts`
- Create: `api/v1/_lib/queries.ts`

- [ ] **Step 1: Write db.ts**

Unified query interface. Uses `@vercel/postgres` `sql` template literal in production (auto-detects `POSTGRES_URL`). Falls back to `pg.Pool` with `DATABASE_URL` for local dev. Exports `query(text, params)` function. Sets `statement_timeout` to 5 seconds.

- [ ] **Step 2: Write types.ts**

TypeScript interfaces for all API responses: `Technique`, `Group`, `Software`, `Campaign`, `DataSource`, `Mitigation`, `Tactic`, `Sector`, `PaginatedResponse<T>`, `ErrorResponse`, `SearchResponse`, `GraphData`, `MatrixData`.

- [ ] **Step 3: Write validate.ts**

Zod schemas for all route/query params per spec:
- `attackIdSchema`: regex `^(TA|T|G|S|M|C|DS)\d{4}(\.\d{3})?$`
- `slugSchema`: regex `^[a-z0-9-]+$`
- `searchSchema`: min 3, max 200 chars
- `paginationSchema`: page (positive int, max 1000), limit (positive int, clamped 1-200)
- `platformSchema`: allowlist
- `softwareTypeSchema`: enum `malware | tool`
- `sortOrderSchema`: enum `asc | desc`
- `exportSchema`: entityType allowlist, format enum `csv | json`

- [ ] **Step 4: Write middleware.ts**

`withHandler(allowedMethods, handler)` wrapper that:
- Enforces HTTP method (returns 405)
- Runs zod validation
- Catches errors → returns sanitized `{ error: "Internal server error", code: "INTERNAL_ERROR" }`
- Sets `Cache-Control` headers based on route type
- Sets CORS headers (origin-restricted in prod, `localhost:5173` in dev)

- [ ] **Step 5: Write queries.ts**

Reusable query builders:
- `searchQuery(table, searchTerm)` — uses `plainto_tsquery('english', $1)` (never raw `to_tsquery`)
- `paginateQuery(baseQuery, page, limit)` — adds `LIMIT/OFFSET` + count
- `buildFilterQuery(filters)` — dynamic WHERE clause builder

- [ ] **Step 6: Commit**

```bash
git add api/v1/_lib/
git commit -m "feat: API shared library — db, validation, middleware, query builders"
```

---

### Task 2.3: Core entity list + detail endpoints

Build all entity endpoints. Each follows the same pattern:
- `index.ts`: paginated list with search/filter/sort
- `[attackId].ts`: detail with pre-joined relationships

**Files:**
- Create: `api/v1/techniques/index.ts` + `api/v1/techniques/[attackId].ts`
- Create: `api/v1/groups/index.ts` + `api/v1/groups/[attackId].ts`
- Create: `api/v1/campaigns/index.ts` + `api/v1/campaigns/[attackId].ts`
- Create: `api/v1/software/index.ts` + `api/v1/software/[attackId].ts`
- Create: `api/v1/data-sources/index.ts` + `api/v1/data-sources/[attackId].ts`
- Create: `api/v1/mitigations/index.ts` + `api/v1/mitigations/[attackId].ts`
- Create: `api/v1/tactics/index.ts` + `api/v1/tactics/[attackId].ts`
- Create: `api/v1/sectors/index.ts` + `api/v1/sectors/[slug].ts`

- [ ] **Step 1: Write techniques endpoints**

List: paginated, filters (tactic, platform, search), nested sub-techniques under parents, `include_deprecated` toggle, sort/order.
Detail: technique + related groups (with procedure examples), software, mitigations, data components, sub-techniques, campaigns.

- [ ] **Step 2: Write groups endpoints**

List: paginated, filters (sector, search), sort/order.
Detail: group + related techniques (procedures), software, campaigns, sectors.

- [ ] **Step 3: Write campaigns endpoints**

List: paginated, search, sort/order.
Detail: campaign + related techniques, software, groups, temporal data.

- [ ] **Step 4: Write software endpoints**

List: paginated, filters (type, platform, search), sort/order.
Detail: software + related techniques (procedures), groups, campaigns.

- [ ] **Step 5: Write remaining endpoints** (data-sources, mitigations, tactics, sectors)

Follow same pattern. Tactics list ordered by `sort_order`. Data source detail includes nested data components + linked techniques.

- [ ] **Step 6: Commit**

```bash
git add api/v1/techniques/ api/v1/groups/ api/v1/campaigns/ api/v1/software/ api/v1/data-sources/ api/v1/mitigations/ api/v1/tactics/ api/v1/sectors/
git commit -m "feat: all entity list + detail API endpoints"
```

---

### Task 2.4: Special endpoints — dashboard, matrix, search, relationships, export, procedures

**Files:**
- Create: `api/v1/dashboard.ts`
- Create: `api/v1/matrix.ts`
- Create: `api/v1/search.ts`
- Create: `api/v1/relationships/[attackId].ts`
- Create: `api/v1/export/[entityType].ts`
- Create: `api/v1/procedures.ts`

- [ ] **Step 1: Write dashboard.ts**

Returns stats (entity counts), top 10 groups by technique count, tactic distribution, sector breakdown, ATT&CK version from `seed_metadata`.

- [ ] **Step 2: Write matrix.ts**

Returns full tactic→technique mapping with group usage counts per technique. Tactics ordered by `sort_order`. Accepts `domain` filter. Single payload, cached aggressively.

- [ ] **Step 3: Write search.ts**

Global full-text search across all entity tables using `plainto_tsquery`. Returns grouped results: `{ techniques, groups, software, mitigations, campaigns, data_sources }`. Min 3 char query. Top 20 per entity type.

- [ ] **Step 4: Write relationships/[attackId].ts**

Queries all relationship tables for an entity. Returns `{ center, nodes, edges, truncated }` graph data. Server-side limit (default 200 nodes). Includes campaigns and data sources in the graph.

- [ ] **Step 5: Write export/[entityType].ts**

Validates `entityType` against allowlist. Validates `format` (csv/json). Queries full entity table (no pagination). For CSV: generates header row + data rows. For JSON: returns array. Rate limited to 10/min.

- [ ] **Step 6: Write procedures.ts**

Full-text search across `group_techniques.description`, `software_techniques.description`, and `campaign_techniques.description`. Paginated results with entity links.

- [ ] **Step 7: Commit**

```bash
git add api/v1/dashboard.ts api/v1/matrix.ts api/v1/search.ts api/v1/relationships/ api/v1/export/ api/v1/procedures.ts
git commit -m "feat: dashboard, matrix, search, relationships, export, procedures endpoints"
```

---

### Task 2.5: Local dev server

**Files:**
- Create: `server/dev-server.ts`
- Modify: `package.json` (add `dev:api` script)

- [ ] **Step 1: Write dev-server.ts**

Express server that scans `api/v1/` directory, registers routes matching Vercel filesystem conventions. Maps `[param].ts` to `:param` routes. Uses `pg.Pool` via `DATABASE_URL`. Runs on `:3001`.

- [ ] **Step 2: Add scripts to package.json**

```json
"dev:api": "tsx watch server/dev-server.ts"
```

- [ ] **Step 3: Test locally**

```bash
npm run dev:api &
curl http://localhost:3001/api/v1/dashboard
```

Expected: JSON response with stats.

- [ ] **Step 4: Commit and push**

```bash
git add server/ package.json
git commit -m "feat: local dev server mirroring Vercel routing"
git push origin main
```

---

## Chunk 3: React Frontend

### File Structure

```
src/
  components/
    layout/Sidebar.tsx, PageHeader.tsx, SearchBar.tsx
    shared/DataTable.tsx, StatCard.tsx, Badge.tsx, Pagination.tsx, EntityLink.tsx, DeprecatedBadge.tsx
    charts/TacticBarChart.tsx, SectorPieChart.tsx, GroupTechniqueChart.tsx, CampaignTimeline.tsx
    graph/ForceGraph.tsx, GraphTooltip.tsx
    matrix/MatrixGrid.tsx, MatrixCell.tsx, MatrixLegend.tsx
  pages/ (all pages from spec Routes table)
  hooks/useApi.ts
  lib/api.ts, types.ts, sanitize.ts
  App.tsx
  main.tsx
  index.css
index.html
tailwind.config.ts
vite.config.ts
postcss.config.js
```

---

### Task 3.1: Vite + React + Tailwind scaffold

**Files:**
- Create: `vite.config.ts`, `tailwind.config.ts`, `postcss.config.js`, `index.html`
- Create: `src/main.tsx`, `src/App.tsx`, `src/index.css`

- [ ] **Step 1: Install frontend dependencies**

```bash
npm install react react-dom react-router-dom @tanstack/react-query recharts d3 dompurify
npm install -D @types/react @types/react-dom @types/d3 @types/dompurify @vitejs/plugin-react tailwindcss postcss autoprefixer
npx tailwindcss init -p
```

- [ ] **Step 2: Configure Vite** with React plugin + API proxy to `:3001`

- [ ] **Step 3: Configure Tailwind** dark theme with custom colors from spec design system

- [ ] **Step 4: Write index.html, main.tsx, App.tsx** (basic router shell + sidebar layout)

- [ ] **Step 5: Write index.css** with Tailwind directives + dark theme base styles

- [ ] **Step 6: Test dev server**

```bash
npm run dev
```

Expected: React app running on `:5173` with sidebar.

- [ ] **Step 7: Commit**

```bash
git add vite.config.ts tailwind.config.ts postcss.config.js index.html src/
git commit -m "feat: React + Vite + Tailwind scaffold with dark theme"
```

---

### Task 3.2: Shared library — api client, types, sanitizer

**Files:**
- Create: `src/lib/api.ts`, `src/lib/types.ts`, `src/lib/sanitize.ts`
- Create: `src/hooks/useApi.ts`

- [ ] **Step 1: Write api.ts** — fetch wrapper with base URL, error handling
- [ ] **Step 2: Write types.ts** — TypeScript interfaces matching API responses
- [ ] **Step 3: Write sanitize.ts** — DOMPurify wrapper
- [ ] **Step 4: Write useApi.ts** — TanStack Query hooks for each endpoint (useTechniques, useGroups, useDashboard, etc.)
- [ ] **Step 5: Commit**

```bash
git add src/lib/ src/hooks/
git commit -m "feat: API client, types, sanitizer, TanStack Query hooks"
```

---

### Task 3.3: Layout components — Sidebar, SearchBar, PageHeader

**Files:**
- Create: `src/components/layout/Sidebar.tsx`
- Create: `src/components/layout/SearchBar.tsx`
- Create: `src/components/layout/PageHeader.tsx`

- [ ] **Step 1: Write Sidebar** — nav links for all pages, active state highlighting, ATT&CK version display, CTI section separator
- [ ] **Step 2: Write SearchBar** — debounced input (300ms), min 3 chars, navigates to `/search?q=`
- [ ] **Step 3: Write PageHeader** — title + breadcrumb
- [ ] **Step 4: Update App.tsx** — integrate sidebar layout with React Router outlet
- [ ] **Step 5: Commit**

```bash
git add src/components/layout/ src/App.tsx
git commit -m "feat: sidebar, search bar, page header layout"
```

---

### Task 3.4: Shared components — DataTable, EntityLink, StatCard, Badge

**Files:**
- Create: `src/components/shared/DataTable.tsx`
- Create: `src/components/shared/EntityLink.tsx`
- Create: `src/components/shared/StatCard.tsx`
- Create: `src/components/shared/Badge.tsx`
- Create: `src/components/shared/Pagination.tsx`
- Create: `src/components/shared/DeprecatedBadge.tsx`

- [ ] **Step 1: Write DataTable** — generic table with columns config, sorting (URL params), search, filters, pagination, row click → navigate, sticky header, alternating rows
- [ ] **Step 2: Write EntityLink** — color-coded badge per entity type, clickable → detail page
- [ ] **Step 3: Write StatCard, Badge, Pagination, DeprecatedBadge**
- [ ] **Step 4: Commit**

```bash
git add src/components/shared/
git commit -m "feat: DataTable, EntityLink, StatCard, Badge, Pagination components"
```

---

### Task 3.5: Dashboard page

**Files:**
- Create: `src/pages/Dashboard.tsx`
- Create: `src/components/charts/TacticBarChart.tsx`
- Create: `src/components/charts/SectorPieChart.tsx`
- Create: `src/components/charts/GroupTechniqueChart.tsx`

- [ ] **Step 1: Write Dashboard** — stat cards row, tactic bar chart, sector pie chart, top groups chart, quick access links
- [ ] **Step 2: Write chart components** using Recharts
- [ ] **Step 3: Add route to App.tsx**
- [ ] **Step 4: Test** — start dev:api + dev, verify dashboard loads with real data
- [ ] **Step 5: Commit**

```bash
git add src/pages/Dashboard.tsx src/components/charts/
git commit -m "feat: dashboard page with stats and charts"
```

---

### Task 3.6: Entity list + detail pages

Build all list and detail pages. Each list page reuses DataTable. Each detail page shows entity info + related entities via EntityLink.

- [ ] **Step 1: TechniquesList + TechniqueDetail** — nested sub-techniques with expand/collapse, procedure examples section, data sources section, detection tab
- [ ] **Step 2: GroupsList + GroupDetail** — sector tags, campaign links
- [ ] **Step 3: CampaignsList + CampaignDetail** — CampaignTimeline component
- [ ] **Step 4: SoftwareList + SoftwareDetail**
- [ ] **Step 5: DataSourcesList + DataSourceDetail** — nested data components
- [ ] **Step 6: MitigationsList + MitigationDetail**
- [ ] **Step 7: TacticsList + TacticDetail** — kill chain ordered
- [ ] **Step 8: SectorsList + SectorDetail**
- [ ] **Step 9: Search page** — grouped results across entity types
- [ ] **Step 10: Add all routes to App.tsx**
- [ ] **Step 11: Commit**

```bash
git add src/pages/ src/components/charts/CampaignTimeline.tsx
git commit -m "feat: all entity list + detail pages"
```

---

### Task 3.7: ATT&CK Matrix heatmap

**Files:**
- Create: `src/pages/Matrix.tsx`
- Create: `src/components/matrix/MatrixGrid.tsx`
- Create: `src/components/matrix/MatrixCell.tsx`
- Create: `src/components/matrix/MatrixLegend.tsx`

- [ ] **Step 1: Write MatrixGrid** — tactics as columns (kill chain order), techniques as rows, sub-technique expand toggle, platform filter dropdown
- [ ] **Step 2: Write MatrixCell** — color intensity by group usage count, hover tooltip, click → technique detail
- [ ] **Step 3: Write MatrixLegend** — color scale
- [ ] **Step 4: Write Matrix page** — composes grid + legend + filter
- [ ] **Step 5: Commit**

```bash
git add src/pages/Matrix.tsx src/components/matrix/
git commit -m "feat: ATT&CK Navigator-style matrix heatmap"
```

---

### Task 3.8: D3 Relationship Explorer

**Files:**
- Create: `src/pages/Relationships.tsx`
- Create: `src/components/graph/ForceGraph.tsx`
- Create: `src/components/graph/GraphTooltip.tsx`

- [ ] **Step 1: Write ForceGraph** — D3 force simulation, color-coded nodes, draggable, click-to-expand, edge hover descriptions. Uses `textContent` only (never `innerHTML`).
- [ ] **Step 2: Write GraphTooltip** — shows name, attackId, type on hover
- [ ] **Step 3: Write Relationships page** — search autocomplete → select entity → render graph
- [ ] **Step 4: Commit**

```bash
git add src/pages/Relationships.tsx src/components/graph/
git commit -m "feat: D3 force-directed relationship explorer"
```

---

### Task 3.9: Keyboard navigation + final polish

- [ ] **Step 1: Add keyboard shortcuts** — `/` for search, `Esc` to blur, arrow keys in tables, Enter to open
- [ ] **Step 2: Add deep-linkable filter state** — sync all filters/sort/page to URL query params
- [ ] **Step 3: Add `public/robots.txt`** from spec
- [ ] **Step 4: Full local test** — verify all pages load with real data
- [ ] **Step 5: Commit and push**

```bash
git add src/ public/
git commit -m "feat: keyboard nav, deep-linkable filters, robots.txt"
git push origin main
```

---

## Chunk 4: CTI Feed Layer

### File Structure

```
cron/
  ingest-otx.ts
  ingest-abuse-ch.ts
  ingest-cisa-kev.ts
  ingest-rss.ts
  sync-d3fend.ts
.github/workflows/
  sync-sigma.yml
  sync-atomic.yml
src/pages/
  ReportsList.tsx
  IocsList.tsx
  SigmaList.tsx
  FeedStatus.tsx
```

---

### Task 4.1: CTI database tables

**Files:**
- Modify: `seed/schema.sql` — add CTI tables

- [ ] **Step 1: Add CTI tables to schema.sql**

Add all tables from spec "CTI Database Schema" section: `threat_reports`, `ioc_entries`, `sigma_rules`, `atomic_tests`, `defensive_mappings`, `technique_iocs`, `report_techniques`, `feed_sync_log`. Plus all CTI indexes.

- [ ] **Step 2: Run schema update**

```bash
/Applications/Postgres.app/Contents/Versions/18/bin/psql -U postgres -d mitre_attack -f seed/schema.sql
```

- [ ] **Step 3: Commit**

```bash
git add seed/schema.sql
git commit -m "feat: CTI feed tables — reports, IOCs, sigma, atomic, d3fend, sync log"
```

---

### Task 4.2: Vercel Cron jobs — OTX, abuse.ch, CISA, RSS, D3FEND

**Files:**
- Create: `cron/ingest-otx.ts`
- Create: `cron/ingest-abuse-ch.ts`
- Create: `cron/ingest-cisa-kev.ts`
- Create: `cron/ingest-rss.ts`
- Create: `cron/sync-d3fend.ts`

- [ ] **Step 1: Write ingest-otx.ts**

Polls `GET /api/v1/pulses/subscribed?modified_since={cursor}&limit=50`. Follows pagination. Extracts `attack_ids` (already `T1059.001` format). Upserts `threat_reports` + `report_techniques` + `ioc_entries`. Tracks cursor in `feed_sync_log`. Budget: max 200 requests per run.

- [ ] **Step 2: Write ingest-abuse-ch.ts**

POST to ThreatFox (`{"query": "get_iocs", "days": 1}`) and MalwareBazaar (`{"query": "get_recent", "selector": "100"}`). `Auth-Key` header. Inserts `ioc_entries`. Cross-references `malware_family` against `attack_software.name/aliases` (case-insensitive) → links via `technique_iocs` with `confidence='inferred'`.

- [ ] **Step 3: Write ingest-cisa-kev.ts**

Fetches static JSON. Inserts CVEs into `ioc_entries` with `type='cve'`. No technique linking (Phase 2).

- [ ] **Step 4: Write ingest-rss.ts**

Polls 4 RSS feeds. Parses XML. Extracts technique IDs via regex `\bT\d{4}(\.\d{3})?\b`. Validates against `techniques` table. Inserts `threat_reports` + `report_techniques`. Catches UNIQUE conflicts silently (skips, not errors).

- [ ] **Step 5: Write sync-d3fend.ts**

Downloads `https://d3fend.mitre.org/ontologies/d3fend.json`. Parses OWL/JSON-LD for offensive→defensive mappings. Upserts `defensive_mappings`. Never deletes existing rows on failure.

- [ ] **Step 6: Add `CRON_SECRET` env var** for manual sync auth

- [ ] **Step 7: Commit**

```bash
git add cron/
git commit -m "feat: Vercel Cron jobs for OTX, abuse.ch, CISA, RSS, D3FEND ingestion"
```

---

### Task 4.3: GitHub Actions — Sigma + Atomic sync

**Files:**
- Create: `.github/workflows/sync-sigma.yml`
- Create: `.github/workflows/sync-atomic.yml`

- [ ] **Step 1: Write sync-sigma.yml**

Scheduled weekly. Checks out SigmaHQ repo (shallow clone). Parses all YAML files under `rules/`. Extracts: `sigma_id` (YAML `id` field), `title`, ATT&CK technique from `tags` (format `attack.t1059.001` → normalize to `T1059.001`), `level`, `status`, `logsource`. Upserts `sigma_rules` via `DATABASE_URL` secret. Uses `psql` or a small Node script.

- [ ] **Step 2: Write sync-atomic.yml**

Same pattern. Checks out Atomic Red Team repo. Parses `atomics/T*/T*.yaml`. Extracts test name, description, platforms, executor, commands. Upserts `atomic_tests`.

- [ ] **Step 3: Add `DATABASE_URL` as GitHub Actions secret**

```bash
/Users/peripan/dev/gh_CLI/bin/gh secret set DATABASE_URL --repo PerIPan/mitre-attack-explorer
```

(Enter the Vercel Postgres connection string when prompted)

- [ ] **Step 4: Commit**

```bash
git add .github/
git commit -m "feat: GitHub Actions for Sigma + Atomic Red Team weekly sync"
```

---

### Task 4.4: CTI API endpoints

**Files:**
- Create: `api/v1/techniques/[attackId]/intelligence.ts` (or handle in existing `[attackId].ts`)
- Create: `api/v1/feed/reports.ts`
- Create: `api/v1/feed/iocs.ts`
- Create: `api/v1/feed/sigma.ts`
- Create: `api/v1/feed/atomic.ts`
- Create: `api/v1/feed/status.ts`
- Create: `api/v1/feed/[source]/sync.ts`

- [ ] **Step 1: Write intelligence endpoint** — aggregates top 5 reports, 10 IOCs, all sigma rules, atomic tests, d3fend mappings for a technique
- [ ] **Step 2: Write feed list endpoints** — paginated with `since`, `q`, `source` filters
- [ ] **Step 3: Write feed status endpoint** — latest `feed_sync_log` per source
- [ ] **Step 4: Write manual sync trigger** — POST authenticated with `CRON_SECRET`
- [ ] **Step 5: Commit**

```bash
git add api/v1/feed/ api/v1/techniques/
git commit -m "feat: CTI feed API endpoints — intelligence, reports, IOCs, sigma, status"
```

---

### Task 4.5: CTI frontend pages

**Files:**
- Create: `src/pages/ReportsList.tsx`
- Create: `src/pages/IocsList.tsx`
- Create: `src/pages/SigmaList.tsx`
- Create: `src/pages/FeedStatus.tsx`
- Modify: `src/pages/TechniqueDetail.tsx` — add Intelligence tab

- [ ] **Step 1: Write ReportsList** — threat reports feed with source/date filters
- [ ] **Step 2: Write IocsList** — IOC feed with type/source/malware filters
- [ ] **Step 3: Write SigmaList** — sigma rules with technique/level filters
- [ ] **Step 4: Write FeedStatus** — sync status per source, last sync time, record counts, error display, "Sync Now" button
- [ ] **Step 5: Add Intelligence tab to TechniqueDetail** — recent reports, sigma rules, atomic tests, d3fend mappings, IOCs (as shown in spec wireframe)
- [ ] **Step 6: Add routes and sidebar links**
- [ ] **Step 7: Commit**

```bash
git add src/pages/ src/components/ src/App.tsx
git commit -m "feat: CTI feed pages — reports, IOCs, sigma, feed status, intelligence tab"
```

---

## Chunk 5: Deployment + Integration

### Task 5.1: First Vercel deployment

- [ ] **Step 1: Push all code**

```bash
git push origin main
```

- [ ] **Step 2: Deploy to Vercel**

```bash
npx vercel --prod --token 2C84RTBeW2wbcERJdAbGOxlw --scope enable4all
```

- [ ] **Step 3: Provision Vercel Postgres**

Via Vercel dashboard or CLI — create a Postgres database, link to project. This auto-injects `POSTGRES_URL`.

- [ ] **Step 4: Seed production database**

```bash
npm run seed:prod -- --confirm-destructive
```

- [ ] **Step 5: Verify deployment** — open Vercel URL, check dashboard loads with data

- [ ] **Step 6: Set remaining env vars on Vercel**

```bash
npx vercel env add CRON_SECRET production --token 2C84RTBeW2wbcERJdAbGOxlw --scope enable4all
```

---

### Task 5.2: End-to-end verification

- [ ] **Step 1: Verify all pages load** — dashboard, matrix, techniques list + detail, groups, campaigns, software, data sources, mitigations, tactics, sectors, relationships, search
- [ ] **Step 2: Verify search works** — search for "PowerShell", "APT29", confirm results
- [ ] **Step 3: Verify relationship graph** — select APT29, verify D3 graph renders
- [ ] **Step 4: Verify matrix heatmap** — all 14 tactics, techniques colored by usage
- [ ] **Step 5: Verify export** — `/api/v1/export/techniques?format=csv` downloads CSV
- [ ] **Step 6: Verify cron jobs fire** — check feed status page after first schedule
- [ ] **Step 7: Run OTX manual sync** — trigger via feed status page, verify reports appear

---

### Task 5.3: Final commit + tag

- [ ] **Step 1: Tag release**

```bash
git tag v1.0.0
git push origin v1.0.0
```

---

## Execution Order

| Phase | Chunk | Can parallelize? |
|-------|-------|-----------------|
| 1 | Database + Seed | No — foundation |
| 2 | API Layer | Depends on DB |
| 3 | React Frontend | Depends on API |
| 4 | CTI Feed Layer | Independent (DB tables + cron + pages) |
| 5 | Deployment | Depends on all |

Tasks within Chunk 2 (API) can be parallelized — each entity endpoint is independent. Same for Chunk 3 pages. Chunk 4 can run in parallel with Chunk 3 after the CTI DB tables exist.
